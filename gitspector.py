#!/usr/bin/env python3
"""
gitspector.py — compute & persist Git checksums; auto-compare on rescan; history + custom baselines.
Now with private-repo auth for GitHub/GitLab via HTTPS token or SSH key.

Usage:
  python gitspector.py <path-or-url> [--include-untracked] [--algo sha256]
                       [--db ./gitspector.db] [--label NAME]
                       [--show-history] [--baseline-id ID] [--baseline-mode latest|first]
                       [--keep-clone]
  # Auth (private repos):
                       [--token TOKEN | --token-env VAR]
                       [--provider auto|github|gitlab]
                       [--prefer-ssh]
                       [--ssh-key PATH] [--ssh-known-hosts PATH] [--no-strict-host-key-checking]

Key behavior:
- <path-or-url> can be local path OR remote Git URL (ssh/https). URLs are cloned to a temp dir.
- Stores a record in SQLite and compares against a baseline (latest/first/specific).
- Default DB path: ./gitspector.db (current working directory).
- Auth:
  * HTTPS token (safe, easy): --token or --token-env; provider auto-detected or forced.
    - GitHub:   https://x-access-token:<TOKEN>@github.com/owner/repo.git
    - GitLab:   https://oauth2:<TOKEN>@gitlab.com/owner/repo.git
  * SSH key: --ssh-key (optionally --ssh-known-hosts). Uses GIT_SSH_COMMAND. Works for git@... URLs.
- Secrets are masked in output.
- Exit codes: 0 unchanged, 1 changed, 2 error.
"""

import hashlib
import os
import sys
import subprocess
import tempfile
import shutil
import sqlite3
import time
import re
import shlex
from pathlib import Path
from typing import List, Tuple, Optional

# ----------------------- Utils -----------------------

def redact(s: str) -> str:
    if not s:
        return s
    # Hide anything that looks like scheme://user:pass@host or user:token@host
    s = re.sub(r'(://[^:/@]+:)[^@]+@', r'\1***@', s)
    # Hide long token-looking substrings (40+ hex/alnum)
    s = re.sub(r'([A-Za-z0-9_\-]{20,})', '***', s)
    return s

def guess_provider_from_url(url: str) -> str:
    if "github.com" in url:
        return "github"
    if "gitlab.com" in url or re.search(r'gitlab\.', url):
        return "gitlab"
    return "auto"

def to_ssh_url_if_possible(url: str) -> Optional[str]:
    """
    Convert https://HOST/owner/repo(.git)? to git@HOST:owner/repo.git
    Returns None if it doesn't look like standard https format.
    """
    m = re.match(r'^https?://([^/]+)/([^/]+)/(.*?)(?:\.git)?$', url)
    if not m:
        return None
    host, owner, repo = m.groups()
    return f"git@{host}:{owner}/{repo}.git"

def make_token_url(url: str, token: str, provider: str) -> str:
    """
    Inject token into HTTPS URL according to provider convention.
    GitHub requires username 'x-access-token'; GitLab uses 'oauth2'.
    """
    if not url.startswith("http"):
        # Can't inject token into SSH URL
        return url
    username = "x-access-token" if provider == "github" else "oauth2"
    # Insert 'https://USER:TOKEN@'
    m = re.match(r'^(https?://)(.*)$', url)
    if not m:
        return url
    scheme, rest = m.groups()
    return f"{scheme}{username}:{token}@{rest}"

# ----------------------- Git helpers -----------------------

def run_git(args: List[str], cwd: Path, text=True, check=True, env=None) -> str:
    return subprocess.run(
        ["git"] + args, cwd=cwd, check=check, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text
    ).stdout.strip()

def in_git_repo(cwd: Path) -> bool:
    try:
        run_git(["rev-parse", "--is-inside-work-tree"], cwd)
        return True
    except subprocess.CalledProcessError:
        return False

def get_head_tree(cwd: Path) -> str:
    try:
        return run_git(["rev-parse", "HEAD^{tree}"], cwd)
    except subprocess.CalledProcessError:
        return "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # Git's empty tree

def get_index_tree(cwd: Path) -> str:
    return run_git(["write-tree"], cwd)

def list_tracked_files(cwd: Path) -> List[str]:
    out = run_git(["ls-files", "-z"], cwd, text=False)
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\x00") if p]

def list_untracked_files(cwd: Path) -> List[str]:
    out = run_git(["ls-files", "--others", "--exclude-standard", "-z"], cwd, text=False)
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\x00") if p]

def file_mode(p: Path) -> str:
    try:
        st = p.lstat()
        if os.path.islink(p):
            return "120000"
        is_exec = bool(st.st_mode & 0o111)
        return "100755" if is_exec else "100644"
    except FileNotFoundError:
        return "000000"

def read_content_for_hash(p: Path) -> bytes:
    if os.path.islink(p):
        target = os.readlink(p)
        return target.encode("utf-8", "surrogateescape")
    with open(p, "rb") as f:
        return f.read()

def working_tree_checksum(cwd: Path, files: List[str], algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    for rel in sorted(files):
        p = (cwd / rel)
        path_bytes = rel.replace("\\", "/").encode("utf-8", "surrogateescape")
        mode = file_mode(p).encode("ascii")
        h.update(b"path\0" + path_bytes + b"\n")
        h.update(b"mode\0" + mode + b"\n")
        if p.exists() or os.path.islink(p):
            content = read_content_for_hash(p)
            h.update(b"size\0" + str(len(content)).encode("ascii") + b"\n")
            h.update(content)
        else:
            h.update(b"deleted\n")
    return h.hexdigest()

def git_status_porcelain(cwd: Path):
    out = run_git(["status", "--porcelain=1", "-z"], cwd, text=False)
    entries = []
    i = 0
    b = out
    while i < len(b):
        xy = b[i:i+3]
        code = xy[:2].decode()
        i += 3
        j = b.find(b"\x00", i)
        path1 = b[i:j].decode("utf-8", "surrogateescape")
        i = j + 1
        if code[0] in ("R", "C"):
            j = b.find(b"\x00", i)
            path2 = b[i:j].decode("utf-8", "surrogateescape")
            i = j + 1
            path = f"{path1} -> {path2}"
        else:
            path = path1
        entries.append((code, path))
    return entries

# ----------------------- Cloning with Auth -----------------------

def build_git_env(ssh_key: Optional[str], known_hosts: Optional[str], strict: bool) -> dict:
    env = os.environ.copy()
    if ssh_key:
        cmd_parts = [f"ssh -i {shlex.quote(ssh_key)}"]
        if known_hosts:
            cmd_parts.append(f"-o UserKnownHostsFile={shlex.quote(known_hosts)}")
        if strict:
            cmd_parts.append("-o StrictHostKeyChecking=yes")
        else:
            cmd_parts.append("-o StrictHostKeyChecking=no")
        env["GIT_SSH_COMMAND"] = " ".join(cmd_parts)
    return env

def clone_with_auth(url: str, dest: Path, token: Optional[str], provider: str,
                    prefer_ssh: bool, ssh_key: Optional[str], known_hosts: Optional[str],
                    strict_host_key_checking: bool) -> None:
    """
    Clone using either:
      - SSH (if URL is ssh OR prefer_ssh=True and https convertible)
      - HTTPS with token (if token provided)
      - Plain HTTPS otherwise
    """
    env = build_git_env(ssh_key, known_hosts, strict_host_key_checking)

    # Prefer SSH if requested and url is https convertible
    if prefer_ssh and url.startswith("http"):
        ssh_url = to_ssh_url_if_possible(url)
        if ssh_url:
            url_to_use = ssh_url
        else:
            url_to_use = url
    else:
        url_to_use = url

    # If https and token provided, inject token properly
    prov = provider if provider != "auto" else guess_provider_from_url(url_to_use)
    if url_to_use.startswith("http") and token:
        url_to_use = make_token_url(url_to_use, token, prov)

    try:
        subprocess.run(
            ["git", "clone", "--quiet", "--depth=1", url_to_use, str(dest)],
            check=True, env=env
        )
    except subprocess.CalledProcessError as e:
        masked = redact(url_to_use)
        print(f"Error: could not clone {masked}: {e}", file=sys.stderr)
        sys.exit(2)

def clone_if_url(path_or_url: str,
                 token: Optional[str],
                 provider: str,
                 prefer_ssh: bool,
                 ssh_key: Optional[str],
                 known_hosts: Optional[str],
                 strict_host_key_checking: bool) -> Tuple[Path, bool, str]:
    """
    If input is a URL, clone to temp dir. Return (repo_path, is_temp, identifier).
    identifier is the original URL string (unmodified) or the absolute path.
    """
    if "://" in path_or_url or path_or_url.startswith("git@"):
        tmpdir = Path(tempfile.mkdtemp(prefix="gitspector_"))
        clone_with_auth(
            url=path_or_url,
            dest=tmpdir,
            token=token,
            provider=provider,
            prefer_ssh=prefer_ssh,
            ssh_key=ssh_key,
            known_hosts=known_hosts,
            strict_host_key_checking=strict_host_key_checking,
        )
        return tmpdir, True, path_or_url
    else:
        p = Path(path_or_url).resolve()
        return p, False, str(p)

# ----------------------- SQLite helpers -----------------------

DDL = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_utc INTEGER NOT NULL,
  repo_identifier TEXT NOT NULL,        -- URL string or absolute path (input identity)
  repo_root TEXT NOT NULL,              -- resolved top-level work tree on disk
  label TEXT NOT NULL,                  -- optional user label (defaults to "")
  algo TEXT NOT NULL,
  include_untracked INTEGER NOT NULL,   -- 0/1
  head_commit TEXT,
  head_tree TEXT NOT NULL,
  index_tree TEXT NOT NULL,
  working_sum TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_key ON runs(repo_identifier, label, algo, include_untracked, ts_utc);
"""

def open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    for stmt in DDL.strip().split(";\n"):
        s = stmt.strip()
        if s:
            conn.execute(s)
    return conn

def fetch_previous(conn: sqlite3.Connection, repo_identifier: str, label: str, algo: str, include_untracked: int, mode: str = "latest") -> Optional[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    order = "DESC" if mode == "latest" else "ASC"
    cur = conn.execute(
        f"""
        SELECT * FROM runs
        WHERE repo_identifier = ? AND label = ? AND algo = ? AND include_untracked = ?
        ORDER BY ts_utc {order}
        LIMIT 1
        """,
        (repo_identifier, label, algo, include_untracked),
    )
    return cur.fetchone()

def fetch_by_id(conn: sqlite3.Connection, run_id: int) -> Optional[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
    return cur.fetchone()

def insert_run(conn: sqlite3.Connection, row: dict) -> int:
    cur = conn.execute(
        """
        INSERT INTO runs
        (ts_utc, repo_identifier, repo_root, label, algo, include_untracked,
         head_commit, head_tree, index_tree, working_sum)
        VALUES (:ts_utc, :repo_identifier, :repo_root, :label, :algo, :include_untracked,
                :head_commit, :head_tree, :index_tree, :working_sum)
        """,
        row,
    )
    conn.commit()
    return cur.lastrowid

def list_history(conn: sqlite3.Connection, repo_identifier: str, label: str, algo: str, include_untracked: int, limit: int = 50) -> list:
    conn.row_factory = sqlite3.Row
    cur = conn.execute(
        """
        SELECT id, ts_utc, head_commit, head_tree, index_tree, working_sum
        FROM runs
        WHERE repo_identifier = ? AND label = ? AND algo = ? AND include_untracked = ?
        ORDER BY ts_utc DESC
        LIMIT ?
        """,
        (repo_identifier, label, algo, include_untracked, limit),
    )
    return cur.fetchall()

# ----------------------- Main -----------------------

def iso_utc(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
    except Exception:
        return str(ts)

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Compute & store Git checksums; compare to history (with private-repo auth).")
    ap.add_argument("path_or_url", help="Local repo path OR remote Git URL.")
    ap.add_argument("--include-untracked", action="store_true", help="Include untracked (not ignored) files in working checksum.")
    ap.add_argument("--algo", default="sha256", help="Hash algorithm (sha256, sha1, blake2b, etc.).")
    ap.add_argument("--db", default=str(Path.cwd() / "gitspector.db"), help="SQLite DB file path (default: ./gitspector.db).")
    ap.add_argument("--label", default="", help="Optional label to segment baselines (e.g., 'prod', 'pre-commit').")
    ap.add_argument("--show-history", action="store_true", help="List previous scans for this repo key and exit.")
    ap.add_argument("--baseline-id", type=int, help="Compare against a specific historical scan ID (from --show-history).")
    ap.add_argument("--baseline-mode", choices=["latest", "first"], default="latest", help="If no --baseline-id, choose latest (default) or first baseline.")
    ap.add_argument("--keep-clone", action="store_true", help="If input is a URL, keep the temp clone directory.")

    # Auth options
    ap.add_argument("--token", help="Personal access token for HTTPS cloning (GitHub/GitLab). Avoid putting secrets in shell history; prefer --token-env.")
    ap.add_argument("--token-env", help="Environment variable name that holds the token (safer than --token).")
    ap.add_argument("--provider", choices=["auto", "github", "gitlab"], default="auto", help="Force token provider if auto-detection is wrong.")
    ap.add_argument("--prefer-ssh", action="store_true", help="Prefer SSH when given an https URL (converts to git@host:owner/repo.git if possible).")
    ap.add_argument("--ssh-key", help="Path to an SSH private key for cloning (sets GIT_SSH_COMMAND).")
    ap.add_argument("--ssh-known-hosts", help="Path to a known_hosts file for SSH (with --ssh-key).")
    ap.add_argument("--no-strict-host-key-checking", action="store_true", help="Disable StrictHostKeyChecking for SSH (⚠️ less secure).")

    args = ap.parse_args()

    # Resolve token, if provided via env
    token = args.token
    if args.token_env:
        token = os.environ.get(args.token_env, token)

    strict = not args.no_strict_host_key_checking

    repo, is_temp, identifier = clone_if_url(
        args.path_or_url,
        token=token,
        provider=args.provider,
        prefer_ssh=args.prefer_ssh,
        ssh_key=args.ssh_key,
        known_hosts=args.ssh_known_hosts,
        strict_host_key_checking=strict,
    )

    # Open DB
    try:
        conn = open_db(Path(args.db))
    except Exception as e:
        print(f"Error opening DB {args.db}: {e}", file=sys.stderr)
        sys.exit(2)

    include_untracked_flag = 1 if args.include_untracked else 0

    # If not a repo and --show-history, we can still show history keyed by the identifier.
    if not in_git_repo(repo):
        if args.show_history:
            hist = list_history(conn, identifier, args.label, args.algo, include_untracked_flag)
            if not hist:
                print("No history for this repo key.")
                sys.exit(0)
            print(f"History for key: {redact(identifier)} | label={args.label or '(none)'} | algo={args.algo} | include_untracked={bool(include_untracked_flag)}")
            for row in hist:
                print(f"- id={row['id']}  ts={iso_utc(row['ts_utc'])}  head={row['head_commit'] or '(no commits)'}")
                print(f"    head_tree={row['head_tree'][:12]}  index_tree={row['index_tree'][:12]}  working={row['working_sum'][:12]}")
            sys.exit(0)
        else:
            print(f"Error: '{repo}' is not inside a Git work tree.", file=sys.stderr)
            sys.exit(2)

    # Normalize to repo root
    toplevel = Path(run_git(["rev-parse", "--show-toplevel"], repo)).resolve()

    # Compute current hashes
    head_tree = get_head_tree(toplevel)
    index_tree = get_index_tree(toplevel)
    tracked = list_tracked_files(toplevel)
    files = tracked[:]
    if args.include_untracked:
        files += list_untracked_files(toplevel)
    working_sum = working_tree_checksum(toplevel, files, args.algo)

    try:
        head_commit = run_git(["rev-parse", "HEAD"], toplevel)
    except subprocess.CalledProcessError:
        head_commit = "(no commits yet)"

    # Show history & exit if requested
    if args.show_history:
        hist = list_history(conn, identifier, args.label, args.algo, include_untracked_flag)
        if not hist:
            print("No history for this repo key.")
        else:
            print(f"History for key: {redact(identifier)} | label={args.label or '(none)'} | algo={args.algo} | include_untracked={bool(include_untracked_flag)}")
            for row in hist:
                print(f"- id={row['id']}  ts={iso_utc(row['ts_utc'])}  head={row['head_commit'] or '(no commits)'}")
                print(f"    head_tree={row['head_tree'][:12]}  index_tree={row['index_tree'][:12]}  working={row['working_sum'][:12]}")
        if is_temp and not args.keep_clone:
            shutil.rmtree(repo, ignore_errors=True)
        sys.exit(0)

    # Choose baseline
    baseline = None
    if args.baseline_id is not None:
        baseline = fetch_by_id(conn, args.baseline_id)
        if baseline is None:
            print(f"Error: baseline id {args.baseline_id} not found.", file=sys.stderr)
            if is_temp and not args.keep_clone:
                shutil.rmtree(repo, ignore_errors=True)
            sys.exit(2)
        same_key = (
            baseline["repo_identifier"] == identifier and
            baseline["label"] == args.label and
            baseline["algo"] == args.algo and
            int(baseline["include_untracked"]) == include_untracked_flag
        )
        if not same_key:
            print("Error: baseline-id does not match current repo key (identifier/label/algo/include_untracked).", file=sys.stderr)
            if is_temp and not args.keep_clone:
                shutil.rmtree(repo, ignore_errors=True)
            sys.exit(2)
    else:
        baseline = fetch_previous(conn, identifier, args.label, args.algo, include_untracked_flag, mode=args.baseline_mode)

    # Report header (mask identifier if it might contain a token)
    print(f"Repository: {toplevel}")
    print(f"Input:     {redact(identifier)}")
    print(f"Label:     {args.label or '(none)'}")
    print(f"Algo:      {args.algo} | Include untracked: {bool(include_untracked_flag)}")
    print(f"HEAD commit: {head_commit}")
    print(f"HEAD tree:   {head_tree}")
    print(f"INDEX tree:  {index_tree}")
    print(f"WORKING {args.algo}: {working_sum}\n")

    # Compare to baseline (if any)
    changed = False
    if baseline is None:
        print("No baseline found for this repo key. Saving this scan as the baseline.")
    else:
        print(f"Comparing to baseline id={baseline['id']} at {iso_utc(baseline['ts_utc'])} (head={baseline['head_commit'] or '(no commits)'})")
        diffs = []
        if baseline["head_tree"] != head_tree:
            diffs.append(("HEAD tree", baseline["head_tree"], head_tree))
        if baseline["index_tree"] != index_tree:
            diffs.append(("INDEX tree", baseline["index_tree"], index_tree))
        if baseline["working_sum"] != working_sum:
            diffs.append(("WORKING sum", baseline["working_sum"], working_sum))
        if diffs:
            changed = True
            print("Changes since baseline:")
            for what, old, new in diffs:
                print(f"  {what} changed:")
                print(f"    baseline: {old}")
                print(f"    current : {new}")
        else:
            print("No changes vs baseline.")

    # Show current working status (useful for local paths)
    status = git_status_porcelain(toplevel)
    if status:
        print("\nWorking tree status (vs HEAD):")
        for code, path in status:
            print(f"  {code}  {path}")
    else:
        print("\nWorking tree is clean.")

    # Store current run
    row = {
        "ts_utc": int(time.time()),
        "repo_identifier": identifier,
        "repo_root": str(toplevel),
        "label": args.label,
        "algo": args.algo,
        "include_untracked": include_untracked_flag,
        "head_commit": head_commit,
        "head_tree": head_tree,
        "index_tree": index_tree,
        "working_sum": working_sum,
    }
    try:
        new_id = insert_run(conn, row)
        print(f"\nSaved current scan as id={new_id}.")
    except Exception as e:
        print(f"\nError writing to DB: {e}", file=sys.stderr)
        if is_temp and not args.keep_clone:
            shutil.rmtree(repo, ignore_errors=True)
        sys.exit(2)

    if is_temp and not args.keep_clone:
        shutil.rmtree(repo, ignore_errors=True)

    sys.exit(1 if changed else 0)

if __name__ == "__main__":
    main()
