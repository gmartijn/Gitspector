#!/usr/bin/env python3
"""
gitspector.py — compute & persist Git checksums; auto-compare on rescan; history + custom baselines.

Usage:
  python gitspector.py <path-or-url> [--include-untracked] [--algo sha256]
                       [--db ./gitspector.db] [--label NAME]
                       [--show-history] [--baseline-id ID] [--baseline-mode latest|first]
                       [--keep-clone]

Key behavior:
- <path-or-url> can be local path OR remote Git URL (https/ssh). URLs are cloned to a temp dir.
- Every run stores a record in SQLite and (unless --show-history) compares against a baseline:
    * default baseline: latest previous scan for the same {identifier, label, algo, include_untracked}
    * --baseline-id: compare with the given past scan id (must have the same repo key)
    * --baseline-mode first: compare with the oldest scan for the same repo key
- Default DB path: ./gitspector.db (in current working directory)
- Exit codes:
    0 => unchanged vs chosen baseline
    1 => changed
    2 => errors (clone/DB/mismatched baseline/etc.)
"""

import hashlib
import os
import sys
import subprocess
import tempfile
import shutil
import sqlite3
import time
from pathlib import Path
from typing import List, Tuple, Optional

# ----------------------- Git helpers -----------------------

def run_git(args: List[str], cwd: Path, text=True, check=True) -> str:
    return subprocess.run(
        ["git"] + args, cwd=cwd, check=check,
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

def clone_if_url(path_or_url: str) -> Tuple[Path, bool, str]:
    if "://" in path_or_url or path_or_url.startswith("git@"):
        tmpdir = Path(tempfile.mkdtemp(prefix="gitspector_"))
        try:
            subprocess.run(
                ["git", "clone", "--quiet", "--depth=1", path_or_url, str(tmpdir)],
                check=True
            )
            return tmpdir, True, path_or_url
        except subprocess.CalledProcessError as e:
            shutil.rmtree(tmpdir, ignore_errors=True)
            print(f"Error: could not clone {path_or_url}: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        p = Path(path_or_url).resolve()
        return p, False, str(p)

# ----------------------- SQLite helpers -----------------------

DDL = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_utc INTEGER NOT NULL,
  repo_identifier TEXT NOT NULL,
  repo_root TEXT NOT NULL,
  label TEXT NOT NULL,
  algo TEXT NOT NULL,
  include_untracked INTEGER NOT NULL,
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
    ap = argparse.ArgumentParser(description="Compute & store Git checksums; compare to history.")
    ap.add_argument("path_or_url", help="Local repo path OR remote Git URL.")
    ap.add_argument("--include-untracked", action="store_true", help="Include untracked (not ignored) files in working checksum.")
    ap.add_argument("--algo", default="sha256", help="Hash algorithm (sha256, sha1, blake2b, etc.).")
    ap.add_argument("--db", default=str(Path.cwd() / "gitspector.db"), help="SQLite DB file path (default: ./gitspector.db).")
    ap.add_argument("--label", default="", help="Optional label to segment baselines (e.g., 'prod', 'pre-commit').")
    ap.add_argument("--show-history", action="store_true", help="List previous scans for this repo key and exit.")
    ap.add_argument("--baseline-id", type=int, help="Compare against a specific historical scan ID (from --show-history).")
    ap.add_argument("--baseline-mode", choices=["latest", "first"], default="latest", help="If no --baseline-id, choose latest (default) or first baseline.")
    ap.add_argument("--keep-clone", action="store_true", help="If input is a URL, keep the temp clone directory.")
    args = ap.parse_args()

    repo, is_temp, identifier = clone_if_url(args.path_or_url)

    try:
        conn = open_db(Path(args.db))
    except Exception as e:
        print(f"Error opening DB {args.db}: {e}", file=sys.stderr)
        sys.exit(2)

    include_untracked_flag = 1 if args.include_untracked else 0

    if not in_git_repo(repo):
        if args.show_history:
            hist = list_history(conn, identifier, args.label, args.algo, include_untracked_flag)
            if not hist:
                print("No history for this repo key.")
                sys.exit(0)
            print(f"History for key: {identifier} | label={args.label or '(none)'} | algo={args.algo} | include_untracked={bool(include_untracked_flag)}")
            for row in hist:
                print(f"- id={row['id']}  ts={iso_utc(row['ts_utc'])}  head={row['head_commit'] or '(no commits)'}")
                print(f"    head_tree={row['head_tree'][:12]}  index_tree={row['index_tree'][:12]}  working={row['working_sum'][:12]}")
            sys.exit(0)
        else:
            print(f"Error: '{repo}' is not inside a Git work tree.", file=sys.stderr)
            sys.exit(2)

    toplevel = Path(run_git(["rev-parse", "--show-toplevel"], repo)).resolve()

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

    if args.show_history:
        hist = list_history(conn, identifier, args.label, args.algo, include_untracked_flag)
        if not hist:
            print("No history for this repo key.")
        else:
            print(f"History for key: {identifier} | label={args.label or '(none)'} | algo={args.algo} | include_untracked={bool(include_untracked_flag)}")
            for row in hist:
                print(f"- id={row['id']}  ts={iso_utc(row['ts_utc'])}  head={row['head_commit'] or '(no commits)'}")
                print(f"    head_tree={row['head_tree'][:12]}  index_tree={row['index_tree'][:12]}  working={row['working_sum'][:12]}")
        if is_temp and not args.keep_clone:
            shutil.rmtree(repo, ignore_errors=True)
        sys.exit(0)

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
            print("Error: baseline-id does not match current repo key.", file=sys.stderr)
            if is_temp and not args.keep_clone:
                shutil.rmtree(repo, ignore_errors=True)
            sys.exit(2)
    else:
        baseline = fetch_previous(conn, identifier, args.label, args.algo, include_untracked_flag, mode=args.baseline_mode)

    print(f"Repository: {toplevel}")
    print(f"Input:     {identifier}")
    print(f"Label:     {args.label or '(none)'}")
    print(f"Algo:      {args.algo} | Include untracked: {bool(include_untracked_flag)}")
    print(f"HEAD commit: {head_commit}")
    print(f"HEAD tree:   {head_tree}")
    print(f"INDEX tree:  {index_tree}")
    print(f"WORKING {args.algo}: {working_sum}\n")

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

    status = git_status_porcelain(toplevel)
    if status:
        print("\nWorking tree status (vs HEAD):")
        for code, path in status:
            print(f"  {code}  {path}")
    else:
        print("\nWorking tree is clean.")

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
