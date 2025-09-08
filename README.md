# 🛰️ GitSpector 🕵️‍♂️✨

> **"Stare deep into your repos… and they stare back."**  
> A checksum inspector, baseline tracker, and change sniffer for Git repositories. 🐙🔍

---

## 🚀 What is this?

**GitSpector** is a Python tool that:  
- 🧮 Computes **checksums** of your repo (HEAD, INDEX, WORKING tree).  
- 📦 Stores them in an **SQLite database** (default: `repo_checksum.db` in your working dir).  
- 🔄 On rescan, **automatically compares** against previous runs.  
- 📜 Keeps a **history of scans** so you can time-travel through your repo’s past.  
- 🌍 Works with **local repos** or **remote URLs** (clones them automagically).  

Basically, it’s like `git status`… but with **cryptographic receipts** and an elephant’s memory. 🐘

---

## ✨ Features

- 🔗 Works with **local paths** or **remote Git URLs** (SSH/HTTPS).  
- ⏱️ Auto-stores **each scan** in SQLite for posterity.  
- 📊 Compare against:  
  - 🕒 **latest scan** (default)  
  - ⏮️ **first scan** (`--baseline-mode first`)  
  - 🎯 a **specific scan ID** (`--baseline-id 42`)  
- 📚 Show full **history** (`--show-history`).  
- 🎭 Supports **labels** (e.g. `--label prod`, `--label pre-release`) to keep environments separate.  
- 🎒 Optionally include **untracked files** (`--include-untracked`).  
- 🔒 Hash algorithm is configurable (`--algo sha256`, `--algo sha1`, `--algo blake2b`, etc).  
- 🧹 Cleans up temp clones (unless you say `--keep-clone`).  

---

## 🛠️ Installation

Clone this repo, drop the script somewhere in your `$PATH`, or just run it directly with Python 3:

```bash
git clone https://github.com/yourname/gitspector.git
cd gitspector
chmod +x repo_checksum_sqlite.py
./repo_checksum_sqlite.py --help
```

---

## 🧑‍💻 Usage

### 🔍 Scan a local repo
```bash
./repo_checksum_sqlite.py .
```

### 🌍 Scan a remote repo (auto-clone)
```bash
./repo_checksum_sqlite.py https://github.com/git/git.git
```

### 📦 Include untracked files
```bash
./repo_checksum_sqlite.py . --include-untracked
```

### 🏷️ Use labels (keep prod vs dev separate)
```bash
./repo_checksum_sqlite.py . --label prod
./repo_checksum_sqlite.py . --label dev
```

### ⏮️ Compare against the first ever baseline
```bash
./repo_checksum_sqlite.py . --baseline-mode first
```

### 🎯 Compare against a specific scan ID
```bash
./repo_checksum_sqlite.py . --baseline-id 42
```

### 📜 Show history
```bash
./repo_checksum_sqlite.py . --show-history
```

---

## 📊 Example Output

```text
Repository: /home/user/myrepo
Input:     .
Label:     (none)
Algo:      sha256 | Include untracked: False
HEAD commit: a1b2c3d4
HEAD tree:   3c9f8e123abc...
INDEX tree:  3c9f8e123abc...
WORKING sha256: 93fbc1239abc...

Comparing to baseline id=1 at 2025-09-08 12:34:56 UTC (head=a1b2c3d4)
No changes vs baseline.

Working tree is clean.

Saved current scan as id=2.
```

---

## 🎉 Why use GitSpector?

- 📦 CI/CD pipelines → detect unexpected changes between stages.  
- 🔒 Security audits → prove your repo hasn’t mysteriously drifted.  
- 🧙 Nerd factor → because checksumming everything is cool.  
- 🗿 For the memes → it’s like `git status` but with **serious cryptographic swagger**.  

---

## 🦄 Future Ideas

- 🌐 JSON output for CI pipelines  
- 🧩 Per-file checksums for granular diffs  
- ⏳ Time-based filters for history (`--since`, `--until`)  
- 🎨 Fancy TUI mode with curses (why not?)  

---

## 🐙 License

MIT License.  
Feel free to fork, hack, and spectate your own Git repos!  

---

## 😂 Auditor Joke

Remember: **GitSpector** won’t stop auditors from asking  
*“But can you prove it again, with screenshots… in Excel?”* 📊🕵️‍♀️  
