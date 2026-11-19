#!/usr/bin/env python3
"""Public sanitized export of git-vault.

Whitelist copy -> scrub machine-specific strings -> self-check sensitive patterns.
Only writes files; never touches the source config/. Standard library only.

    python scripts/export_public.py --out dist/public
    python scripts/export_public.py --scan-only dist/public
"""
import argparse
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

COPY_FILES = (
    "server.py",
    "start-git-vault.cmd",
    "start-vault.cmd",
    "service.cmd",
    "run-vault-tray.vbs",
    "LICENSE",
    "README.public.md",
)
COPY_DIRS = ("core", "extensions", "tests", "web", "docs", "scripts", ".github")
SKIP_DIRS = {"__pycache__", "__pkg__", ".git"}
SKIP_SUFFIX = (".pyc", ".log")
SKIP_MARK = ".bak"

EXAMPLE_CONFIG = {
    "vault.example.json": None,  # copied from config/vault.example.json
    "managed_repos.example.json": '''{
  "managed_repos": [
    {
      "path": "%USERPROFILE%/git-vault/demo-repo",
      "name": "demo-repo",
      "is_my_repo": true,
      "owner": "<owner>",
      "added_by": "auto"
    }
  ]
}
''',
    "git_profiles.example.json": '''{
  "default_id": "github",
  "active_id": "github",
  "profiles": [
    {
      "id": "github",
      "label": "GitHub",
      "name": "<owner>",
      "email": "<owner>@users.noreply.github.com",
      "platform": "github",
      "builtin": true
    },
    {
      "id": "gitlab",
      "label": "GitLab",
      "name": "<owner>",
      "email": "<owner>@users.noreply.gitlab.com",
      "platform": "gitlab",
      "builtin": true
    },
    {
      "id": "gitee",
      "label": "Gitee",
      "name": "<owner>",
      "email": "<owner>@users.noreply.gitee.com",
      "platform": "gitee",
      "builtin": true
    },
    {
      "id": "agent",
      "label": "<bot-account>",
      "name": "<bot-account>",
      "email": "<bot-email>",
      "platform": "agent",
      "builtin": true
    }
  ]
}
''',
    "network_routes.example.json": '''{
  "routes": {
    "github": {
      "mode": "direct",
      "proxy_url": "http://127.0.0.1:11455"
    },
    "gitee": {
      "mode": "direct",
      "locked": true,
      "description": "境内直连通道 (强制锁定)"
    },
    "gitlab": {
      "mode": "proxy",
      "proxy_url": "http://127.0.0.1:11455"
    }
  }
}
''',
}

# Order matters: full identities before their prefixes, drive roots before owners.
SCRUB_RULES = (
    (re.compile(r"354668645\+agy-code-bot\[bot\]@users\.noreply\.github\.com"), "<bot-email>"),
    (re.compile(r"(?i)<owner>@users\.noreply\.github\.com"), "<owner>@users.noreply.github.com"),
    (re.compile(r"(?i)<owner>@users\.noreply\.gitlab\.com"), "<owner>@users.noreply.gitlab.com"),
    (re.compile(r"(?i)C:(?:\\{1,2}|/)Users(?:\\{1,2}|/)MTL"), "%USERPROFILE%"),
    (re.compile(r"(?i)E:(?:\\{1,2}|/)<vault-root>"), "<vault-root>"),
    # Any leftover Windows drive root: <path>\\x, <path>/x, <path>/x (URL scheme letters are skipped).
    (re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z]:(\\{1,2}|/)"), r"<path>\1"),
    (re.compile(r"(?i)354668645\+agy-code-bot\[bot\]"), "<bot-account>"),
    (re.compile(r"(?i)<owner>"), "<owner>"),
    (re.compile(r"(?i)<owner>"), "<owner>"),
    (re.compile(r"(?i)mlgbz5\d\d"), "<owner>"),
    (re.compile(r"(?i)<vault-root>"), "<vault-root>"),
)

# Values that ship on purpose: detector fixtures in tests/ and demo text in web/.
SAFE_VALUES = {
    "AKIA" + "1234567890ABCDEF",
    "ghp_" + "123456789012345678901234567890123456",
    "ghp_" + "000000000000000000000000000000000000",
    "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890",
    "ghp_" + "testsecrettoken1234567890abcdef",
    "sk-proj-" + "1234567890123456789012345678901234567890",
    "sk-proj-" + "test1234567890",
    "sk-proj-" + "test1234567890abcdef",
    "sk-dsk-" + "test-secret-key-12345678",
    "agent@" + "test.com",
    "work@" + "company.com",
}

# Fixtures that only make sense inside tests/ (redaction/scan self-tests).
SAFE_IN_TESTS = {
    "-----BEGIN " + "RSA PRIVATE KEY-----",
    "-----BEGIN " + "PRIVATE KEY-----",
    "attacker@127.0.0.1",
}

SCAN_RULES = (
    ("github_pat", re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])")),
    ("gitlab_pat", re.compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,}")),
    ("aws_key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*" + "PRIVATE KEY-----")),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@(?!github\.com|gitlab\.com|gitee\.com)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")),
    ("windows_path", re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/](?=[A-Za-z0-9_.])")),
)


def scrub(text):
    """Return (sanitized text, number of replacements)."""
    total = 0
    for pattern, repl in SCRUB_RULES:
        text, n = pattern.subn(repl, text)
        total += n
    return text, total


def iter_source_files():
    for name in COPY_FILES:
        path = os.path.join(ROOT, name)
        if os.path.isfile(path):
            yield path
    for top in COPY_DIRS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, top)):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if SKIP_MARK in name or name.endswith(SKIP_SUFFIX):
                    continue
                yield os.path.join(dirpath, name)


def copy_scrubbed(src, dst, stats):
    """Copy one file, scrubbing text; binary files are copied verbatim."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    try:
        with open(src, "r", encoding="utf-8", newline="") as f:
            text = f.read()
    except UnicodeDecodeError:
        shutil.copyfile(src, dst)
    else:
        text, n = scrub(text)
        stats["scrub"] += n
        with open(dst, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    stats["files"] += 1


def write_examples(out, stats):
    os.makedirs(os.path.join(out, "config"), exist_ok=True)
    src = os.path.join(ROOT, "config", "vault.example.json")
    for name, body in EXAMPLE_CONFIG.items():
        dst = os.path.join(out, "config", name)
        if body is None:
            if os.path.isfile(src):
                copy_scrubbed(src, dst, stats)
            continue
        text, n = scrub(body)
        stats["scrub"] += n
        with open(dst, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        stats["files"] += 1


def scan_tree(root, skip_rel=()):
    """Yield (relative path, line number, rule, matched value) for sensitive hits."""
    skip_dirs = {".git", "__pycache__", ".vault-runtime"}
    if os.path.isdir(os.path.join(root, ".git")):
        # A live checkout also holds machine data and this workflow.
        skip_dirs.update({"config", "logs", ".github"})
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            if name.endswith(SKIP_SUFFIX):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace("\\", "/")
            if rel in skip_rel:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                for rule, pattern in SCAN_RULES:
                    for match in pattern.finditer(line):
                        value = match.group(0)
                        if value in SAFE_VALUES:
                            continue
                        if rel.startswith("tests/") and value in SAFE_IN_TESTS:
                            continue
                        if rule == "email" and value.lower().rsplit("@", 1)[-1].endswith(
                            ("example.invalid", "example.com", "example.org", "example.net")
                        ):
                            continue  # RFC 2606 reserved test domain, never personal data
                        yield rel, lineno, rule, match.group(0)


def run_scan(root):
    hits = list(scan_tree(root, skip_rel=("scripts/export_public.py",)))
    if not hits:
        print("selfcheck: clean (0 sensitive hits)")
        return 0
    for rel, lineno, rule, value in hits:
        print(f"selfcheck: {rule} {rel}:{lineno} {value[:80]}")
    print(f"selfcheck: FAILED ({len(hits)} hits)")
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export a sanitized public copy of git-vault.")
    parser.add_argument("--out", default="dist/public", help="output directory (default: dist/public)")
    parser.add_argument("--scan-only", metavar="PATH", help="only run the sensitive-pattern scan")
    args = parser.parse_args(argv)

    if args.scan_only:
        return run_scan(os.path.abspath(args.scan_only))

    out = os.path.abspath(args.out)
    root = os.path.realpath(ROOT)
    if os.path.realpath(out) in (root, os.path.dirname(root)) or root.startswith(os.path.realpath(out) + os.sep):
        print("refuse: --out must not be the source tree or its parent", file=sys.stderr)
        return 2
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out, exist_ok=True)

    stats = {"files": 0, "scrub": 0}
    for src in iter_source_files():
        copy_scrubbed(src, os.path.join(out, os.path.relpath(src, ROOT)), stats)
    write_examples(out, stats)

    print(f"files={stats['files']} scrub={stats['scrub']} out={out}")
    return run_scan(out)


if __name__ == "__main__":
    sys.exit(main())
