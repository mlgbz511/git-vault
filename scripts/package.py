#!/usr/bin/env python3
"""Build dist/vault.pyz (zipapp) + dist/SHA256SUMS and smoke-test --version."""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

import zipapp

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from export_public import scrub  # reuse the same sanitizer for the bundle

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
TARGET = os.path.join(DIST, "vault.pyz")
SUMS = os.path.join(DIST, "SHA256SUMS")
VERSION = "2.0.0"
BUNDLE_SCRUB = 0
BUNDLED = ("server.py", "core", "extensions")

BOOTSTRAP = '''"""git-vault single-file entry point."""
import os
import sys
import zipfile

VERSION = "%s"


def _runtime_dir():
    """zipapp: unpack beside the archive so config/ and logs/ stay writable."""
    archive = os.path.abspath(sys.argv[0])
    if not archive.lower().endswith(".pyz") or not os.path.isfile(archive):
        return None
    dest = os.path.join(os.path.dirname(archive), ".vault-runtime")
    stamp = os.path.join(dest, ".stamp")
    if os.path.exists(stamp) and os.path.getmtime(stamp) >= os.path.getmtime(archive):
        return dest
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)
    open(stamp, "w").close()
    return dest


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if args[:1] in (["--version"], ["-V"], ["-v"]):
        print("git-vault " + VERSION)
        return 0
    runtime = _runtime_dir()
    if runtime:
        sys.path.insert(0, runtime)
    from server import run_server
    run_server()
    return 0


if __name__ == "__main__":
    sys.exit(main())
''' % VERSION


def _ignore(dirpath, names):
    return [n for n in names if n == "__pycache__" or n.endswith((".pyc", ".log")) or ".bak" in n]


def build():
    global BUNDLE_SCRUB
    BUNDLE_SCRUB = 0
    staging = tempfile.mkdtemp(prefix="git-vault-pyzz-")
    try:
        for name in BUNDLED:
            src = os.path.join(ROOT, name)
            dst = os.path.join(staging, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst, ignore=_ignore)
            elif os.path.isfile(src):
                shutil.copyfile(src, dst)
        for dirpath, _dirnames, filenames in os.walk(staging):
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    with open(path, "r", encoding="utf-8", newline="") as f:
                        text = f.read()
                except UnicodeDecodeError:
                    continue
                text, count = scrub(text)
                if count:
                    with open(path, "w", encoding="utf-8", newline="") as f:
                        f.write(text)
                    BUNDLE_SCRUB += count
        with open(os.path.join(staging, "__main__.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(BOOTSTRAP)
        os.makedirs(DIST, exist_ok=True)
        zipapp.create_archive(staging, TARGET, interpreter=None, compressed=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    digest = hashlib.sha256(open(TARGET, "rb").read()).hexdigest()
    with open(SUMS, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"{digest}  vault.pyz\n")
    return digest


def verify():
    proc = subprocess.run([sys.executable, TARGET, "--version"], capture_output=True, text=True)
    out = (proc.stdout + proc.stderr).strip()
    ok = proc.returncode == 0 and VERSION in out
    return ok, out, proc.returncode


def main():
    digest = build()
    size = os.path.getsize(TARGET)
    print(f"built dist/vault.pyz bytes={size} sha256={digest[:16]}... bundle_scrub={BUNDLE_SCRUB}")
    ok, out, code = verify()
    print(f"verify: python dist/vault.pyz --version -> {out!r} exit={code}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
