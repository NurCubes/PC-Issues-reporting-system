"""special_feature.py - simple scanner for corrupted data files and apps.

diagnostics.check_corruption_scan() calls this module during every full scan (the
"Scan Now" button and the automatic background scans), so its findings reach the
dashboard, become tickets and upload to Firebase exactly like every other check.

Instead of only reading Windows' corruption events (diagnostics.check_data_integrity),
this scanner opens the files themselves and verifies their content:

  JSON / XML          parsed; a broken structure is corruption
  ZIP / Office files  archive integrity tested (.docx/.xlsx/.pptx are ZIP containers)
  SQLite databases    PRAGMA quick_check
  images / PDF        header ("magic bytes") must match the extension
  .exe executables    PE header must be valid (files in user folders + installed apps)
  text files          binary null bytes where text should be

Bounded so a scan stays fast: 800 user files, 400 app executables, OneDrive
cloud-only placeholders are skipped, and huge files are not deep-checked.
"""
import json
import os
import sqlite3
import struct
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_DATA_FILES = 800                    # user files inspected per scan
MAX_APP_FILES = 400                     # installed-app executables inspected per scan
MAX_PARSE = 8 * 1024 * 1024             # json / xml / text
MAX_ZIP = 32 * 1024 * 1024              # zip CRC test
MAX_SQLITE = 64 * 1024 * 1024           # sqlite quick_check
SKIP_LARGER_THAN = 256 * 1024 * 1024    # too big to validate quickly
SKIP_ATTR = 0x400000 | 0x400 | 0x1000   # OneDrive cloud placeholder / reparse / offline
SKIP_NAMES = {"thumbs.db"}               # legit Windows file that is not SQLite
SKIP_DIRS = {"node_modules", "__pycache__"}

TEXT_EXT = {".txt", ".csv", ".log", ".md", ".ini"}
JSON_EXT = {".json"}
XML_EXT = {".xml"}
ZIP_EXT = {".zip", ".docx", ".xlsx", ".pptx", ".jar"}
SQLITE_EXT = {".db", ".sqlite", ".sqlite3", ".db3"}
HEADER_MAGIC = {".png": b"\x89PNG\r\n\x1a\n", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff",
                ".gif": b"GIF8", ".bmp": b"BM", ".pdf": b"%PDF"}
APP_EXT = {".exe", ".dll", ".sys"}


def default_folders():
    """User data folders; OneDrive-redirected variants are included when they exist."""
    home = os.path.expanduser("~")
    candidates = ("Desktop", os.path.join("OneDrive", "Desktop"), "Documents",
                  os.path.join("OneDrive", "Documents"), "Downloads", "Pictures")
    folders, seen = [], set()
    for name in candidates:
        path = os.path.abspath(os.path.join(home, name))
        if os.path.isdir(path) and path.lower() not in seen:
            seen.add(path.lower())
            folders.append(path)
    return folders


def short_path(path):
    """'folder\\file.ext' - readable in the dashboard without the whole path."""
    return os.path.join(os.path.basename(os.path.dirname(path)) or ".",
                        os.path.basename(path))


# ------------------------------------------------------------ per-type checks
def _head(path, size):
    with open(path, "rb") as fh:
        return fh.read(size)


def _check_text(path):
    head = _head(path, 64 * 1024)
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):     # UTF-16 text has NUL bytes by design
        return None
    if b"\x00" in head:
        return "binary null bytes inside a text file (file looks corrupted)"
    return None


def _check_json(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            json.load(fh)
        return None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "invalid JSON structure"


def _check_xml(path):
    try:
        ET.parse(path)
        return None
    except ET.ParseError:
        return "invalid XML structure"


def _check_zip(path):
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
        if bad:
            return f"damaged archive entry ({os.path.basename(bad)})"
        return None
    except zipfile.BadZipFile:
        return "not a valid ZIP archive"
    except RuntimeError:                            # password-protected, not corrupted
        return None


def _check_sqlite(path):
    try:
        con = sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True, timeout=2)
        try:
            row = con.execute("PRAGMA quick_check").fetchone()
        finally:
            con.close()
        if row and str(row[0]).strip().lower() != "ok":
            return f"database integrity check failed ({row[0]})"
        return None
    except sqlite3.OperationalError:                # locked by its app - cannot judge it
        return None
    except sqlite3.DatabaseError:
        return "not a readable database"


def _check_image(path, ext):
    magic = HEADER_MAGIC[ext]
    if not _head(path, len(magic)).startswith(magic):
        return f"header does not match a valid {ext[1:].upper()} file"
    return None


def _check_pe(path, size):
    with open(path, "rb") as fh:
        head = fh.read(64)
        if len(head) < 64 or head[:2] != b"MZ":
            return "missing MZ executable header"
        offset = struct.unpack("<I", head[60:64])[0]
        if offset < 1 or offset + 4 > size:
            return "corrupt PE header offset"
        fh.seek(offset)
        if fh.read(4) != b"PE\x00\x00":
            return "missing PE signature"
    return None


def _inspect(path, size):
    """One file -> None (fine) or a reason why it looks corrupted."""
    ext = os.path.splitext(path)[1].lower()
    if os.path.basename(path).lower() in SKIP_NAMES:
        return None
    if ext in JSON_EXT and size <= MAX_PARSE:
        return _check_json(path)
    if ext in XML_EXT and size <= MAX_PARSE:
        return _check_xml(path)
    if ext in ZIP_EXT and size <= MAX_ZIP:
        return _check_zip(path)
    if ext in SQLITE_EXT and size <= MAX_SQLITE:
        return _check_sqlite(path)
    if ext in HEADER_MAGIC:
        return _check_image(path, ext)
    if ext in APP_EXT:
        return _check_pe(path, size)
    if ext in TEXT_EXT and size <= MAX_PARSE:
        return _check_text(path)
    return None


# ------------------------------------------------------------------ scanners
def _walk_files(folders, max_files):
    """Yield (path, size); bounded, and OneDrive placeholders are never read."""
    scanned = 0
    for folder in folders:
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs
                       if not d.startswith(("$", ".")) and d.lower() not in SKIP_DIRS]
            for name in files:
                if scanned >= max_files:
                    return
                scanned += 1
                path = os.path.join(root, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if getattr(st, "st_file_attributes", 0) & SKIP_ATTR:
                    continue                     # reading would force a cloud download
                yield path, st.st_size


def scan_corrupted_files(folders=None, max_files=MAX_DATA_FILES):
    """Scan the user's data folders. Returns [{'path', 'reason', 'kind'}]."""
    findings = []
    for path, size in _walk_files(folders if folders is not None else default_folders(),
                                  max_files):
        if size > SKIP_LARGER_THAN:
            continue
        try:
            reason = _inspect(path, size)
        except (OSError, ValueError):
            continue
        if reason:
            ext = os.path.splitext(path)[1].lower()
            findings.append({"path": path, "reason": reason,
                             "kind": "app" if ext in APP_EXT else "data"})
    return findings


def scan_app_executables(max_files=MAX_APP_FILES):
    """Validate the .exe files of installed apps (Program Files, a few levels deep)."""
    findings = []
    roots = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
             os.environ.get("ProgramW6432")]
    roots = [r for r in roots if r and os.path.isdir(r)]
    scanned = 0
    for root in roots:
        try:
            apps = sorted(os.listdir(root))
        except OSError:
            continue
        for app in apps:
            appdir = os.path.join(root, app)
            if not os.path.isdir(appdir):
                continue
            for cur, dirs, files in os.walk(appdir):
                if os.path.relpath(cur, appdir).count(os.sep) >= 1:
                    dirs[:] = []                  # the app folder and its first subfolders
                for name in files:
                    if scanned >= max_files:
                        return findings
                    if os.path.splitext(name)[1].lower() != ".exe":
                        continue
                    scanned += 1
                    path = os.path.join(cur, name)
                    try:
                        st = os.stat(path)
                        reason = _inspect(path, st.st_size)
                    except (OSError, ValueError):
                        continue
                    if reason:
                        findings.append({"path": path, "reason": reason, "kind": "app"})
    return findings
