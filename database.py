"""database.py - SQLite storage for the Computer Lab Issues Reporting System.

Every thread (UI, background monitor) opens its own short-lived connection, so the
monitor can write while the dashboard reads. WAL mode keeps readers and writers apart.

Tables
  admins       technician accounts (PBKDF2-hashed passwords)
  issues       student reports AND system-detected problems, in one place
  scans        one row per diagnostic scan (every scan is documented)
  diagnostics  the per-component results of each scan
  snapshots    the "black box": a heartbeat of CPU/RAM/disk/top processes every ~15 s
  outbox       findings waiting to be uploaded to Firebase (offline-first queue)
  meta         small key/value store (e.g. last crash already reported)

The system works fully offline. Reports are saved locally and queued in the outbox;
they are uploaded to Firebase only when the PC is connected to the internet.

Firebase layout (one document per report, all of its data grouped inside):
  lab_reports/{PC name}/issue_reports/{YYYY-MM-DD}/scan_reports/{issue_id}
  lab_reports/{PC name}/issue_reports/{YYYY-MM-DD}/feedback_reports/{issue_id}

The admin registration key is never hardcoded: it comes from LAB_ADMIN_KEY or from
admin_key.txt, which is generated on first use and excluded from source control.
"""
import os
import re
import json
import hmac
import logging
import time
import socket
import traceback
import hashlib
import secrets
import sqlite3
import platform
import threading
from contextlib import contextmanager
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab_issues.db")
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin_key.txt")
_KEY_LOCK = threading.Lock()
_GENERATED_KEY = None
log = logging.getLogger("lab.database")
STATUSES = ("Pending", "Ongoing", "Resolved")
SEVERE = ("Critical", "Needs Immediate Action")
LAB_NAME = os.environ.get("LAB_NAME", "Computer Laboratory")
UPLOAD_STATUS = {
    "low": "Notice", "minimal": "Minimal", "normal": "Minimal", "notice": "Notice",
    "warning": "Warning", "high": "Warning", "critical": "Critical",
    "needs immediate action": "Critical",
}
SNAPSHOT_KEEP = 240                                          # 240 x 15 s = the last hour of black-box data
TS_FORMAT = "%Y-%m-%d %H:%M:%S"
# Every manual scan is uploaded as a scan report. Automatic scans run every 10 minutes, so by
# default only those that found a problem are uploaded. Set True to upload all of them.
UPLOAD_NORMAL_AUTO_SCANS = False

ISSUE_COLUMNS = ["ID", "Computer", "Problem", "Category", "Severity", "Status",
                 "Source", "Reporter", "Seen", "System agrees?", "Reported"]

_SEVERITY_RANK = ("CASE severity "
                  "WHEN 'Needs Immediate Action' THEN 0 "
                  "WHEN 'Critical' THEN 1 "
                  "WHEN 'Warning' THEN 2 "
                  "WHEN 'Notice' THEN 3 "
                  "WHEN 'Minimal' THEN 4 "
                  "ELSE 5 END")

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    computer TEXT NOT NULL, pc_model TEXT DEFAULT '', os_info TEXT DEFAULT '', connectivity TEXT DEFAULT '',
    category TEXT NOT NULL, title TEXT NOT NULL DEFAULT 'Other', description TEXT NOT NULL,
    severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Pending',
    reporter TEXT NOT NULL DEFAULT 'Anonymous', source TEXT NOT NULL DEFAULT 'Student',
    evidence TEXT DEFAULT '', attachment BLOB, verified INTEGER DEFAULT 0, signature TEXT DEFAULT '',
    occurrences INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_issues_status ON issues(status);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    computer TEXT NOT NULL, kind TEXT NOT NULL, overall TEXT NOT NULL, scanned_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS diagnostics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL, computer TEXT NOT NULL, component TEXT NOT NULL,
    value TEXT, status TEXT NOT NULL, finding TEXT, scanned_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_diag_scan ON diagnostics(scan_id);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    taken_at TEXT NOT NULL, cpu REAL, ram REAL, disk REAL, procs TEXT);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL, computer TEXT NOT NULL, payload TEXT NOT NULL,
    created_at TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0, sent_at TEXT);
"""


@contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def initialize_database():
    with _conn() as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(SCHEMA)
        cols = {r["name"] for r in con.execute("PRAGMA table_info(issues)")}
        if "attachment" not in cols:
            con.execute("ALTER TABLE issues ADD COLUMN attachment BLOB")
        outbox_cols = {r["name"] for r in con.execute("PRAGMA table_info(outbox)")}
        if "sent_at" not in outbox_cols:               # when a report reached Firebase
            con.execute("ALTER TABLE outbox ADD COLUMN sent_at TEXT")
    _admin_key()          # create admin_key.txt on first run so the key is ready
    _kick_sync()          # start uploading anything still waiting in the outbox


def _kick_sync():
    """Start the Firebase uploader (first call) or wake it (new report). Imported lazily
    because cloud.py imports this module. Never raises: saving a report must not fail
    just because the uploader could not start."""
    try:
        import cloud
        cloud.wake()
    except Exception:                              # noqa: BLE001
        log.exception("Could not start the Firebase uploader")
        try:                                       # also leave a trace that works without a console
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "cloud_status.log"),
                      "a", encoding="utf-8") as fh:
                fh.write(f"{now()}  ERROR could not start uploader:\n{traceback.format_exc()}\n")
        except OSError:
            pass


def now():
    return datetime.now().strftime(TS_FORMAT)


def pretty(ts):
    """'2026-11-10 03:30:00' -> 'Tue Nov 10, 2026  03:30:00 AM' (day + full date + time)."""
    try:
        return datetime.strptime(ts, TS_FORMAT).strftime("%a %b %d, %Y  %I:%M:%S %p")
    except (TypeError, ValueError):
        return str(ts or "")


# ------------------------------------------------------------------ admins
def _hash(password, salt_hex):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 200_000).hex()


def _admin_key():
    """Secret key required to register an admin.

    It is never hardcoded. The order is: LAB_ADMIN_KEY environment variable,
    then a local admin_key.txt (generated once, kept out of source control).
    """
    global _GENERATED_KEY
    key = os.environ.get("LAB_ADMIN_KEY", "").strip()
    if key:
        return key
    with _KEY_LOCK:
        if _GENERATED_KEY:
            return _GENERATED_KEY
        try:
            with open(KEY_FILE, encoding="utf-8") as fh:
                key = fh.read().strip()
            if key:
                _GENERATED_KEY = key
                return key
        except OSError:
            pass
        key = secrets.token_urlsafe(24)
        _GENERATED_KEY = key
        try:
            with open(KEY_FILE, "w", encoding="utf-8") as fh:
                fh.write(key + "\n")
            try:
                os.chmod(KEY_FILE, 0o600)          # best effort on Windows
            except OSError:
                pass
        except OSError:
            pass
        return key


def get_admin_key():
    """The registration key, for the admin-only dashboard view."""
    return _admin_key()


def register_admin(username, password, key):
    if not hmac.compare_digest(str(key or "").encode(), _admin_key().encode()):
        return False, "Invalid admin key."
    if not username:
        return False, "Username is required."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    salt = secrets.token_hex(16)
    try:
        with _conn() as con:
            con.execute("INSERT INTO admins (username, salt, pw_hash, created_at) VALUES (?,?,?,?)",
                        (username, salt, _hash(password, salt), now()))
    except sqlite3.IntegrityError:
        return False, "That username is already taken."
    return True, "Admin account created. You can now log in."


def verify_admin(username, password):
    with _conn() as con:
        row = con.execute("SELECT salt, pw_hash FROM admins WHERE username=?", (username,)).fetchone()
    return bool(row) and hmac.compare_digest(row["pw_hash"], _hash(password, row["salt"]))


# ------------------------------------------------------------------ outbox (Firebase queue)
def _enqueue(con, kind, computer, payload):
    con.execute("INSERT INTO outbox (kind, computer, payload, created_at) VALUES (?,?,?,?)",
                (kind, computer, json.dumps(payload), now()))


def pending_outbox(limit=25):
    with _conn() as con:
        rows = con.execute("SELECT * FROM outbox WHERE sent=0 ORDER BY id LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def pending_outbox_count():
    with _conn() as con:
        return con.execute("SELECT COUNT(*) FROM outbox WHERE sent=0").fetchone()[0]


def mark_sent(ids):
    """Call only after the upload succeeded. Records when each report reached Firebase."""
    if ids:
        ts = now()
        with _conn() as con:
            con.executemany("UPDATE outbox SET sent=1, sent_at=? WHERE id=?", [(ts, i) for i in ids])


def uploaded_counts():
    """(scan reports uploaded today, feedback reports uploaded today, all-time uploaded)."""
    scan = feedback = 0
    with _conn() as con:
        rows = con.execute("SELECT payload FROM outbox WHERE sent=1 AND kind IN ('issue','scan') "
                           "AND date(sent_at)=date('now','localtime')").fetchall()
        total = con.execute("SELECT COUNT(*) FROM outbox WHERE sent=1").fetchone()[0]
    for row in rows:
        try:
            report_type = json.loads(row["payload"]).get("report_type")
        except ValueError:
            continue
        if report_type == "Scan report":
            scan += 1
        else:
            feedback += 1
    return scan, feedback, total


# ------------------------------------------------------------------ connectivity / local PC info
_NET_CACHE = (0.0, "")
# Port 443 first: campus and school firewalls often block raw DNS (port 53) to public
# resolvers while normal HTTPS works, which made a PC look "Offline" when it was online.
_NET_PROBES = (("1.1.1.1", 443), ("8.8.8.8", 443), ("8.8.8.8", 53))


def check_connectivity(timeout=0.8):
    """'Online' when the internet is reachable, else 'Offline'. Each probe waits at most
    `timeout` seconds and the answer is cached for 20 s so frequent scans never stall
    waiting on the network.

    This is only a label for reports. Never use it to decide whether to upload: call
    cloud.sync_pending() and let the real request to Firebase be the test."""
    global _NET_CACHE
    stamp, value = _NET_CACHE
    if value and time.time() - stamp < 20:
        return value
    value = "Offline"
    for host, port in _NET_PROBES:
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            value = "Online"
            break
        except OSError:
            continue
    _NET_CACHE = (time.time(), value)
    return value


def local_os():
    """Operating system of this PC (e.g. 'Windows 11')."""
    try:
        from diagnostics import PC_OS              # imported lazily to avoid a circular import
        if PC_OS:
            return PC_OS
    except Exception:                              # noqa: BLE001
        pass
    return f"{platform.system()} {platform.release()}".strip()


# ------------------------------------------------------------------ Firebase layout
def _key(text):
    """Firebase keys cannot contain  . $ # [ ] /"""
    return re.sub(r"[.$#\[\]/]", "_", str(text or "")).strip() or "unknown"


def firebase_path(payload):
    """lab_reports/{PC}/issue_reports/{date}/scan_reports|feedback_reports/{issue_id}.
    Works for Realtime Database paths and Firestore (collection/doc/collection/doc/...)."""
    kind = "scan_reports" if payload.get("report_type") == "Scan report" else "feedback_reports"
    date = str(payload.get("timestamp") or now())[:10]
    return (f"lab_reports/{_key(payload.get('pc_name'))}/issue_reports/"
            f"{_key(date)}/{kind}/{payload.get('issue_id')}")


def firebase_document(payload):
    """All the data of one report, organised in groups, ready to upload."""
    return {
        "report_type": payload.get("report_type"),
        "issue_id": payload.get("issue_id"),
        "pc": {
            "lab": payload.get("lab"),
            "name": payload.get("pc_name"),
            "model": payload.get("model"),
            "os": payload.get("os") or "n/a",
            "network": payload.get("network") or "n/a",
        },
        "problem": {
            "title": payload.get("problem"),
            "category": payload.get("category"),
            "description": payload.get("description"),
            "severity": payload.get("severity"),
            "status": payload.get("status"),
        },
        "reporter": payload.get("reporter"),
        "evidence": payload.get("evidence"),
        "reported_at": payload.get("timestamp"),
        "uploaded_at": now(),
    }


# ------------------------------------------------------------------ issues
def upload_status(value):
    """Normalize any severity/status to the four cloud statuses."""
    return UPLOAD_STATUS.get(str(value or "").strip().lower(), "Warning")


def _issue_payload(issue_id, computer, pc_model, title, category, severity, description,
                   source, reporter, evidence, created_at, os_info="", connectivity=""):
    return {
        "issue_id": issue_id,
        "lab": LAB_NAME,
        "pc_name": computer,
        "model": pc_model or "Unknown",
        "os": os_info,
        "network": connectivity,
        "report_type": "Scan report" if source == "System" else "Feedback report",
        "problem": title,
        "description": description,
        "status": upload_status(severity),
        "severity": severity,
        "category": category,
        "source": source,
        "reporter": reporter,
        "evidence": evidence,
        "timestamp": created_at,
    }


def save_issue(computer, category, description, severity, reporter="Anonymous", title="Other",
               pc_model="", os_info="", connectivity="", evidence="", verified=0, source="Student",
               attachment=None):
    """Store a report (student form), with an optional image attachment.
    Every report is also queued for Firebase."""
    ts = now()
    with _conn() as con:
        cur = con.execute(
            """INSERT INTO issues (computer, pc_model, os_info, connectivity, category, title, description,
                                   severity, reporter, source, evidence, verified, attachment,
                                   created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (computer, pc_model, os_info, connectivity, category, title, description,
             severity, reporter, source, evidence, int(bool(verified)), attachment, ts, ts))
        issue_id = cur.lastrowid
        _enqueue(con, "issue", computer,
                 _issue_payload(issue_id, computer, pc_model, title, category, severity, description,
                                source, reporter, evidence, ts, os_info, connectivity))
    _kick_sync()
    return issue_id


def raise_system_issue(computer, title, category, severity, description, signature,
                       evidence="", pc_model="", os_info="", connectivity=""):
    """Open a ticket from a system finding, WITHOUT spamming: if the same problem (same
    signature) is still unresolved on that PC, just count another occurrence.
    The OS and network status of this PC are recorded automatically when not given.
    Returns (issue_id, is_new)."""
    ts = now()
    os_info = os_info or local_os()
    connectivity = connectivity or check_connectivity()      # checked before taking the DB write lock
    with _conn() as con:
        row = con.execute("SELECT id FROM issues WHERE computer=? AND signature=? AND status!='Resolved'",
                          (computer, signature)).fetchone()
        if row:
            con.execute("UPDATE issues SET occurrences=occurrences+1, "
                        "pc_model=COALESCE(NULLIF(?, ''), pc_model), "
                        "os_info=COALESCE(NULLIF(?, ''), os_info), connectivity=?, "
                        "severity=?, description=?, evidence=?, updated_at=? WHERE id=?",
                        (pc_model, os_info, connectivity, severity, description, evidence, ts, row["id"]))
            return row["id"], False
        cur = con.execute(
            """INSERT INTO issues (computer, pc_model, os_info, connectivity, category, title, description,
                                   severity, reporter, source, evidence, verified, signature,
                                   created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,'System','System',?,1,?,?,?)""",
            (computer, pc_model, os_info, connectivity, category, title, description, severity,
             evidence, signature, ts, ts))
        _enqueue(con, "issue", computer,
                 _issue_payload(cur.lastrowid, computer, pc_model, title, category, severity, description,
                                "System", "System", evidence, ts, os_info, connectivity))
        new_id = cur.lastrowid
    _kick_sync()                       # after the commit, so the uploader sees the row
    return new_id, True


def update_issue_status(issue_id, status):
    if status not in STATUSES:
        raise ValueError(f"Status must be one of {STATUSES}")
    with _conn() as con:
        con.execute("UPDATE issues SET status=?, updated_at=? WHERE id=?", (status, now(), issue_id))


def get_issue(issue_id):
    with _conn() as con:
        row = con.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
    return dict(row) if row else None


def _issue_rows(rows):
    return [[r["id"], r["computer"], r["title"], r["category"], r["severity"], r["status"], r["source"],
             r["reporter"], r["occurrences"], "Yes" if r["verified"] else "No", pretty(r["created_at"])]
            for r in rows]


def get_unresolved_issues():
    """Pending + Ongoing, most urgent first. Columns match ISSUE_COLUMNS."""
    with _conn() as con:
        rows = con.execute(f"SELECT * FROM issues WHERE status!='Resolved' "
                           f"ORDER BY {_SEVERITY_RANK}, created_at DESC").fetchall()
    return _issue_rows(rows)


def get_all_issues(status=None, source=None, category=None):
    sql, args = "SELECT * FROM issues WHERE 1=1", []
    for column, value in (("status", status), ("source", source), ("category", category)):
        if value:
            sql += f" AND {column}=?"
            args.append(value)
    with _conn() as con:
        rows = con.execute(sql + " ORDER BY id DESC", args).fetchall()
    return _issue_rows(rows)


def count_issues(*statuses):
    if not statuses:
        return 0
    marks = ",".join("?" * len(statuses))
    with _conn() as con:
        return con.execute(f"SELECT COUNT(*) FROM issues WHERE status IN ({marks})", statuses).fetchone()[0]


def count_critical_open():
    marks = ",".join("?" * len(SEVERE))
    with _conn() as con:
        return con.execute(f"SELECT COUNT(*) FROM issues WHERE status!='Resolved' "
                           f"AND severity IN ({marks})", SEVERE).fetchone()[0]


def ranking_by_title(limit=5):
    """'What problem always occurs?' - student reports and system detections merged."""
    with _conn() as con:
        rows = con.execute("SELECT title, SUM(occurrences) n FROM issues GROUP BY title "
                           "ORDER BY n DESC LIMIT ?", (limit,)).fetchall()
    return [[r["title"], r["n"]] for r in rows]


def ranking_by_computer(limit=5):
    """Problem PCs: the machines that keep coming back (suspect hardware)."""
    with _conn() as con:
        rows = con.execute("SELECT computer, SUM(occurrences) n FROM issues GROUP BY computer "
                           "ORDER BY n DESC LIMIT ?", (limit,)).fetchall()
    return [[r["computer"], r["n"]] for r in rows]


# ------------------------------------------------------------------ scans
def _scan_payload(scan_id, computer, kind, overall, results, ts, os_info, connectivity, model):
    """One diagnostic scan, shaped like every other report so firebase_path() files it under
    .../scan_reports/scan-{id}. The per-component results travel along in a "scan" group."""
    rows = [{"component": r["component"], "value": r["value"], "status": r["status"],
             "finding": r["finding"] or ""} for r in results]
    problems = [r for r in rows if str(r["status"]).upper() != "NORMAL"]
    return {
        "issue_id": f"scan-{scan_id}",
        "lab": LAB_NAME,
        "pc_name": computer,
        "model": model or "Unknown",
        "os": os_info,
        "network": connectivity,
        "report_type": "Scan report",
        "problem": f"{str(kind).title()} scan - overall {overall}",
        "description": " | ".join(f"{r['component']}: {r['finding']}" for r in problems if r["finding"])
                       or "No problems found.",
        "status": upload_status(overall),
        "severity": upload_status(overall),
        "category": "Scan",
        "source": "System",
        "reporter": "System",
        "evidence": "; ".join(f"{r['component']} {r['value']} ({r['status']})" for r in problems)
                    or "All checks normal",
        "timestamp": ts,
        "scan": {"id": scan_id, "kind": kind, "overall": overall, "results": rows},
    }


def save_scan(computer, kind, overall, results):
    """Document one scan: a scans row + one diagnostics row per result. Returns the scan id.
    The scan is also queued for Firebase as a scan report (manual scans always; automatic
    scans when they found a problem, see UPLOAD_NORMAL_AUTO_SCANS)."""
    ts = now()
    upload = (str(kind).lower() != "auto" or UPLOAD_NORMAL_AUTO_SCANS
              or str(overall).strip().upper() != "NORMAL")
    os_info = connectivity = model = ""
    if upload:                          # looked up before taking the DB write lock
        os_info, connectivity = local_os(), check_connectivity()
        try:
            from diagnostics import pc_model          # lazy: diagnostics imports this module
            model = pc_model()
        except Exception:                             # noqa: BLE001
            model = ""
    with _conn() as con:
        scan_id = con.execute("INSERT INTO scans (computer, kind, overall, scanned_at) VALUES (?,?,?,?)",
                              (computer, kind, overall, ts)).lastrowid
        con.executemany(
            "INSERT INTO diagnostics (scan_id, computer, component, value, status, finding, scanned_at) "
            "VALUES (?,?,?,?,?,?,?)",
            [(scan_id, computer, r["component"], r["value"], r["status"], r["finding"], ts) for r in results])
        if upload:
            _enqueue(con, "scan", computer,
                     _scan_payload(scan_id, computer, kind, overall, results, ts,
                                   os_info, connectivity, model))
    if upload:
        _kick_sync()                    # after the commit, so the uploader sees the row
    return scan_id


def _diag_rows(con, scan_id):
    rows = con.execute("SELECT component, value, status, finding FROM diagnostics "
                       "WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
    return [list(r) for r in rows]


def get_latest_scan(computer):
    """(scan dict or None, [[component, value, status, finding], ...])"""
    with _conn() as con:
        scan = con.execute("SELECT * FROM scans WHERE computer=? ORDER BY id DESC LIMIT 1",
                           (computer,)).fetchone()
        if not scan:
            return None, []
        rows = _diag_rows(con, scan["id"])
    return dict(scan), rows


def get_scan_history(limit=100):
    with _conn() as con:
        rows = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [[r["id"], r["computer"], r["kind"], r["overall"], pretty(r["scanned_at"])] for r in rows]


def get_scan_results(scan_id):
    with _conn() as con:
        return _diag_rows(con, scan_id)


def count_anomalies_today():
    """Components that showed a WARNING/CRITICAL at least once today."""
    with _conn() as con:
        return con.execute("SELECT COUNT(DISTINCT computer || '|' || component) FROM diagnostics "
                           "WHERE status!='NORMAL' AND date(scanned_at)=date('now','localtime')").fetchone()[0]


# ------------------------------------------------------------------ black box
def save_snapshot(cpu, ram, disk, procs):
    with _conn() as con:
        con.execute("INSERT INTO snapshots (taken_at, cpu, ram, disk, procs) VALUES (?,?,?,?,?)",
                    (now(), cpu, ram, disk, procs))
        con.execute("DELETE FROM snapshots WHERE id NOT IN (SELECT id FROM snapshots ORDER BY id DESC LIMIT ?)",
                    (SNAPSHOT_KEEP,))


def last_snapshot():
    with _conn() as con:
        row = con.execute("SELECT * FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


# ------------------------------------------------------------------ meta
def get_meta(key, default=""):
    with _conn() as con:
        row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(key, value):
    with _conn() as con:
        con.execute("INSERT INTO meta (key, value) VALUES (?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))