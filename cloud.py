"""cloud.py - offline-first upload of lab reports to Firebase Realtime Database.

Both feedback reports and scan reports never go straight to the cloud. They are queued in
SQLite (the `outbox` table), which survives crashes and Wi-Fi outages, and this module
drains the queue whenever the internet is back. It uses only the standard library (no
Firebase SDK, and no secret service-account key stored on student PCs).

Where each report is stored (one record per report, its data grouped inside):
    lab_reports/{PC name}/issue_reports/{YYYY-MM-DD}/scan_reports/{issue_id}
    lab_reports/{PC name}/issue_reports/{YYYY-MM-DD}/feedback_reports/{issue_id}
The date is the day the report was created, so a report made while offline is filed under
its own day when it is finally uploaded.

Setup: set the LAB_FIREBASE_URL environment variable, or create
firebase_config.json next to this file:
    {"database_url": "https://YOUR-PROJECT-default-rtdb.firebaseio.com"}
The environment variable wins over the config file, and the config file wins over the
built-in default URL.

Why a report may stay queued (see sync_status() or the `cloud_last_error` meta key):
    HTTP 401/403  the Realtime Database rules reject the write
    HTTP 404      the database URL is wrong
    network: ...  no route to Firebase (offline, blocked by the school firewall,
                  or HTTPS inspection breaking the certificate)

Recommended Realtime Database rules (lab PCs can only ADD reports; nobody can read them
without admin access through the Firebase console). Re-sending the same report is allowed,
so a retry after a dropped connection never gets stuck:
    {"rules": {"lab_reports": {".read": false,
      "$pc": {"issue_reports": {"$date": {"$type": {"$id": {
        ".write": "!data.exists() || data.child('issue_id').val() === newData.child('issue_id').val()"
      }}}}}}}}
"""
import os
import json
import logging
import threading
import traceback
import http.client
import urllib.request
import urllib.error
from urllib.parse import quote

from database import (pending_outbox, mark_sent, set_meta, get_meta, now, LAB_NAME,
                      upload_status, firebase_path, firebase_document)

log = logging.getLogger("lab.cloud")

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(HERE, "firebase_config.json")
STATUS_LOG = os.path.join(HERE, "cloud_status.log")   # open this file to see what the uploader is doing
DEFAULT_DATABASE_URL = "https://esp32-shit-default-rtdb.asia-southeast1.firebasedatabase.app"
REQUEST_TIMEOUT = 10          # seconds per upload
SYNC_INTERVAL = 15            # seconds between background upload attempts


def database_url():
    """Environment variable first, then firebase_config.json, then the built-in project URL."""
    url = os.environ.get("LAB_FIREBASE_URL", "").strip()
    if not url and os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as fh:
                url = str(json.load(fh).get("database_url") or "").strip()
        except (OSError, ValueError, AttributeError):
            url = ""
    url = (url or DEFAULT_DATABASE_URL).strip().rstrip("/")
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _report_payload(row, data):
    """Normalise a queued report (old or new format) into one flat dict."""
    source = data.get("source", "")
    severity = data.get("severity", "")
    report = {
        "issue_id": data.get("issue_id") or f"row-{row['id']}",   # corrupt rows still get a unique key
        "lab": data.get("lab") or LAB_NAME,
        "pc_name": data.get("pc_name") or row["computer"],
        "model": data.get("model") or "Unknown",
        "os": data.get("os", ""),
        "network": data.get("network", ""),
        "report_type": data.get("report_type") or (
            "Scan report" if source == "System" else "Feedback report"),
        "problem": data.get("problem") or data.get("title") or "",
        "description": data.get("description", ""),
        "status": data.get("status") or upload_status(severity),
        "severity": severity,
        "category": data.get("category", ""),
        "source": source,
        "reporter": data.get("reporter", ""),
        "evidence": data.get("evidence", ""),
        "timestamp": data.get("timestamp") or data.get("created_at") or row["created_at"],
    }
    if data.get("raw"):
        report["raw"] = data["raw"]
    if data.get("scan"):                       # a diagnostic scan report carries its per-component results
        report["scan"] = data["scan"]
    return report


def _report_url(base, report):
    """Full REST URL of one report. Spaces and other unsafe characters in the PC name are
    percent-encoded; a raw space in the URL would crash urllib before anything is sent."""
    return f"{base}/{quote(firebase_path(report), safe='/')}.json"


# ------------------------------------------------------------------ status (so failures are visible)
_LAST_LINE = ""


def status_log(line):
    """Append one line to cloud_status.log (skips an exact repeat of the previous line)."""
    global _LAST_LINE
    if line == _LAST_LINE:
        return
    _LAST_LINE = line
    try:
        with open(STATUS_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{now()}  {line}\n")
    except OSError:
        pass


def _remember_ok():
    try:
        set_meta("cloud_last_ok", now())
        set_meta("cloud_last_error", "")
    except Exception:                                   # noqa: BLE001 - status is best effort
        pass


def _remember_error(message):
    log.warning("Firebase upload problem: %s", message)
    status_log(f"ERROR {message}")
    try:
        set_meta("cloud_last_error", f"{now()}  {message}")
    except Exception:                                   # noqa: BLE001
        pass


def sync_status():
    """{'last_ok': 'YYYY-MM-DD HH:MM:SS' or '', 'last_error': '...' or ''} for the dashboard."""
    return {"last_ok": get_meta("cloud_last_ok", ""), "last_error": get_meta("cloud_last_error", "")}


# ------------------------------------------------------------------ upload
def _put(url, body):
    """Upload one report. Returns (outcome, message) where outcome is:
        'ok'    Firebase accepted it
        'stop'  a problem that affects every report (offline, rules, wrong URL, server busy):
                stop this round and try again later
        'skip'  a problem with this one report only: leave it queued, carry on with the rest
    """
    request = urllib.request.Request(url, data=body, method="PUT",
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            response.read()
        return "ok", ""
    except urllib.error.HTTPError as exc:               # must come before URLError (it is a subclass)
        try:
            detail = exc.read().decode("utf-8", "replace")[:200]
        except Exception:                               # noqa: BLE001
            detail = ""
        message = f"HTTP {exc.code} {exc.reason} {detail}".strip()
        if exc.code in (401, 403):
            return "stop", message + "  -> the database rules are rejecting writes"
        if exc.code == 404:
            return "stop", message + "  -> check the database URL"
        if exc.code in (408, 429) or exc.code >= 500:
            return "stop", message
        return "skip", message                          # e.g. 400: this report's data is invalid
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        return "stop", f"network: {exc}"
    except ValueError as exc:                           # malformed URL for this report
        return "skip", f"bad request: {exc}"


def sync_pending(limit=25):
    """Upload queued reports, oldest first. A report is marked as sent only after Firebase
    accepted it. A network or server-wide problem stops the round and keeps the rest queued;
    a problem with one report only skips that report so it cannot block the others.
    Returns how many were uploaded."""
    base = database_url()
    if not base:
        return 0
    rows = pending_outbox(limit)
    if not rows:
        return 0

    sent, error = [], ""
    try:
        for row in rows:
            try:
                data = json.loads(row["payload"])
                if not isinstance(data, dict):
                    raise ValueError
            except ValueError:                 # a corrupt row must not block the whole queue
                data = {"raw": row["payload"]}
            report = _report_payload(row, data)
            document = firebase_document(report)
            if report.get("raw"):
                document["raw"] = report["raw"]
            if report.get("scan"):
                document["scan"] = report["scan"]
            body = json.dumps(document).encode("utf-8")

            # PUT writes the record at its exact place in the tree (same report = same place)
            outcome, message = _put(_report_url(base, report), body)
            if outcome == "ok":
                sent.append(row["id"])
                continue
            error = f"report {report['issue_id']} ({report['pc_name']}): {message}"
            if outcome == "stop":
                break
    finally:
        mark_sent(sent)                        # even if something unexpected escapes the loop

    if sent:
        status_log(f"uploaded {len(sent)} report(s) to Firebase")
        _remember_ok()
    if error:
        _remember_error(error)
    return len(sent)


# ------------------------------------------------------------------ background uploader
# The uploader runs by itself, so reports reach Firebase even if no other module calls
# sync_pending(). database.initialize_database() starts it, and every saved report wakes it
# for an immediate upload. Set LAB_CLOUD_SYNC=0 to switch it off.
_WORKER = None
_WORKER_LOCK = threading.Lock()
_WAKE = threading.Event()


def _worker_loop():
    status_log(f"uploader started, database {database_url()}")
    while True:
        try:
            while sync_pending(25) >= 25:      # a full batch went through: keep draining
                pass
        except Exception:                      # noqa: BLE001 - the uploader must never die
            log.exception("Firebase uploader error")
            status_log("ERROR uploader crashed: " + traceback.format_exc().strip().splitlines()[-1])
        _WAKE.wait(SYNC_INTERVAL)
        _WAKE.clear()


def start_background_sync():
    """Start the uploader thread once (safe to call many times, from any thread)."""
    global _WORKER
    if os.environ.get("LAB_CLOUD_SYNC", "1").strip() == "0":
        return
    with _WORKER_LOCK:
        if _WORKER is None or not _WORKER.is_alive():
            _WORKER = threading.Thread(target=_worker_loop, name="firebase-sync", daemon=True)
            _WORKER.start()


def wake():
    """A new report was queued: make sure the uploader is running and send it now."""
    start_background_sync()
    _WAKE.set()