"""diagnostics.py - reads this lab PC's health: hardware, OS, network, Windows Defender,
disk, drivers, peripherals, apps and crash history.

Every check returns dicts shaped {component, value, status, finding, topic, severity}
(topic/severity are optional and only used to open tickets automatically).
Slow checks (PowerShell, event logs) are meant to run in a background thread, never
on the UI thread.
"""
import os
import json
import socket
import platform
import subprocess
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone, timedelta
from functools import lru_cache

import psutil
from database import save_scan, raise_system_issue, get_latest_scan, pretty
import special_feature

COMPUTER_NAME = socket.gethostname()
IS_WINDOWS = platform.system() == "Windows"
PC_OS = f"{platform.system()} {platform.release()}"
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0      # stop PowerShell flashing a console window

# (warning, critical) percent
THRESHOLDS = {"CPU": (75, 90), "RAM": (85, 95), "Disk": (85, 95)}

# Processes that must always be running. Add your lab software here, e.g. "examclient.exe".
WATCHED_APPS = ["explorer.exe"]

PERIPHERAL_CLASSES = {"Keyboard", "Mouse", "HIDClass", "Printer", "PrintQueue"}
VIRTUAL_PRINTERS = ("pdf", "xps", "onenote", "fax", "microsoft")
CRASH_PROVIDERS = {"Microsoft-Windows-Kernel-Power", "EventLog", "Microsoft-Windows-WER-SystemErrorReporting"}
PRINTER_PROBLEMS = {"Offline", "Error", "PaperJam", "PaperOut", "PaperProblem", "NoToner", "DoorOpen",
                    "UserIntervention", "ServerOffline", "NotAvailable", "OutOfMemory", "OutputBinFull"}
# NTFS / volume events Windows logs when files or file-system data may be corrupt.
CORRUPTION_EVENT_IDS = (55, 130, 140)
CORRUPTION_PROVIDERS = {"ntfs", "microsoft-windows-ntfs", "disk", "volmgr", "volsnap"}

# One shared vocabulary: students pick from it AND the system files its own tickets under it,
# so rankings and "does the system agree?" work across both sources.
T_CRASH = "Unexpected shutdown / freeze"
T_SLOW = "Slow performance"
T_NET = "No internet / network"
T_PERIPH = "Keyboard / mouse / printer"
T_APP = "App not running / crashing"
T_SEC = "Malware / security"
T_DISK = "Disk problem"
T_DRIVER = "Driver problem"
T_OS = "Operating system"
T_OTHER = "Other"
PROBLEM_TYPES = [T_CRASH, T_SLOW, T_NET, T_PERIPH, T_APP, T_SEC, T_DISK, T_DRIVER, T_OS,
                 "Display problem", "PC won't turn on", T_OTHER]
TOPIC_CATEGORY = {T_CRASH: "Unidentified", T_SLOW: "Software", T_NET: "Hardware", T_PERIPH: "Hardware",
                  T_APP: "Software", T_SEC: "Software", T_DISK: "Hardware", T_DRIVER: "Software",
                  T_OS: "Software"}

# The overall status follows the impact of the damaged part, not the number of findings.
# A problem in one of these core areas can disrupt the whole PC.
CORE_COMPONENTS = {"CPU", "RAM", "Disk", "Stability", "Disk Health", "Data Integrity",
                   "Corrupted Files", "Defender"}

OVERALL_TEXT = {
    "NORMAL":   "The PC is healthy. Only a few minor findings, if any.",
    "NOTICE":   "Only secondary areas (network, peripherals, drivers, apps, battery) have "
                "findings. The core hardware and OS are healthy; keep an eye on it.",
    "HIGH":     "A core component has a warning. The PC needs a technician's attention soon.",
    "CRITICAL": "A core component is critical (CPU, RAM, disk, stability, Defender, disk "
                "health or data integrity). The PC needs immediate attention.",
}

# Plain-language labels shown in the UI (the raw codes stay in the database).
OVERALL_LABELS = {"NORMAL": "Minimal", "NOTICE": "Notice", "WARNING": "Warning",
                  "HIGH": "Warning", "CRITICAL": "Critical"}


# ----------------------------------------------------------------- helpers
def _result(component, value, status, finding, topic=None, severity=None):
    return {"component": component, "value": value, "status": status, "finding": finding,
            "topic": topic, "severity": severity}


def _classify(component, percent):
    warn, crit = THRESHOLDS[component]
    if percent >= crit:
        return "CRITICAL", f"{component} usage is critically high."
    if percent >= warn:
        return "WARNING", f"{component} usage is unusually high."
    return "NORMAL", f"{component} usage is within the normal range."


def _run(cmd, timeout=20):
    """Run a command; return stdout or None on any failure (never raises)."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             creationflags=_NO_WINDOW)
        return out.stdout if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _powershell_json(script, timeout=25):
    text = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"{script} | ConvertTo-Json -Depth 4 -Compress"], timeout)
    if not text or not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _utc_to_local(text):
    dt = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return dt.astimezone().replace(tzinfo=None)


def _query_events(log, event_ids, window_ms, count=50):
    """Read Windows event-log entries. Returns [{'id', 'provider', 'time' (local), 'data'}]
    newest first, or None."""
    cond = " or ".join(f"EventID={i}" for i in event_ids)
    query = f"*[System[({cond}) and TimeCreated[timediff(@SystemTime) <= {window_ms}]]]"
    xml = _run(["wevtutil", "qe", log, f"/q:{query}", f"/c:{count}", "/rd:true", "/f:xml"])
    if xml is None:
        return None
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    try:
        root = ET.fromstring(f"<r>{xml}</r>")
        events = []
        for ev in root.iter(f"{ns}Event"):
            system = ev.find(f"{ns}System")
            provider = system.find(f"{ns}Provider")
            events.append({
                "id": int(system.find(f"{ns}EventID").text),
                "provider": provider.attrib.get("Name", "") if provider is not None else "",
                "time": _utc_to_local(system.find(f"{ns}TimeCreated").attrib["SystemTime"]),
                "data": [d.text or "" for d in ev.findall(f"{ns}EventData/{ns}Data")]})
        return events
    except (ET.ParseError, AttributeError, KeyError, ValueError):
        return None


def read_crash_events(days=7):
    """41 = rebooted without clean shutdown (freeze / power cut / hard reset),
       6008 = previous shutdown unexpected, 1001 = blue screen.
       Returns [(event_id, local datetime)] newest first, or None if the log can't be read."""
    if not IS_WINDOWS:
        return None
    events = _query_events("System", (41, 6008, 1001), days * 24 * 3600 * 1000, count=50)
    return None if events is None else [(e["id"], e["time"]) for e in events
                                         if e["provider"] in CRASH_PROVIDERS]


def group_incidents(events, gap_minutes=10):
    """Events 41 / 6008 / 1001 of ONE crash arrive minutes apart: merge them into one incident."""
    clusters = []
    for event_id, when in sorted(events, key=lambda e: e[1]):
        if clusters and (when - clusters[-1]["end"]).total_seconds() <= gap_minutes * 60:
            clusters[-1]["ids"].add(event_id)
            clusters[-1]["end"] = when
        else:
            clusters.append({"time": when, "end": when, "ids": {event_id}})
    return clusters


def top_processes(n=3):
    """Heaviest processes right now. CPU numbers are measured since the previous call."""
    rows = []
    for p in psutil.process_iter(["name"]):
        try:
            name = p.info["name"] or "?"
            if name in ("System Idle Process", "System"):
                continue
            rows.append((p.cpu_percent(None), p.memory_percent(), name))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    rows.sort(reverse=True)
    return rows[:n]


def top_processes_text(n=3):
    return ", ".join(f"{name} (CPU {c:.0f}%, RAM {m:.1f}%)" for c, m, name in top_processes(n))


@lru_cache(maxsize=1)
def pc_model():
    """Manufacturer + model straight from the BIOS registry key (instant, no subprocess)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            maker = winreg.QueryValueEx(key, "SystemManufacturer")[0]
            model = winreg.QueryValueEx(key, "SystemProductName")[0]
        return f"{maker} {model}".strip()
    except (ImportError, OSError):
        return platform.machine() or "Unknown model"


def is_online(timeout=2):
    """Raw internet reachability (no DNS). Fast enough to call every 30 s."""
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=timeout).close()
        return True
    except OSError:
        return False


def disk_percent():
    """Used-space % of the system drive, shared by scans and the black box."""
    path = os.environ.get("SystemDrive") or os.path.abspath(os.sep)
    return psutil.disk_usage(path.rstrip("\\/") + os.sep).percent


# ------------------------------------------------------------------ checks
def check_os():
    """OS identity + pending restart + how long since the last restart."""
    value = f"Windows {platform.release()}" if IS_WINDOWS else PC_OS
    if not IS_WINDOWS:
        return _result("OS", value, "WARNING", "Not Windows: event-log, Defender and driver checks are skipped.")
    notes = []
    if _reboot_pending():
        notes.append("a restart is pending (updates waiting)")
    uptime_days = (datetime.now() - datetime.fromtimestamp(psutil.boot_time())).days
    if uptime_days >= 14:
        notes.append(f"PC has run {uptime_days} days without a restart")
    if notes:
        return _result("OS", value, "WARNING", f"Build {platform.version()}: " + "; ".join(notes) + ".",
                       topic=T_OS)
    return _result("OS", value, "NORMAL", f"Build {platform.version()}, healthy.")


def _reboot_pending():
    try:
        import winreg
    except ImportError:
        return False
    for sub in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"):
        try:
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub))
            return True
        except OSError:
            continue
    return False


def check_hardware():
    top_processes()                                   # prime per-process CPU counters
    readings = {"CPU": psutil.cpu_percent(interval=1),   # 1 s sample: a real reading, not a 10-minute average
                "RAM": psutil.virtual_memory().percent,
                "Disk": disk_percent()}
    results = []
    for component, percent in readings.items():
        status, finding = _classify(component, percent)
        if status != "NORMAL" and component in ("CPU", "RAM"):
            finding += f" Heaviest processes: {top_processes_text()}."
        topic = T_DISK if component == "Disk" else T_SLOW
        results.append(_result(component, f"{percent:.1f}%", status, finding, topic=topic))

    battery = psutil.sensors_battery()
    if battery is None:
        results.append(_result("Battery", "N/A", "NORMAL", "No battery detected (desktop PC)."))
    else:
        low = battery.percent <= 10 and not battery.power_plugged
        results.append(_result("Battery", f"{battery.percent:.0f}%", "WARNING" if low else "NORMAL",
                               "Battery is low." if low else "Battery level is fine."))
    return results


def check_connectivity():
    """Tells three situations apart:
       no active adapter (PC side) / adapter up but no internet (router or ISP) / internet OK."""
    link_up = [n for n, s in psutil.net_if_stats().items()
               if s.isup and not n.lower().startswith(("lo", "loopback"))]
    if not link_up:
        return _result("Network", "No link", "WARNING",
                       "No active network adapter. Wi-Fi or cable is off or disconnected.", topic=T_NET)
    if not is_online(3):
        return _result("Network", "LAN only", "WARNING",
                       "Connected to a network but no internet. The router or ISP is likely at fault.", topic=T_NET)
    try:
        socket.gethostbyname("firebase.googleapis.com")
    except OSError:
        return _result("Network", "Internet, DNS fail", "WARNING",
                       "Internet reachable but DNS is failing. Cloud sync will not work.", topic=T_NET)
    return _result("Network", "Online", "NORMAL", "Internet and cloud services are reachable.")


def check_stability(days=7):
    """Crash history from the System log, counted as INCIDENTS (not raw events).
       The Value column compares yesterday with today; the 7-day total is in the finding
       and still drives the status. Tickets for new crashes are opened by monitor.py after
       reboot (with black-box data), so this check only reports."""
    if not IS_WINDOWS:
        return _result("Stability", "N/A", "NORMAL", "Event log check is Windows-only.")
    events = read_crash_events(days)
    if events is None:
        return _result("Stability", "Unknown", "WARNING", "Could not read the System event log (run as Administrator).")
    incidents = group_incidents(events)
    n = len(incidents)
    today = datetime.now().date()
    yesterday = today - timedelta(days=1)
    today_count = sum(1 for c in incidents if c["time"].date() == today)
    yesterday_count = sum(1 for c in incidents if c["time"].date() == yesterday)
    value = f"Yesterday {yesterday_count} | Today {today_count}"
    if n == 0:
        return _result("Stability", value, "NORMAL",
                       f"No crashes or unexpected shutdowns in the last {days} days.")
    latest = ", ".join(
        f"{'blue screen' if 1001 in c['ids'] else 'unexpected shutdown/reboot'} @ {c['time']:%b %d %H:%M}"
        for c in reversed(incidents[-3:]))
    return _result("Stability", value, "CRITICAL" if n >= 3 else "WARNING",
                   f"{n} crash incident(s) in the last {days} days. Latest: {latest}.")


def check_defender():
    """Windows Defender is the scanner: is it on, are definitions fresh, any active threats?"""
    if not IS_WINDOWS:
        return _result("Defender", "N/A", "NORMAL", "Defender check is Windows-only.")
    st = _powershell_json("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusSignatureAge")
    if not isinstance(st, dict):
        return _result("Defender", "Unknown", "WARNING",
                       "Defender status unavailable (another antivirus may manage this PC).")
    active = [t.get("ThreatName", "?") for t in _as_list(_powershell_json(
        "Get-MpThreat | Select-Object ThreatName,IsActive")) if isinstance(t, dict) and t.get("IsActive")]
    if active:
        return _result("Defender", f"{len(active)} threat(s)", "CRITICAL",
                       "Active threat(s) detected: " + ", ".join(active[:3]),
                       topic=T_SEC, severity="Needs Immediate Action")
    if not st.get("RealTimeProtectionEnabled"):
        return _result("Defender", "Protection OFF", "CRITICAL", "Real-time protection is disabled.", topic=T_SEC)
    if (st.get("AntivirusSignatureAge") or 0) > 7:
        return _result("Defender", f"Definitions {st['AntivirusSignatureAge']}d old", "WARNING",
                       "Virus definitions are outdated.", topic=T_SEC)
    return _result("Defender", "Protected", "NORMAL", "Real-time protection is on, no active threats.")


def check_storage():
    """Physical disk health."""
    if not IS_WINDOWS:
        return None
    problems = []
    disks = _powershell_json(
        "Get-PhysicalDisk | Select-Object FriendlyName,@{n='Health';e={[string]$_.HealthStatus}}")
    if disks is None:
        return _result("Disk Health", "Unknown", "WARNING", "Could not read physical disk health.")
    for d in _as_list(disks):
        if d.get("Health") not in (None, "Healthy"):
            problems.append(f"{d.get('FriendlyName', 'Disk')} reports {d['Health']}")
    if problems:
        return _result("Disk Health", "Problem", "CRITICAL", "; ".join(problems) + ".", topic=T_DISK)
    return _result("Disk Health", "Healthy", "NORMAL", "Disks report healthy.")


def check_data_integrity(days=7):
    """Awareness of corrupted files/data: the file-system dirty bit and recent NTFS/volume errors."""
    if not IS_WINDOWS:
        return _result("Data Integrity", "N/A", "NORMAL", "Data-integrity check is Windows-only.")
    events = _query_events("System", CORRUPTION_EVENT_IDS, days * 24 * 3600 * 1000, count=10)
    if events is None:
        return _result("Data Integrity", "Unknown", "WARNING",
                       "Could not read the System event log (run as Administrator).")
    problems = [f"event {e['id']} from {e['provider'] or 'unknown'}" for e in events
                if (e["provider"] or "").lower() in CORRUPTION_PROVIDERS]
    out = _run(["fsutil", "dirty", "query", os.environ.get("SystemDrive", "C:")])
    if out and "NOT Dirty" not in out and "Dirty" in out:
        problems.append("file system is flagged dirty (possible corrupted files/data)")
    if problems:
        return _result("Data Integrity", f"{len(problems)} warning(s)", "CRITICAL",
                       "; ".join(problems[:3]) + ".", topic=T_DISK)
    return _result("Data Integrity", "Healthy", "NORMAL",
                   "No file-system corruption signals found.")


def check_corruption_scan():
    """Content-level scan from special_feature.py: corrupted data files and app executables."""
    files = special_feature.scan_corrupted_files()
    apps = special_feature.scan_app_executables()
    results = []
    for component, items, topic in (("Corrupted Files", files, T_DISK),
                                     ("Corrupted Apps", apps, T_APP)):
        if not items:
            results.append(_result(component, "None found", "NORMAL",
                                   f"No corrupted {'data files' if component == 'Corrupted Files' else 'app executables'} found."))
            continue
        shown = "; ".join(f"{special_feature.short_path(f['path'])}: {f['reason']}"
                          for f in items[:3])
        more = f" (and {len(items) - 3} more)" if len(items) > 3 else ""
        status = "CRITICAL" if len(items) >= 3 else "WARNING"
        results.append(_result(component, f"{len(items)} corrupted", status,
                               f"{shown}{more}.", topic=topic))
    return results


def check_devices():
    """Peripherals (keyboard, mouse, printer) and drivers (faulty / missing / outdated)."""
    if not IS_WINDOWS:
        return []
    info = _powershell_json(
        "$all = @(Get-PnpDevice -PresentOnly); [pscustomobject]@{ "
        "kb = @($all | Where-Object { $_.Class -eq 'Keyboard' }).Count; "
        "ms = @($all | Where-Object { $_.Class -eq 'Mouse' }).Count; "
        "bad = @($all | Where-Object { $_.Status -eq 'Error' } | Select-Object Class,FriendlyName,Problem) }", 40)
    if not isinstance(info, dict):
        return [_result("Peripherals", "Unknown", "WARNING", "Could not enumerate devices."),
                _result("Drivers", "Unknown", "WARNING", "Could not enumerate devices.")]
    bad = _as_list(info.get("bad"))

    periph = []
    if not info.get("kb"):
        periph.append("no keyboard detected")
    if not info.get("ms"):
        periph.append("no mouse detected")
    periph += [f"{d.get('FriendlyName') or d.get('Class')} has an error" for d in bad
               if d.get("Class") in PERIPHERAL_CLASSES]
    for p in _as_list(_powershell_json("Get-Printer | Select-Object Name,@{n='State';e={[string]$_.PrinterStatus}}")):
        name = (p.get("Name") or "").lower()
        if not any(v in name for v in VIRTUAL_PRINTERS) and p.get("State") in PRINTER_PROBLEMS:
            periph.append(f"printer '{p['Name']}' is {p['State']}")

    drivers = [f"{d.get('FriendlyName') or d.get('Class')}: driver problem ({d.get('Problem')})"
               for d in bad if d.get("Class") not in PERIPHERAL_CLASSES]
    for d in _as_list(_powershell_json(
            "Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -in 'DISPLAY','NET','MEDIA' "
            "-and $_.Manufacturer -notmatch 'Microsoft' -and $_.DriverDate -and "
            "$_.DriverDate -lt (Get-Date).AddYears(-4) } | Select-Object DeviceName,"
            "@{n='Date';e={$_.DriverDate.ToString('yyyy-MM-dd')}}", 45)):
        drivers.append(f"{d.get('DeviceName')} driver is outdated ({d.get('Date')})")

    return [
        _result("Peripherals", f"{len(periph)} problem(s)" if periph else "All OK",
                "WARNING" if periph else "NORMAL",
                "; ".join(periph) + "." if periph else "Keyboard, mouse and printers look fine.", topic=T_PERIPH),
        _result("Drivers", f"{len(drivers)} problem(s)" if drivers else "All OK",
                "WARNING" if drivers else "NORMAL",
                "; ".join(drivers[:4]) + "." if drivers else "No missing, faulty or outdated drivers found.",
                topic=T_DRIVER)]


def check_apps():
    """Required apps that stopped, and apps that keep crashing or hanging (Application log)."""
    if not IS_WINDOWS:
        return None
    running = {(p.info["name"] or "").lower() for p in psutil.process_iter(["name"])}
    problems = [f"{app} is not running" for app in WATCHED_APPS if app.lower() not in running]
    events = _query_events("Application", (1000, 1002), 24 * 3600 * 1000, count=100)
    if events is None:
        problems.append("could not read the Application event log")
    else:
        # Event ID 1000/1002 are also used by other providers for unrelated messages,
        # so only trust the two providers that actually report app crashes/hangs.
        crashed = Counter((e["data"][0] if e["data"] else "unknown").lower() for e in events
                          if e["provider"] in ("Application Error", "Application Hang"))
        problems += [f"{app} crashed or hung {n}x in 24h" for app, n in crashed.most_common(3) if n >= 2]
    if problems:
        return _result("Apps", f"{len(problems)} problem(s)", "WARNING", "; ".join(problems) + ".", topic=T_APP)
    return _result("Apps", "All OK", "NORMAL", "Required apps are running, no repeated crashes.")


# -------------------------------------------------------------- public API
def _safe(check):
    """One failing check must never kill the whole scan."""
    try:
        out = check()
    except Exception as exc:                                    # noqa: BLE001
        return [_result(check.__name__.replace("check_", "").title(), "Error", "WARNING", f"Check failed: {exc}")]
    if out is None:
        return []
    return out if isinstance(out, list) else [out]


def collect_full():
    results = []
    for check in (check_os, check_hardware, check_connectivity, check_stability, check_defender,
                  check_storage, check_data_integrity, check_corruption_scan, check_devices,
                  check_apps):
        results += _safe(check)
    return results


def _overall_from(pairs):
    """pairs are (component, status). A core problem decides the level (see OVERALL_TEXT)."""
    if not pairs:
        return "NORMAL"
    core = [status for component, status in pairs if component in CORE_COMPONENTS]
    if "CRITICAL" in core:
        return "CRITICAL"
    if "WARNING" in core:
        return "HIGH"
    if any(status != "NORMAL" for _, status in pairs):
        return "NOTICE"
    return "NORMAL"


def overall_status(results):
    return _overall_from([(r["component"], r["status"]) for r in results])


def overall_from_rows(rows):
    """rows are saved scan rows: (component, value, status, finding)."""
    return _overall_from([(r[0], r[2]) for r in rows])


def describe_overall(overall, rows):
    """One-line explanation for the dashboard. rows are saved scan rows: (component, value, status, finding)."""
    core_bad = [r for r in rows if r[0] in CORE_COMPONENTS and r[2] != "NORMAL"]
    other_bad = [r for r in rows if r[0] not in CORE_COMPONENTS and r[2] != "NORMAL"]
    if core_bad:
        detail = "Core issue: " + ", ".join(
            f"{r[0]} ({OVERALL_LABELS.get(r[2], r[2])})" for r in core_bad[:3]) + "."
    elif other_bad:
        detail = "Core hardware and OS are healthy; only secondary areas have findings."
    else:
        detail = "All checks are normal."
    return (f"{len(core_bad) + len(other_bad)} of {len(rows)} checks have a problem. "
            f"{detail} {OVERALL_TEXT.get(overall, '')}")


def _raise_issues(results):
    """Turn real findings into tickets. Brief CPU/RAM warnings are noise, so only CRITICAL ones count."""
    for r in results:
        if r["status"] == "NORMAL" or not r.get("topic"):
            continue
        if r["status"] == "WARNING" and r["component"] in ("CPU", "RAM"):
            continue
        severity = r.get("severity") or ("Critical" if r["status"] == "CRITICAL" else "Warning")
        # Signature is the component only: if the same component escalates from WARNING to
        # CRITICAL, update the open ticket instead of opening a duplicate one.
        raise_system_issue(COMPUTER_NAME, r["topic"], TOPIC_CATEGORY.get(r["topic"], "Unidentified"), severity,
                           f"{r['component']}: {r['finding']}", r["component"], pc_model=pc_model())


def run_scan(kind="manual"):
    """Full scan -> documented in the database -> problems become tickets. Returns (scan_id, results)."""
    results = collect_full()
    scan_id = save_scan(COMPUTER_NAME, kind, overall_status(results), results)
    _raise_issues(results)
    return scan_id, results


def build_evidence():
    """Health snapshot attached to every student report, so the technician can see
    whether the system itself agrees with what the student described."""
    live = f"Live now: CPU {psutil.cpu_percent(None):.0f}%, RAM {psutil.virtual_memory().percent:.0f}%."
    scan, rows = get_latest_scan(COMPUTER_NAME)
    if not scan:
        return {"text": f"No scan recorded yet. {live}", "verified": 0, "connectivity": "Unknown"}
    abnormal = [r for r in rows if r[2] != "NORMAL"]
    found = "; ".join(f"{r[0]} {r[1]} ({r[2]})" for r in abnormal) if abnormal else "no abnormal findings"
    network = next((r[1] for r in rows if r[0] == "Network"), "Unknown")
    overall = overall_from_rows(rows)
    return {"text": f"Scan {pretty(scan['scanned_at'])} - overall {overall}: {found}. {live}",
            "verified": 1 if abnormal else 0, "connectivity": network}