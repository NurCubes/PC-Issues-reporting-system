"""monitor.py - the always-on watchdog. Runs as long as the PC is on.

  * Black box   : every 15 s it records CPU/RAM/disk/top processes (a rolling one-hour window).
  * Crash report: at start-up it checks whether the PC died since last time (freeze, power cut,
                  blue screen). If so it opens a ticket that includes the LAST thing the PC was
                  doing before it went down - "report this problem after the PC is booted again".
  * Auto scans  : a full diagnostic scan every 10 minutes; findings become tickets.
  * Cloud sync  : cloud.py's background uploader sends queued reports to Firebase. This loop
                  only wakes it and writes any upload error to monitor.log.

Run headless on each lab PC at logon:   pythonw monitor.py
ui.py also starts it in-process; a port lock makes sure only one copy runs per PC.
"""
import os
import socket
import threading
import time
import traceback
from datetime import datetime

import psutil

import cloud
import diagnostics as dg
from database import (initialize_database, save_snapshot, last_snapshot, get_meta, set_meta,
                      raise_system_issue, pending_outbox_count, pretty, TS_FORMAT)

SNAPSHOT_SECS = 15
FULL_SCAN_SECS = 600
SYNC_SECS = 30
LOCK_PORT = 47653
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.log")
_lock_socket = None


def _log(message):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now():{TS_FORMAT}}  {message}\n")
    except OSError:
        pass


def acquire_single_instance():
    """True if this process is the only monitor on the PC."""
    global _lock_socket
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", LOCK_PORT))
        s.listen(1)
    except OSError:
        s.close()
        return False
    _lock_socket = s
    return True


# --------------------------------------------------------------- crash recorder
def report_crashes_since_last_run():
    events = dg.read_crash_events(days=3)
    if events is None:                       # not Windows, or log unreadable
        return
    heartbeat = last_snapshot()              # read BEFORE this run writes new snapshots: the PC's "last words"
    seen = get_meta("last_crash_event", "")
    newest = max((w for _, w in events), default=None)
    if not seen:                             # first ever run: just set a baseline, don't create fake tickets
        set_meta("last_crash_event", (newest or datetime.now()).strftime(TS_FORMAT))
        return

    try:
        seen_at = datetime.strptime(seen, TS_FORMAT)
    except ValueError:
        seen_at = datetime.min
    fresh = [(i, w) for i, w in events if w > seen_at]
    clusters = dg.group_incidents(fresh)
    for n, c in enumerate(clusters):
        blue_screen = 1001 in c["ids"]
        kind = "blue screen (BSOD)" if blue_screen else "power loss, freeze or forced shutdown"
        text = (f"Detected after reboot: the PC went down unexpectedly - {kind}. "
                f"Windows logged it at {pretty(c['time'].strftime(TS_FORMAT))}.")
        evidence = "No heartbeat recorded before the crash."
        if n == len(clusters) - 1 and heartbeat:         # last words only belong to the most recent crash
            evidence = (f"Last heartbeat {pretty(heartbeat['taken_at'])}: CPU {heartbeat['cpu']:.0f}%, "
                        f"RAM {heartbeat['ram']:.0f}%, Disk {heartbeat['disk']:.0f}%. "
                        f"Heaviest processes: {heartbeat['procs'] or 'n/a'}.")
            try:
                gap = (c["time"] - datetime.strptime(heartbeat["taken_at"], TS_FORMAT)).total_seconds() / 60
            except (TypeError, ValueError):
                gap = 0
            if gap > 0:
                text += f" The PC was down for about {gap:.0f} minute(s)."
        raise_system_issue(dg.COMPUTER_NAME, dg.T_CRASH, "Unidentified",
                           "Needs Immediate Action" if blue_screen else "Critical",
                           f"{text} {evidence}", f"crash:{c['time'].strftime(TS_FORMAT)}",
                           evidence, pc_model=dg.pc_model())
    if newest:
        set_meta("last_crash_event", newest.strftime(TS_FORMAT))


# --------------------------------------------------------------- main loop
class Monitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="lab-monitor")
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def _heartbeat(self):
        save_snapshot(psutil.cpu_percent(None), psutil.virtual_memory().percent,
                      dg.disk_percent(), dg.top_processes_text())

    @staticmethod
    def _log_sync_error(previous):
        """Write a new Firebase upload error to monitor.log (once per distinct error)."""
        error = cloud.sync_status()["last_error"]
        if error and error != previous:
            _log(f"Firebase: {error}")
        return error

    def run(self):
        try:
            report_crashes_since_last_run()
        except Exception:                                    # noqa: BLE001
            _log(traceback.format_exc())
        cloud.start_background_sync()
        next_scan = time.time() + 10
        next_sync = 0.0
        last_error = ""
        while not self._stop_event.is_set():
            # Each job has its own try block: a failure in one must never stop the others.
            try:
                self._heartbeat()
            except Exception:                                # noqa: BLE001
                _log(traceback.format_exc())

            now = time.time()
            if now >= next_scan:
                next_scan = now + FULL_SCAN_SECS     # schedule first, so a failing scan cannot repeat every 15 s
                try:
                    dg.run_scan("auto")
                except Exception:                            # noqa: BLE001
                    _log(traceback.format_exc())

            if now >= next_sync:
                next_sync = time.time() + SYNC_SECS
                try:
                    # No "is the PC online?" gate: the upload itself is the real test, and a
                    # failed check used to keep reports queued forever.
                    if pending_outbox_count():
                        cloud.wake()
                        last_error = self._log_sync_error(last_error)
                except Exception:                            # noqa: BLE001
                    _log(traceback.format_exc())

            self._stop_event.wait(SNAPSHOT_SECS)


def start_monitor():
    """Start the watchdog unless another copy already runs on this PC. Returns the Monitor or None."""
    if not acquire_single_instance():
        return None
    monitor = Monitor()
    monitor.start()
    return monitor


if __name__ == "__main__":
    initialize_database()
    if start_monitor() is None:
        raise SystemExit("Monitor is already running on this PC.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass