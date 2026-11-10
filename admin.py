"""admin.py - Admin/Technician login + registration, the dashboard and the logs."""
import psutil

from PySide6.QtCore import Qt, Signal, QTimer, QThread
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout, QLabel,
                               QLineEdit, QPushButton, QTabWidget, QFrame, QTableWidget,
                               QTableWidgetItem, QHeaderView, QMessageBox, QComboBox, QTextEdit)
from database import (register_admin, verify_admin, count_issues, count_critical_open,
                      count_anomalies_today, get_unresolved_issues, get_all_issues, get_issue,
                      update_issue_status, ranking_by_title, ranking_by_computer, get_latest_scan,
                      get_scan_history, get_scan_results, pending_outbox_count, uploaded_counts,
                      pretty, get_admin_key, ISSUE_COLUMNS, STATUSES)
from diagnostics import (pc_model, PC_OS, COMPUTER_NAME, describe_overall, overall_from_rows,
                         OVERALL_LABELS, CORE_COMPONENTS, THRESHOLDS, disk_percent, run_scan)
from evidence import EvidenceViewer

STATUS_COLORS = {"NORMAL": "#2e7d32", "NOTICE": "#f9a825", "WARNING": "#ef6c00",
                 "HIGH": "#ef6c00", "CRITICAL": "#c62828"}
SEVERITY_COLORS = {"Needs Immediate Action": "#c62828", "Critical": "#c62828",
                   "Warning": "#ef6c00", "Notice": "#f9a825",
                   "Minimal": "#2e7d32", "Low": "#6b7280"}
SEVERITY_LABELS = {"Low": "Minimal", "Minimal": "Minimal", "Notice": "Notice",
                   "Warning": "Warning", "High": "Warning", "Critical": "Critical",
                   "Needs Immediate Action": "Critical"}
DIAG_COLUMNS = ["Component", "Value", "Status", "Finding"]

# Logs: "Source" becomes "Report Type", "Reporter" becomes "Name",
# "Severity" becomes "Issue Status" (the four report labels).
REPORT_TYPE_LABEL = {"Student": "Feedback report", "System": "Scan report"}
REPORT_TYPE_TO_SOURCE = {v: k for k, v in REPORT_TYPE_LABEL.items()}
NO_NAME = ("", "anonymous", "none", "n/a", "not defined", "null")
SRC_I = ISSUE_COLUMNS.index("Source")
REP_I = ISSUE_COLUMNS.index("Reporter")
SEV_I = ISSUE_COLUMNS.index("Severity")
ISSUE_HEADERS = ["Report Type" if c == "Source" else "Name" if c == "Reporter"
                 else "Issue Status" if c == "Severity" else c for c in ISSUE_COLUMNS]

# The dashboard shows only the crucial columns; everything else is in the expanded detail.
DASH_ISSUE_COLS = ["ID", "Computer", "Problem", "Severity", "Status", "Reported"]
DASH_ISSUE_IDX = [ISSUE_COLUMNS.index(c) for c in DASH_ISSUE_COLS]
DASH_ISSUE_HEADERS = ["Issue Status" if c == "Severity" else c for c in DASH_ISSUE_COLS]
_STATUS_RANK = {"CRITICAL": 0, "WARNING": 1}


def clean_name(value):
    """Empty text when the reporter is anonymous / not defined."""
    name = str(value or "").strip()
    return "" if name.lower() in NO_NAME else name


def issue_rows(rows):
    """Relabel Source -> Report Type, Severity -> the four status labels, and leave Name
    empty when anonymous / not defined."""
    out = []
    for row in rows:
        row = list(row)
        row[SRC_I] = REPORT_TYPE_LABEL.get(row[SRC_I], row[SRC_I])
        row[SEV_I] = SEVERITY_LABELS.get(row[SEV_I], row[SEV_I])
        row[REP_I] = clean_name(row[REP_I])
        out.append(row)
    return out


def issue_detail_text(issue):
    """Full text of one issue (used by the dashboard and the Logs tab)."""
    report_type = REPORT_TYPE_LABEL.get(issue["source"], issue["source"])
    name = clean_name(issue["reporter"])
    who = f"  |  Name: {name}" if name else ""
    severity = SEVERITY_LABELS.get(issue["severity"], issue["severity"])
    # Older reports were saved without model / OS: if the report is from this PC, fill them in.
    here = issue["computer"] == COMPUTER_NAME
    model_text = issue["pc_model"] or (pc_model() if here else "") or "model n/a"
    os_text = issue["os_info"] or (PC_OS if here else "") or "OS n/a"
    return (
        f"Problem:   {issue['title']}  ({issue['category']}, {severity})\n"
        f"Computer:  {issue['computer']}  |  {model_text}  |  {os_text}"
        f"  |  Network: {issue['connectivity'] or 'n/a'}\n"
        f"Report Type: {report_type}{who}  |  Seen {issue['occurrences']}x\n"
        f"Reported:  {pretty(issue['created_at'])}   Last update: {pretty(issue['updated_at'])}\n\n"
        f"Description:\n{issue['description']}\n\n"
        f"System evidence:\n{issue['evidence'] or 'none'}")


# ====================================================== LOGIN / REGISTER
class AdminLoginPage(QWidget):
    login_success = Signal(str)          # carries the username
    back_requested = Signal()

    def __init__(self):
        super().__init__()
        title = QLabel("Admin / Technician Access")
        title.setObjectName("pageTitle")

        tabs = QTabWidget()
        tabs.addTab(self._login_tab(), "Login")
        tabs.addTab(self._register_tab(), "Register Admin")

        back = QPushButton("Back")
        back.setObjectName("secondary")
        back.clicked.connect(self.back_requested.emit)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(220, 40, 220, 40)
        layout.addWidget(title)
        layout.addWidget(tabs)
        layout.addWidget(back)

    @staticmethod
    def _password_field(placeholder):
        field = QLineEdit()
        field.setPlaceholderText(placeholder)
        field.setEchoMode(QLineEdit.Password)     # show dots instead of characters
        return field

    def _login_tab(self):
        self.login_user = QLineEdit()
        self.login_user.setPlaceholderText("Username")
        self.login_pass = self._password_field("Password")
        self.login_pass.returnPressed.connect(self._do_login)   # Enter key submits
        button = QPushButton("Login")
        button.clicked.connect(self._do_login)

        tab = QWidget()
        form = QFormLayout(tab)
        form.addRow("Username:", self.login_user)
        form.addRow("Password:", self.login_pass)
        form.addRow("", button)
        return tab

    def _register_tab(self):
        self.reg_user = QLineEdit()
        self.reg_user.setPlaceholderText("Choose a username")
        self.reg_pass = self._password_field("At least 6 characters")
        self.reg_confirm = self._password_field("Repeat password")
        self.reg_key = self._password_field("Secret admin key")
        button = QPushButton("Register")
        button.clicked.connect(self._do_register)

        tab = QWidget()
        form = QFormLayout(tab)
        form.addRow("Username:", self.reg_user)
        form.addRow("Password:", self.reg_pass)
        form.addRow("Confirm:", self.reg_confirm)
        form.addRow("Admin key:", self.reg_key)
        form.addRow("", button)
        return tab

    def _do_login(self):
        username = self.login_user.text().strip()
        if verify_admin(username, self.login_pass.text()):
            self.login_pass.clear()
            self.login_success.emit(username)
        else:
            QMessageBox.warning(self, "Login failed", "Incorrect username or password.")

    def _do_register(self):
        if self.reg_pass.text() != self.reg_confirm.text():
            QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
            return
        ok, message = register_admin(self.reg_user.text().strip(), self.reg_pass.text(),
                                     self.reg_key.text())
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Registration", message)
        if ok:
            for field in (self.reg_user, self.reg_pass, self.reg_confirm, self.reg_key):
                field.clear()


# ====================================================== shared helpers
def make_card(title):
    """Build one summary card; returns (frame, value_label) so the value can be updated later."""
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    caption = QLabel(title)
    caption.setObjectName("cardTitle")
    value = QLabel("-")
    value.setObjectName("cardValue")
    value.setStyleSheet("color: #c62828;")        # red numbers (Host Status sets its own colour)
    value.setAlignment(Qt.AlignCenter)
    layout.addWidget(caption)
    layout.addWidget(value)
    return frame, value


def make_table(headers):
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    table.setEditTriggers(QTableWidget.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectRows)
    return table


def fill_table(table, rows, color_col=None, colors=None, label_col=None, labels=None):
    """Fill a table; optionally colour one column's text using a {text: colour} map and
    replace one column's raw value with a display label. Every cell also gets a tooltip
    so long text can be read in full by hovering."""
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, cell in enumerate(row):
            raw = str(cell)
            text = labels.get(raw, raw) if c == label_col and labels else raw
            item = QTableWidgetItem(text)
            item.setToolTip(raw)
            if c == color_col and colors and raw in colors:
                item.setForeground(QColor(colors[raw]))
            table.setItem(r, c, item)


def wire_detail(table, detail):
    """Show the full contents of the selected row in a read-only detail panel."""
    detail.setReadOnly(True)

    def show():
        row = table.currentRow()
        if row < 0:
            detail.clear()
            return
        lines = []
        for col in range(table.columnCount()):
            header = table.horizontalHeaderItem(col)
            item = table.item(row, col)
            lines.append(f"{header.text() if header else ''}: {item.text() if item else ''}")
        detail.setPlainText("\n".join(lines))

    table.itemSelectionChanged.connect(show)


# ====================================================== DASHBOARD TAB
class DashboardTab(QWidget):
    """Reads everything from the database (the background monitor does the scanning).
    Shows only what needs attention; click any row to expand its full details."""

    def __init__(self):
        super().__init__()
        host_card, self.host_value = make_card(f"Host Status ({COMPUTER_NAME})")
        anomaly_card, self.anomaly_value = make_card("Anomalies Today")
        unresolved_card, self.unresolved_value = make_card("Unresolved Issues")
        critical_card, self.critical_value = make_card("Critical Open")
        sync_card, self.sync_value = make_card("Uploaded to Firebase (Today)")
        self.sync_value.setStyleSheet("color: #2e7d32;")          # green: these reports reached the cloud
        self.sync_detail = QLabel("Scan 0  |  Feedback 0")
        self.sync_detail.setObjectName("cardTitle")
        self.sync_detail.setAlignment(Qt.AlignCenter)
        sync_card.layout().addWidget(self.sync_detail)
        live_card, self.live_value = make_card("Live Scan (real-time)")
        self.live_value.setStyleSheet("font-size: 18px; color: #1f2937;")
        psutil.cpu_percent(None)                 # prime the CPU counter

        cards = QGridLayout()
        for col, card in enumerate((host_card, anomaly_card, unresolved_card,
                                    critical_card, sync_card)):
            cards.addWidget(card, 0, col)
        cards.addWidget(live_card, 1, 0, 1, 5)

        self.pc_info = QLabel()
        self.pc_info.setObjectName("cardTitle")
        self.overall_desc = QLabel()
        self.overall_desc.setWordWrap(True)

        self.diag_table = make_table(DIAG_COLUMNS)
        self.pending_table = make_table(DASH_ISSUE_HEADERS)
        self.rank_type = make_table(["Most Frequent Problems", "Times"])
        self.rank_pc = make_table(["Problem PCs", "Times"])

        # one expanding detail panel, hidden until a row is clicked
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(170)
        self.detail.hide()
        self.evidence = EvidenceViewer()
        self.evidence.hide()
        self.diag_table.itemSelectionChanged.connect(self._show_diag_detail)
        self.pending_table.itemSelectionChanged.connect(self._show_issue_detail)

        left = QVBoxLayout()
        left.addWidget(QLabel("Latest Diagnostic (problems only) - click a row for details"))
        left.addWidget(self.diag_table, 2)
        left.addWidget(QLabel("Unresolved Issues (most urgent first) - click a row for details"))
        left.addWidget(self.pending_table, 3)

        rankings = QVBoxLayout()
        rankings.addWidget(self.rank_type)
        rankings.addWidget(self.rank_pc)

        middle = QHBoxLayout()
        middle.addLayout(left, 3)
        middle.addLayout(rankings, 2)

        self.live_timer = QTimer(self)
        self.live_timer.setInterval(1000)
        self.live_timer.timeout.connect(self._live_tick)

        layout = QVBoxLayout(self)
        layout.addLayout(cards)
        layout.addWidget(self.pc_info)
        layout.addWidget(self.overall_desc)
        layout.addLayout(middle, 1)
        detail_row = QHBoxLayout()
        detail_row.addWidget(self.detail, 3)
        detail_row.addWidget(self.evidence, 2)
        layout.addLayout(detail_row)

    # ---- selection helpers (keep the open row across the 30 s refresh)
    @staticmethod
    def _selected_key(table, key_col):
        items = table.selectedItems()
        return table.item(items[0].row(), key_col).text() if items else None

    @staticmethod
    def _clear(table):
        table.blockSignals(True)
        table.clearSelection()
        table.blockSignals(False)

    def _refill(self, table, rows, key_col, *fill_args):
        keep = self._selected_key(table, key_col)
        table.blockSignals(True)
        fill_table(table, rows, *fill_args)
        if keep is not None:
            for r in range(table.rowCount()):
                if table.item(r, key_col).text() == keep:
                    table.selectRow(r)
                    break
        table.blockSignals(False)

    def _show_diag_detail(self):
        items = self.diag_table.selectedItems()
        if not items:
            if not self.pending_table.selectedItems():
                self.detail.hide()
                self.evidence.hide()
            return
        self._clear(self.pending_table)
        row = items[0].row()
        lines = []
        for col in range(self.diag_table.columnCount()):
            header = self.diag_table.horizontalHeaderItem(col).text()
            item = self.diag_table.item(row, col)
            lines.append(f"{header}: {item.text() if item else ''}")
        self.detail.setPlainText("\n".join(lines))
        self.detail.show()
        self.evidence.clear()
        self.evidence.hide()

    def _show_issue_detail(self):
        items = self.pending_table.selectedItems()
        if not items:
            if not self.diag_table.selectedItems():
                self.detail.hide()
                self.evidence.hide()
            return
        self._clear(self.diag_table)
        issue = get_issue(int(self.pending_table.item(items[0].row(), 0).text()))
        if not issue:
            self.detail.hide()
            self.evidence.hide()
            return
        self.detail.setPlainText(issue_detail_text(issue))
        self.detail.show()
        if issue["source"] == "Student":              # feedback report -> show the evidence image
            self.evidence.show_attachment(issue.get("attachment"))
            self.evidence.show()
        else:                                          # scan report -> no evidence panel
            self.evidence.clear()
            self.evidence.hide()

    def _sync_detail(self):
        if self.pending_table.selectedItems():
            self._show_issue_detail()
        elif self.diag_table.selectedItems():
            self._show_diag_detail()
        else:
            self.detail.hide()
            self.evidence.hide()

    def refresh(self):
        scan, rows = get_latest_scan(COMPUTER_NAME)
        overall = overall_from_rows(rows) if scan else "NO SCAN YET"
        self.host_value.setText(OVERALL_LABELS.get(overall, overall))
        self.host_value.setStyleSheet(f"color: {STATUS_COLORS.get(overall, '#6b7280')};")
        when = f"{pretty(scan['scanned_at'])} ({scan['kind']} scan)" if scan else "waiting for the first scan"
        self.pc_info.setText(f"PC: {COMPUTER_NAME}  |  {pc_model()}  |  {PC_OS}  |  Last scan: {when}")
        self.overall_desc.setText(describe_overall(overall, rows) if scan else "")

        # only findings that need attention, worst first (core components before secondary ones)
        problems = sorted((tuple(r)[:4] for r in rows if r[2] != "NORMAL"),
                          key=lambda r: (_STATUS_RANK.get(r[2], 2), r[0] not in CORE_COMPONENTS))
        if scan and not problems:
            problems = [("All checks", "OK", "NORMAL", "No problems found in the latest scan.")]
        self._refill(self.diag_table, problems, 0, 2, STATUS_COLORS, 2, OVERALL_LABELS)

        issues = issue_rows(get_unresolved_issues())
        slim = [[row[i] for i in DASH_ISSUE_IDX] for row in issues]
        self._refill(self.pending_table, slim, 0, 3, SEVERITY_COLORS)
        self._sync_detail()

        self.anomaly_value.setText(str(count_anomalies_today()))
        self.unresolved_value.setText(str(count_issues("Pending", "Ongoing")))
        self.critical_value.setText(str(count_critical_open()))

        # reports that reached Firebase today (the PC works offline and uploads when online)
        scan_n, feedback_n, total_n = uploaded_counts()
        self.sync_value.setText(str(scan_n + feedback_n))
        self.sync_detail.setText(f"Scan {scan_n}  |  Feedback {feedback_n}")
        self.sync_value.setToolTip(f"All-time uploaded: {total_n}\n"
                                   f"Waiting to upload: {pending_outbox_count()}")

        fill_table(self.rank_type, ranking_by_title())
        fill_table(self.rank_pc, ranking_by_computer())

    # ---- real-time readings (CPU / RAM / disk), independent of the 10-minute full scan
    def start_live(self):
        self._live_tick()
        self.live_timer.start()

    def stop_live(self):
        self.live_timer.stop()

    def _live_tick(self):
        cpu = psutil.cpu_percent(None)
        ram = psutil.virtual_memory().percent
        disk = disk_percent()
        self.live_value.setText(f"CPU {cpu:.0f}%   RAM {ram:.0f}%   Disk {disk:.0f}%")
        statuses = []
        for component, value in (("CPU", cpu), ("RAM", ram), ("Disk", disk)):
            warn, crit = THRESHOLDS[component]
            statuses.append("CRITICAL" if value >= crit else "WARNING" if value >= warn else "NORMAL")
        color = (STATUS_COLORS["CRITICAL"] if "CRITICAL" in statuses else
                 STATUS_COLORS["WARNING"] if "WARNING" in statuses else STATUS_COLORS["NORMAL"])
        self.live_value.setStyleSheet(f"font-size: 18px; color: {color};")


# ====================================================== LOGS TAB
class LogsTab(QWidget):
    """Every report and every scan, categorised, with full date + time; admin edits status here."""
    changed = Signal()                   # a status was edited -> dashboard should refresh

    def __init__(self):
        super().__init__()
        tabs = QTabWidget()
        tabs.addTab(self._issues_page(), "Issue Reports")
        tabs.addTab(self._scans_page(), "Scan History")
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

    # ---- issue reports
    def _issues_page(self):
        self.f_status = self._filter(["All"] + list(STATUSES))
        self.f_source = self._filter(["All", "Feedback report", "Scan report"])
        self.f_category = self._filter(["All", "Hardware", "Software", "Unidentified"])
        filters = QHBoxLayout()
        for label, box in (("Status:", self.f_status), ("Report Type:", self.f_source),
                           ("Category:", self.f_category)):
            filters.addWidget(QLabel(label))
            filters.addWidget(box)
        filters.addStretch()

        self.issue_table = make_table(ISSUE_HEADERS)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.evidence = EvidenceViewer()
        self.evidence.hide()              # only feedback reports can carry an image

        self.status_box = QComboBox()
        self.status_box.addItems(STATUSES)
        save = QPushButton("Save status")
        save.clicked.connect(self._save_status)
        edit = QHBoxLayout()
        edit.addWidget(QLabel("Mark selected problem as:"))
        edit.addWidget(self.status_box)
        edit.addWidget(save)
        edit.addStretch()

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addLayout(filters)
        layout.addWidget(self.issue_table, 3)
        detail_row = QHBoxLayout()
        detail_row.addWidget(self.detail, 3)
        detail_row.addWidget(self.evidence, 2)
        layout.addLayout(detail_row, 2)
        layout.addLayout(edit)
        self.issue_table.itemSelectionChanged.connect(self._show_detail)
        return page

    def _filter(self, items):
        box = QComboBox()
        box.addItems(items)
        box.currentIndexChanged.connect(self.refresh)
        return box

    def _show_detail(self):
        row = self.issue_table.currentRow()
        if row < 0:
            self.detail.clear()
            self.evidence.clear()
            self.evidence.hide()
            return
        issue = get_issue(int(self.issue_table.item(row, 0).text()))
        if not issue:
            self.detail.clear()
            self.evidence.clear()
            self.evidence.hide()
            return
        self.status_box.setCurrentText(issue["status"])
        self.detail.setPlainText(issue_detail_text(issue))
        if issue["source"] == "Student":              # feedback report -> show the evidence image
            self.evidence.show_attachment(issue.get("attachment"))
            self.evidence.show()
        else:                                          # scan report -> no evidence panel
            self.evidence.clear()
            self.evidence.hide()

    def _save_status(self):
        row = self.issue_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select a problem", "Select a problem in the table first.")
            return
        update_issue_status(int(self.issue_table.item(row, 0).text()), self.status_box.currentText())
        self.refresh()
        self.changed.emit()

    # ---- scan history
    def _scans_page(self):
        self.scan_table = make_table(["Scan", "Computer", "Report Type", "Overall", "When"])
        self.scan_table.itemSelectionChanged.connect(self._show_scan)
        self.scan_results = make_table(DIAG_COLUMNS)
        self.scan_detail = QTextEdit()
        self.scan_detail.setPlaceholderText("Click a result to read the full finding.")
        self.scan_detail.setMaximumHeight(110)
        wire_detail(self.scan_results, self.scan_detail)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(self.scan_table, 2)
        layout.addWidget(QLabel("Results of the selected scan"))
        layout.addWidget(self.scan_results, 3)
        layout.addWidget(self.scan_detail, 1)
        return page

    def _show_scan(self):
        row = self.scan_table.currentRow()
        if row >= 0:
            fill_table(self.scan_results, get_scan_results(int(self.scan_table.item(row, 0).text())),
                       2, STATUS_COLORS, 2, OVERALL_LABELS)
            self.scan_detail.clear()

    def refresh(self):
        status = self.f_status.currentText()
        source = REPORT_TYPE_TO_SOURCE.get(self.f_source.currentText())   # None when "All"
        category = self.f_category.currentText()
        fill_table(self.issue_table,
                   issue_rows(get_all_issues(None if status == "All" else status, source,
                                             None if category == "All" else category)),
                   4, SEVERITY_COLORS)

        scans = []
        for row in get_scan_history():
            scan_id, computer, kind, stored_overall, when = list(row)[:5]
            rows = get_scan_results(scan_id)
            overall = overall_from_rows(rows) if rows else stored_overall
            scans.append((scan_id, computer, f"Scan report ({str(kind).title()})", overall, when))
        fill_table(self.scan_table, scans, 3, STATUS_COLORS, 3, OVERALL_LABELS)


# ====================================================== MAIN ADMIN SCREEN
class ScanWorker(QThread):
    """Run the slow full scan away from the UI thread."""

    finished_scan = Signal(str)          # empty on success, error text on failure

    def run(self):
        error = ""
        try:
            run_scan("manual")
        except Exception as exc:         # noqa: BLE001
            error = str(exc)
        self.finished_scan.emit(error)


class AdminDashboard(QWidget):
    logout_requested = Signal()
    REFRESH_MS = 30000                  # database cards every 30 s; live readings every 1 s

    def __init__(self):
        super().__init__()
        self.worker = None
        self.welcome = QLabel()
        self.welcome.setObjectName("pageTitle")
        self.scan_btn = QPushButton("Scan Now")
        self.scan_btn.setToolTip("Run a full diagnostic scan now. Automatic scans still run in the background.")
        self.scan_btn.clicked.connect(self._scan_now)
        key_btn = QPushButton("Admin Key")
        key_btn.setObjectName("secondary")
        key_btn.clicked.connect(self._show_admin_key)
        logout_btn = QPushButton("Logout")
        logout_btn.setObjectName("secondary")
        logout_btn.clicked.connect(self._logout)

        header = QHBoxLayout()
        header.addWidget(self.welcome, 1)
        header.addWidget(self.scan_btn)
        header.addWidget(key_btn)
        header.addWidget(logout_btn)

        self.dashboard_tab = DashboardTab()
        self.logs_tab = LogsTab()
        self.logs_tab.changed.connect(self.dashboard_tab.refresh)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.logs_tab, "Logs")
        self.tabs.currentChanged.connect(lambda i: self.logs_tab.refresh() if i == 1 else None)

        layout = QVBoxLayout(self)
        layout.addLayout(header)
        layout.addWidget(self.tabs)

        self.timer = QTimer(self)                 # live refresh (database reads only)
        self.timer.setInterval(self.REFRESH_MS)
        self.timer.timeout.connect(self._auto_refresh)

    def start(self, username):
        self.welcome.setText(f"Admin  |  Logged in as {username}")
        self.dashboard_tab.refresh()
        self.dashboard_tab.start_live()
        self.logs_tab.refresh()
        self.timer.start()

    def _auto_refresh(self):
        self.dashboard_tab.refresh()
        if self.tabs.currentIndex() == 1:
            self.logs_tab.refresh()

    def _scan_now(self):
        if self.worker and self.worker.isRunning():
            return
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning...")
        self.worker = ScanWorker(self)
        self.worker.finished_scan.connect(self._scan_done)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()

    def _scan_done(self, error):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan Now")
        self.worker = None
        self.dashboard_tab.refresh()
        self.logs_tab.refresh()
        if error:
            QMessageBox.warning(self, "Scan failed", error)
        else:
            QMessageBox.information(self, "Scan complete",
                                    "The diagnostic scan finished. The dashboard is up to date.")

    def _logout(self):
        self.timer.stop()
        self.dashboard_tab.stop_live()
        self.logout_requested.emit()

    def _show_admin_key(self):
        """Visible only after a successful admin login."""
        QMessageBox.information(
            self, "Admin registration key",
            "Only share this key with a technician you trust.\n\n"
            f"Admin key:  {get_admin_key()}\n\n"
            "It is stored in admin_key.txt, or supplied through the "
            "LAB_ADMIN_KEY environment variable.")