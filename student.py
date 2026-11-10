"""student.py - student landing page: report an issue, no login.

The PC details (model, OS, connectivity) are detected automatically, and a health snapshot
of the PC is attached to the report, so the technician sees what the system saw as well as
what the student wrote."""
import os

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QLineEdit,
                               QTextEdit, QComboBox, QCheckBox, QPushButton, QMessageBox,
                               QFileDialog)
from database import save_issue, get_latest_scan
from diagnostics import COMPUTER_NAME, PC_OS, PROBLEM_TYPES, pc_model, build_evidence

CATEGORIES = ["Hardware", "Software", "Unidentified"]
SEVERITIES = ["Minimal", "Notice", "Warning", "Critical"]


class StudentPage(QWidget):
    back_requested = Signal()            # tells the main window to return to role selection

    def __init__(self):
        super().__init__()
        self.attachment_path = ""
        self._build_ui()

    def _build_ui(self):
        title = QLabel("Report a Computer Issue")
        title.setObjectName("pageTitle")

        self.computer = QLineEdit(COMPUTER_NAME)             # pre-filled; students may report another PC
        self.computer.setPlaceholderText("Example: PC 1")
        self.auto_info = QLabel()
        self.auto_info.setObjectName("cardTitle")
        self.category = QComboBox()
        self.category.addItems(CATEGORIES)
        self.problem = QComboBox()
        self.problem.addItems(PROBLEM_TYPES)
        self.severity = QComboBox()
        self.severity.addItems(SEVERITIES)

        self.anonymous = QCheckBox("Submit anonymously")
        self.anonymous.setChecked(True)
        self.anonymous.toggled.connect(self._toggle_name)
        self.name = QLineEdit()
        self.name.setPlaceholderText("Your name (optional)")
        self.name.setEnabled(False)       # disabled while anonymous is ticked

        self.description = QTextEdit()
        self.description.setPlaceholderText("Describe what is wrong, when it started, what you saw...")

        self.attachment_label = QLabel("No image selected")
        self.attachment_label.setWordWrap(True)
        attach = QPushButton("Attach image...")
        attach.setObjectName("secondary")
        attach.clicked.connect(self._pick_attachment)
        clear = QPushButton("Clear")
        clear.setObjectName("secondary")
        clear.clicked.connect(self._clear_attachment)
        attach_row = QHBoxLayout()
        attach_row.addWidget(attach)
        attach_row.addWidget(clear)
        attach_row.addStretch()

        form = QFormLayout()
        form.addRow("Computer ID:", self.computer)
        form.addRow("Detected:", self.auto_info)
        form.addRow("Category:", self.category)
        form.addRow("What is wrong?", self.problem)
        form.addRow("Issue Status:", self.severity)
        form.addRow("", self.anonymous)
        form.addRow("Your name:", self.name)
        form.addRow("Description:", self.description)
        form.addRow("Evidence (optional):", attach_row)
        form.addRow("", self.attachment_label)

        submit = QPushButton("Submit Report")
        submit.clicked.connect(self._submit)
        back = QPushButton("Back")
        back.setObjectName("secondary")
        back.clicked.connect(self.back_requested.emit)

        buttons = QHBoxLayout()
        buttons.addWidget(back)
        buttons.addWidget(submit)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(120, 40, 120, 40)
        layout.addWidget(title)
        layout.addLayout(form)
        layout.addLayout(buttons)

    def showEvent(self, event):
        self._refresh_auto_info()                            # re-read PC info each time the page opens
        super().showEvent(event)

    def _refresh_auto_info(self):
        _, rows = get_latest_scan(COMPUTER_NAME)
        network = next((r[1] for r in rows if r[0] == "Network"), "not scanned yet")
        self.auto_info.setText(f"{PC_OS}  |  {pc_model()}  |  Network: {network}")

    def _toggle_name(self, anonymous):
        self.name.setEnabled(not anonymous)
        if anonymous:
            self.name.clear()

    def _pick_attachment(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Attach evidence", "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif);;All files (*)")
        if path:
            self.attachment_path = path
            self.attachment_label.setText(os.path.basename(path))

    def _clear_attachment(self):
        self.attachment_path = ""
        self.attachment_label.setText("No image selected")

    def _submit(self):
        computer = self.computer.text().strip()
        description = self.description.toPlainText().strip()
        if not computer or not description:
            QMessageBox.warning(self, "Missing information",
                                "Please enter the Computer ID and a description.")
            return
        reporter = "Anonymous" if self.anonymous.isChecked() else (self.name.text().strip() or "Anonymous")

        attachment = None
        if self.attachment_path:
            try:
                if os.path.getsize(self.attachment_path) > 8 * 1024 * 1024:
                    QMessageBox.warning(self, "Attachment too large",
                                        "Please choose an image smaller than 8 MB.")
                    return
                with open(self.attachment_path, "rb") as fh:
                    attachment = fh.read()
            except OSError as exc:
                QMessageBox.warning(self, "Attachment error",
                                    f"Could not read the selected image: {exc}")
                return

        # Evidence only describes THIS PC, so attach it only when the report is about this PC.
        about_this_pc = computer.lower() == COMPUTER_NAME.lower()
        evidence = build_evidence() if about_this_pc else {
            "text": "Reported for a different PC - no system evidence attached.", "verified": 0,
            "connectivity": "Unknown"}

        save_issue(computer, self.category.currentText(), description, self.severity.currentText(), reporter,
                   title=self.problem.currentText(), pc_model=pc_model() if about_this_pc else "",
                   os_info=PC_OS if about_this_pc else "", connectivity=evidence["connectivity"],
                   evidence=evidence["text"], verified=evidence["verified"], attachment=attachment)
        QMessageBox.information(self, "Submitted", "Thank you! Your report has been recorded."
                                + (" A system health snapshot was attached." if about_this_pc else "")
                                + (" Your evidence image was saved." if attachment else ""))
        self.description.clear()
        self._clear_attachment()
        self.anonymous.setChecked(True)