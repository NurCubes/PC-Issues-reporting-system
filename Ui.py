"""ui.py - entry point: role selection + page navigation. Run:  python ui.py"""
import sys
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QApplication, QMainWindow, QStackedWidget, QWidget, QVBoxLayout,
                               QHBoxLayout, QLabel, QPushButton)
from database import initialize_database
from monitor import start_monitor
from student import StudentPage
from admin import AdminLoginPage, AdminDashboard

APP_NAME = "Computer Lab Issues Reporting System"

STYLE = """
QWidget { font-family: Segoe UI, Arial; font-size: 13px; }
QLabel#pageTitle { font-size: 22px; font-weight: bold; padding: 8px; }
QPushButton { padding: 10px 18px; background: #1f2937; color: white; border-radius: 6px; }
QPushButton:hover { background: #374151; }
QPushButton:disabled { background: #9ca3af; }
QPushButton#secondary { background: #9ca3af; }
QPushButton#role { font-size: 18px; padding: 40px 60px; }
QLineEdit, QTextEdit, QComboBox { padding: 7px; border: 1px solid #cbd5e1; border-radius: 4px; }
QFrame#card { background: #f3f4f6; border-radius: 10px; padding: 10px; }
QLabel#cardTitle { color: #4b5563; font-weight: bold; }
QLabel#cardValue { font-size: 30px; font-weight: bold; }
"""


class RolePage(QWidget):
    """Landing page: choose Student or Admin/Technician."""
    def __init__(self, on_student, on_admin):
        super().__init__()
        title = QLabel(APP_NAME)
        title.setObjectName("pageTitle")
        title.setAlignment(Qt.AlignCenter)
        subtitle = QLabel("Select your role to continue")
        subtitle.setAlignment(Qt.AlignCenter)

        student_btn = QPushButton("Student\nReport an issue")
        student_btn.setObjectName("role")
        student_btn.clicked.connect(on_student)
        admin_btn = QPushButton("Admin / Technician\nLogin required")
        admin_btn.setObjectName("role")
        admin_btn.clicked.connect(on_admin)

        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(student_btn)
        row.addWidget(admin_btn)
        row.addStretch()

        layout = QVBoxLayout(self)
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addLayout(row)
        layout.addStretch()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1100, 720)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.role_page = RolePage(lambda: self.go_to(self.student_page),
                                  lambda: self.go_to(self.login_page))
        self.student_page = StudentPage()
        self.login_page = AdminLoginPage()
        self.dashboard = AdminDashboard()

        for page in (self.role_page, self.student_page, self.login_page, self.dashboard):
            self.stack.addWidget(page)

        self.student_page.back_requested.connect(lambda: self.go_to(self.role_page))
        self.login_page.back_requested.connect(lambda: self.go_to(self.role_page))
        self.login_page.login_success.connect(self._open_dashboard)
        self.dashboard.logout_requested.connect(lambda: self.go_to(self.role_page))

    def go_to(self, page):
        self.stack.setCurrentWidget(page)

    def _open_dashboard(self, username):
        self.dashboard.start(username)
        self.go_to(self.dashboard)


if __name__ == "__main__":
    initialize_database()
    monitor = start_monitor()              # None if monitor.py is already running headless on this PC
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    if monitor:
        app.aboutToQuit.connect(monitor.stop)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())