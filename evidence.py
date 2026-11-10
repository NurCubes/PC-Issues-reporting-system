"""evidence.py - shows the optional image a student attached to a report."""
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea,
                               QSizePolicy, QVBoxLayout)


class _ImageLabel(QLabel):
    """QLabel that reports a double-click so the evidence can be opened full screen."""

    double_clicked = Signal()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.double_clicked.emit()
        super().mouseDoubleClickEvent(event)


class EvidenceViewer(QFrame):
    """Preview panel used by the admin dashboard when a report is selected."""

    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        self._pixmap = QPixmap()
        title = QLabel("Evidence")
        title.setObjectName("cardTitle")
        self.full_btn = QPushButton("Full Screen")
        self.full_btn.setObjectName("secondary")
        self.full_btn.setEnabled(False)
        self.full_btn.clicked.connect(self.open_fullscreen)
        title_row = QHBoxLayout()
        title_row.addWidget(title, 1)
        title_row.addWidget(self.full_btn)

        self.image = _ImageLabel("No image attached.")
        self.image.setAlignment(Qt.AlignCenter)
        self.image.setWordWrap(True)
        self.image.setMinimumSize(240, 160)
        self.image.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.image.setToolTip("Double-click to view the image full screen.")
        self.image.double_clicked.connect(self.open_fullscreen)

        layout = QVBoxLayout(self)
        layout.addLayout(title_row)
        layout.addWidget(self.image, 1)

    def show_attachment(self, data):
        if not data:
            self.clear()
            return
        pixmap = QPixmap()
        if pixmap.loadFromData(bytes(data)):
            self._pixmap = pixmap
            self.full_btn.setEnabled(True)
            self._render()
        else:
            self._pixmap = QPixmap()
            self.full_btn.setEnabled(False)
            self.image.setPixmap(QPixmap())
            self.image.setText("The attached file is not a readable image.")

    def clear(self):
        self._pixmap = QPixmap()
        self.full_btn.setEnabled(False)
        self.image.setPixmap(QPixmap())
        self.image.setText("No image attached.")

    def _render(self):
        if self._pixmap.isNull():
            return
        size = self.image.size()
        if size.width() > 10 and size.height() > 10:
            self.image.setPixmap(self._pixmap.scaled(
                size, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._render()

    def open_fullscreen(self):
        """Open the original image in a full-screen dialog with zoom controls."""
        if self._pixmap.isNull():
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Evidence - full size")
        dialog.setStyleSheet("QDialog { background: #111827; } QLabel { color: white; }")

        image = QLabel()
        image.setAlignment(Qt.AlignCenter)
        scroll = QScrollArea()
        scroll.setWidget(image)
        scroll.setWidgetResizable(False)
        scroll.setAlignment(Qt.AlignCenter)
        scroll.setStyleSheet("QScrollArea { background: #111827; border: none; }")
        scroll.viewport().setStyleSheet("background: #111827;")

        zoom_out = QPushButton("Zoom Out")
        zoom_in = QPushButton("Zoom In")
        fit_btn = QPushButton("Fit")
        actual_btn = QPushButton("100%")
        close_btn = QPushButton("Close")
        close_btn.setObjectName("secondary")
        close_btn.clicked.connect(dialog.reject)
        bar = QHBoxLayout()
        for button in (zoom_out, zoom_in, fit_btn, actual_btn):
            button.setObjectName("secondary")
            bar.addWidget(button)
        bar.addStretch()
        bar.addWidget(close_btn)

        layout = QVBoxLayout(dialog)
        layout.addLayout(bar)
        layout.addWidget(scroll, 1)

        original = self._pixmap
        zoom = {"value": 1.0}
        # Do not let a very large screenshot create an enormous zoomed pixmap.
        max_zoom = max(1.0, min(4.0, 4000 / max(original.width(), original.height())))

        def render():
            if abs(zoom["value"] - 1.0) < 0.001:
                scaled = original
            else:
                width = max(1, int(original.width() * zoom["value"]))
                height = max(1, int(original.height() * zoom["value"]))
                scaled = original.scaled(width, height, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            image.setPixmap(scaled)
            image.setFixedSize(scaled.size())

        def fit():
            view = scroll.viewport().size()
            if view.width() <= 10 or view.height() <= 10:
                retry = QTimer(dialog)
                retry.setSingleShot(True)
                retry.timeout.connect(fit)
                retry.start(50)
                return
            zoom["value"] = min(view.width() / original.width(),
                                view.height() / original.height(), 1.0)
            render()

        def zoom_in_click():
            zoom["value"] = min(zoom["value"] * 1.25, max_zoom)
            render()

        def zoom_out_click():
            zoom["value"] = max(zoom["value"] / 1.25, 0.05)
            render()

        def actual_size():
            zoom["value"] = 1.0
            render()

        zoom_in.clicked.connect(zoom_in_click)
        zoom_out.clicked.connect(zoom_out_click)
        fit_btn.clicked.connect(fit)
        actual_btn.clicked.connect(actual_size)

        dialog.showFullScreen()
        fit_timer = QTimer(dialog)
        fit_timer.setSingleShot(True)
        fit_timer.timeout.connect(fit)
        fit_timer.start(0)
        dialog.exec()
