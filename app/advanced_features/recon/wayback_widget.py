# app/advanced_features/recon/wayback_widget.py
from __future__ import annotations

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from PySide6.QtCore import Qt

try:
    from app.core.recon.wayback_engine import WaybackEngine
except Exception:  # pragma: no cover
    WaybackEngine = None  # Fallback if engine is not present


class WaybackWidget(QWidget):
    def __init__(self, settings=None, task_manager=None, parent=None, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.settings = settings
        self.task_manager = task_manager
        self.setObjectName("WaybackWidget")

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Wayback Machine lookup"))

        self.domain_edit = QLineEdit(self)
        self.domain_edit.setPlaceholderText("example.com")

        self.path_edit = QLineEdit(self)
        self.path_edit.setPlaceholderText("/ (optional path)")

        self.btn = QPushButton("Find latest snapshot", self)
        self.out = QTextEdit(self)
        self.out.setReadOnly(True)

        layout.addWidget(self.domain_edit)
        layout.addWidget(self.path_edit)
        layout.addWidget(self.btn)
        layout.addWidget(self.out)

        self.btn.clicked.connect(self._on_click)
        self._engine = WaybackEngine() if WaybackEngine else None

    def _on_click(self):
        domain = self.domain_edit.text().strip()
        path = self.path_edit.text().strip() or "/"
        if not domain:
            self.out.setPlainText("Enter a domain first.")
            return

        if not self._engine:
            self.out.setPlainText("WaybackEngine not available (module missing).")
            return

        # call sync wrapper that safely runs async underneath
        result = self._engine.latest_snapshot_url(domain, path)
        try:
            # If under qasync, it could be a Future
            url = getattr(result, "result", lambda: result)()
        except Exception:
            url = str(result)

        self.out.setPlainText(url or "No snapshot found.")

