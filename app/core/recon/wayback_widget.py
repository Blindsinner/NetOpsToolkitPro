# app/advanced_features/recon/wayback_widget.py
# FIXED: calls the async WaybackEngine API via TaskManager, no more "<Task pending ...>"
#        and no more AttributeError for missing sync wrapper.

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

from app.core.recon.wayback_engine import WaybackEngine


class WaybackWidget(QWidget):
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.task_manager = task_manager
        self._engine = WaybackEngine(timeout=15.0)

        root = QVBoxLayout(self)

        # Inputs
        input_group = QGroupBox("Wayback Machine Lookup")
        grid = QGridLayout(input_group)

        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com (domain only, no scheme)")
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("/ (optional path, default '/')")

        self.lookup_btn = QPushButton("Find Latest Snapshot")
        self.lookup_btn.clicked.connect(self._on_click)

        grid.addWidget(QLabel("Domain:"), 0, 0)
        grid.addWidget(self.domain_input, 0, 1)
        grid.addWidget(QLabel("Path:"), 1, 0)
        grid.addWidget(self.path_input, 1, 1)
        grid.addWidget(self.lookup_btn, 0, 2, 2, 1)

        root.addWidget(input_group)

        # Results
        results_group = QGroupBox("Result")
        v = QVBoxLayout(results_group)
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        v.addWidget(self.output)
        root.addWidget(results_group)

    def shutdown(self):
        # if the parent tab calls this, close the HTTP client
        self.task_manager.create_task(self._engine.aclose())

    # ---------- UI callbacks ----------

    def _on_click(self):
        domain = self.domain_input.text().strip()
        path = self.path_input.text().strip() or "/"

        if not domain:
            QMessageBox.warning(self, "Missing Domain", "Please enter a domain like 'example.com'.")
            return

        self.lookup_btn.setEnabled(False)
        self.output.setPlainText(f"Looking up latest snapshot for https://{domain}{path} ...")

        # Schedule the async lookup on the running event loop (qasync-friendly)
        self.task_manager.create_task(self._run_lookup(domain, path))

    async def _run_lookup(self, domain: str, path: str):
        try:
            url = await self._engine.latest_snapshot_url_async(domain, path)
            if url:
                self.output.setPlainText(f"✅ Latest snapshot:\n{url}")
            else:
                self.output.setPlainText("⚠️ No snapshot found for that URL.")
        except Exception as e:
            QMessageBox.critical(self, "Wayback Lookup Failed", str(e))
        finally:
            self.lookup_btn.setEnabled(True)

