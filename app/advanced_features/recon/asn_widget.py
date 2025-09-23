# app/advanced_features/recon/asn_widget.py
from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTextEdit, QGroupBox, QLabel, QTableWidget, QTableWidgetItem, QMessageBox
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

from app.core.recon.asn_engine import ASNEngine
from app.core.task_manager import TaskManager


class ASNWidget(QWidget):
    """
    Simple UI wrapper around ASNEngine with progress & results table.
    """
    def __init__(self, settings, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.task_manager = task_manager
        self.engine = ASNEngine(task_manager=task_manager)

        root = QVBoxLayout(self)

        # Inputs
        box = QGroupBox("ASN Intelligence")
        boxlay = QVBoxLayout(box)

        row = QHBoxLayout()
        self.query_edit = QLineEdit()
        self.query_edit.setPlaceholderText("AS number, IP, or domain (e.g., AS32934, 57.144.112.1, facebook.com)")
        self.btn_run = QPushButton("Run")
        self.btn_cancel = QPushButton("Cancel")
        row.addWidget(QLabel("Query:"))
        row.addWidget(self.query_edit)
        row.addWidget(self.btn_run)
        row.addWidget(self.btn_cancel)
        boxlay.addLayout(row)

        # Progress
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("Consolas", 10))
        boxlay.addWidget(self.log)

        root.addWidget(box)

        # Results table
        self.table = QTableWidget(0, 6, self)
        self.table.setHorizontalHeaderLabels(["ASN", "Org", "Country", "CIDR", "Name", "Description"])
        self.table.horizontalHeader().setStretchLastSection(True)
        root.addWidget(self.table)

        # Signals
        self.btn_run.clicked.connect(self._on_run)
        self.btn_cancel.clicked.connect(self._on_cancel)

        self.engine.progress.connect(self._on_progress)
        self.engine.error.connect(self._on_error)
        self.engine.finished.connect(self._on_finished)

    def _on_run(self):
        q = self.query_edit.text().strip()
        if not q:
            QMessageBox.warning(self, "Missing input", "Enter AS number, IP, or domain.")
            return
        self.log.clear()
        self.table.setRowCount(0)
        self._set_enabled(False)
        self.engine.run(q)

    def _on_cancel(self):
        self.engine.cancel()
        self._set_enabled(True)
        self._on_progress("Cancelled.")

    def _on_progress(self, msg: str):
        self.log.append(msg)

    def _on_error(self, msg: str):
        self._set_enabled(True)
        self.log.append(f"ERROR: {msg}")

    def _on_finished(self, rows: list[dict]):
        self._set_enabled(True)
        if not rows:
            self.log.append("No results.")
            return
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(str(r.get("asn", ""))))
            self.table.setItem(i, 1, QTableWidgetItem(r.get("organization") or ""))
            self.table.setItem(i, 2, QTableWidgetItem(r.get("country") or ""))
            self.table.setItem(i, 3, QTableWidgetItem(r.get("cidr") or ""))
            self.table.setItem(i, 4, QTableWidgetItem(r.get("name") or ""))
            self.table.setItem(i, 5, QTableWidgetItem(r.get("description") or ""))

    def _set_enabled(self, ok: bool):
        self.btn_run.setEnabled(ok)
        self.btn_cancel.setEnabled(not ok)
        self.query_edit.setEnabled(ok)

    # optional hook used by tab manager
    def shutdown(self):
        self.engine.cancel()

