# app/advanced_features/recon/whois_widget.py
# Robust WHOIS widget with safe fallbacks & no-crash behavior.

import asyncio
from typing import Any, Dict, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QFormLayout,
    QLineEdit, QPushButton, QTextEdit, QLabel, QHBoxLayout, QMessageBox
)

try:
    import whois as pywhois  # python-whois
except Exception:
    pywhois = None


def _safe_str(x: Any) -> str:
    if x is None:
        return "-"
    if isinstance(x, (list, tuple, set)):
        return ", ".join([str(i) for i in x if i is not None])
    return str(x)


class WhoisWidget(QWidget):
    def __init__(self, settings, task_manager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.settings = settings
        self.task_manager = task_manager

        root = QVBoxLayout(self)

        # Inputs
        box = QGroupBox("WHOIS Lookup")
        form = QFormLayout(box)
        self.domain_edit = QLineEdit()
        self.btn_lookup = QPushButton("Lookup")
        self.btn_lookup.clicked.connect(self._on_lookup_clicked)

        row = QHBoxLayout()
        row.addWidget(self.btn_lookup)

        form.addRow("Domain or IP:", self.domain_edit)
        form.addRow(row)

        # Output
        self.out = QTextEdit()
        self.out.setReadOnly(True)

        note = QLabel("Note: WHOIS servers vary by TLD; throttling/odd shapes happen. We catch those.")
        note.setWordWrap(True)

        root.addWidget(box)
        root.addWidget(self.out)
        root.addWidget(note)

    def _on_lookup_clicked(self):
        target = (self.domain_edit.text() or "").strip()
        if not target:
            QMessageBox.warning(self, "Input needed", "Type a domain or IP first.")
            return
        if pywhois is None:
            QMessageBox.critical(
                self, "python-whois missing",
                "The 'python-whois' package is not available. Install it and try again."
            )
            return

        self.btn_lookup.setEnabled(False)
        self.out.clear()

        async def run():
            try:
                loop = asyncio.get_running_loop()
                # run WHOIS in a thread to avoid blocking the event loop
                data: Dict[str, Any] = await loop.run_in_executor(None, lambda: pywhois.whois(target))
                self._render(data or {})
            except Exception as e:
                self._append(f"[ERROR] WHOIS lookup failed: {e}")
            finally:
                self.btn_lookup.setEnabled(True)

        self.task_manager.create_task(run())

    def _render(self, data: Dict[str, Any]):
        # Common fields across many WHOIS servers
        keys = [
            "domain_name", "status", "registrar", "org", "country", "state",
            "emails", "name_servers", "creation_date", "updated_date", "expiration_date"
        ]

        self._append(f"=== WHOIS RESULT ===")
        for k in keys:
            self._append(f"{k.replace('_', ' ').title()}: {_safe_str(data.get(k))}")

        # Dump any extra keys we didn't list
        extras = {k: v for k, v in data.items() if k not in keys}
        if extras:
            self._append("\n--- Raw Fields ---")
            for k, v in extras.items():
                self._append(f"{k}: {_safe_str(v)}")

    def _append(self, text: str):
        if text:
            self.out.append(text)

