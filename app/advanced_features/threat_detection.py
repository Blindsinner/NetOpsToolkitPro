# app/advanced_features/threat_detection.py
# REFACTORED: QWidget-based Threat Intel with input validation to avoid 422.

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QLineEdit, QPushButton, QLabel,
    QGroupBox, QTextEdit, QInputDialog, QMessageBox
)
from PySide6.QtGui import QFont
from app.core.task_manager import TaskManager
from app.core.threat_intelligence import ThreatIntel
import ipaddress
import asyncio


class ThreatIntelWidget(QWidget):
    def __init__(self, settings, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.task_manager = task_manager
        self.intel = ThreatIntel()

        main_layout = QVBoxLayout(self)
        input_group = QGroupBox("Query")
        input_layout = QGridLayout(input_group)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP Address (e.g. 8.8.8.8)")
        self.abuseipdb_btn = QPushButton("Query AbuseIPDB")
        self.api_key_btn = QPushButton("Set API Key")
        input_layout.addWidget(QLabel("IP Address:"), 0, 0)
        input_layout.addWidget(self.target_input, 0, 1)
        input_layout.addWidget(self.abuseipdb_btn, 0, 2)
        input_layout.addWidget(self.api_key_btn, 1, 2)
        main_layout.addWidget(input_group)

        results_group = QGroupBox("AbuseIPDB Report")
        results_layout = QVBoxLayout(results_group)
        self.results_output = QTextEdit()
        self.results_output.setReadOnly(True)
        self.results_output.setFont(QFont("Consolas", 10))
        results_layout.addWidget(self.results_output)
        main_layout.addWidget(results_group)

        self.abuseipdb_btn.clicked.connect(self.run_abuseipdb_query)
        self.api_key_btn.clicked.connect(self.set_api_key)

    def set_api_key(self):
        current_key = self.settings.value("threatintel/abuseipdb_key", "")
        text, ok = QInputDialog.getText(
            self, "Set API Key",
            "Enter your AbuseIPDB API key.\n(Get a free key from abuseipdb.com)",
            QLineEdit.EchoMode.Normal, current_key
        )
        if ok and text:
            self.settings.setValue("threatintel/abuseipdb_key", text)
            QMessageBox.information(self, "Success", "API Key saved.")

    def run_abuseipdb_query(self):
        target = self.target_input.text().strip()
        # Validate IP to avoid 422 when users type a domain
        try:
            ipaddress.ip_address(target)
        except ValueError:
            QMessageBox.warning(self, "Invalid IP", "Please enter a valid IPv4/IPv6 address (e.g. 8.8.8.8).")
            return

        api_key = self.settings.value("threatintel/abuseipdb_key", "")
        if not api_key:
            QMessageBox.warning(self, "API Key Missing", "Please set your AbuseIPDB API key first.")
            return

        self.abuseipdb_btn.setEnabled(False)
        self.results_output.setText(f"Querying {target}...")

        self.task_manager.create_task(self._do_abuseipdb(target, api_key))

    async def _do_abuseipdb(self, ip: str, key: str):
        try:
            response = await self.intel.query_abuseipdb(ip, key)
            if "error" in response:
                self.results_output.setText(f"ERROR: {response['error']}")
            elif "data" in response:
                self.display_report(response["data"])
            else:
                self.results_output.setText("No data returned.")
        except Exception as e:
            self.results_output.setText(f"ERROR: {e}")
        finally:
            # small yield so UI can repaint before re‑enable on qasync
            await asyncio.sleep(0)
            self.abuseipdb_btn.setEnabled(True)

    def display_report(self, data: dict):
        report = [
            f"--- REPORT FOR {data.get('ipAddress')} ---",
            f"Public: {'Yes' if data.get('isPublic') else 'No'}",
            f"IP Version: {data.get('ipVersion')}",
            f"Whitelist: {'Yes' if data.get('isWhitelisted') else 'No'}",
            f"Abuse Confidence Score: {data.get('abuseConfidenceScore')}%",
            f"Country: {data.get('countryCode')}",
            f"ISP: {data.get('isp')}",
            f"Domain: {data.get('domain')}",
            f"Total Reports: {data.get('totalReports')}",
            f"Last Reported: {data.get('lastReportedAt')}",
        ]
        self.results_output.setText("\n".join(report))

