# -*- coding: utf-8 -*-
from PySide6.QtWidgets import (
    QVBoxLayout, QLineEdit, QGroupBox, QGridLayout,
    QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QPlainTextEdit, QCheckBox, QHBoxLayout
)
from app.widgets.base_widget import BaseToolWidget

class LookupWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        layout = QVBoxLayout(self)

        lookup_group = QGroupBox("GeoIP & WHOIS Lookup")
        group_layout = QGridLayout(lookup_group)
        self.target_input = QLineEdit()
        self.geoip_button = QPushButton("Lookup GeoIP")
        self.whois_button = QPushButton("Lookup WHOIS")
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["Property", "Value"])
        
        group_layout.addWidget(QLabel("IP or Domain:"), 0, 0)
        group_layout.addWidget(self.target_input, 0, 1, 1, 2)
        group_layout.addWidget(self.geoip_button, 1, 1)
        group_layout.addWidget(self.whois_button, 1, 2)
        group_layout.addWidget(self.results_table, 2, 0, 1, 3)
        
        # --- NEW: Export Buttons for Lookup Table ---
        export_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy Results")
        export_btn = QPushButton("Export Results")
        export_layout.addStretch()
        export_layout.addWidget(copy_btn)
        export_layout.addWidget(export_btn)
        group_layout.addLayout(export_layout, 3, 0, 1, 3)
        layout.addWidget(lookup_group)

        dns_group = QGroupBox("DNS Resolver")
        dns_layout = QGridLayout(dns_group)
        self.dns_button = QPushButton("Query DNS Records")
        self.dns_results = QPlainTextEdit()
        self.dns_results.setReadOnly(True)
        self.record_types = {}
        for i, r_type in enumerate(["A", "AAAA", "MX", "TXT", "NS", "CNAME"]):
            cb = QCheckBox(r_type); cb.setChecked(True)
            self.record_types[r_type] = cb
            dns_layout.addWidget(cb, 0, i)
        
        dns_layout.addWidget(self.dns_button, 0, len(self.record_types), 1, -1)
        dns_layout.addWidget(self.dns_results, 1, 0, 1, -1)
        layout.addWidget(dns_group)

        self.geoip_button.clicked.connect(lambda: self.task_manager.create_task(self.perform_geoip()))
        self.whois_button.clicked.connect(lambda: self.task_manager.create_task(self.perform_whois()))
        self.dns_button.clicked.connect(lambda: self.task_manager.create_task(self.perform_dns()))
        copy_btn.clicked.connect(lambda: self._copy_table_data(self.results_table))
        export_btn.clicked.connect(lambda: self._export_table_to_csv(self.results_table, "lookup_results.csv"))
        
        self.load_state()

    async def perform_geoip(self):
        target = self.target_input.text().strip()
        self.results_table.setRowCount(0); self.geoip_button.setEnabled(False)
        try:
            data = await self.network_tools.get_ip_geolocation(target)
            if data.get("error"): self.show_error(data["error"])
            else:
                self.results_table.setRowCount(len(data))
                for r, (k, v) in enumerate(data.items()):
                    self.results_table.setItem(r, 0, QTableWidgetItem(k.title()))
                    self.results_table.setItem(r, 1, QTableWidgetItem(str(v)))
        finally:
            self.geoip_button.setEnabled(True)

    async def perform_whois(self):
        target = self.target_input.text().strip()
        self.results_table.setRowCount(0); self.whois_button.setEnabled(False)
        try:
            data = await self.network_tools.get_whois_info(target)
            if data.get("error"): self.show_error(data["error"])
            else:
                flat_data = {k: ", ".join(map(str, v)) if isinstance(v, list) else v for k, v in data.items() if v}
                self.results_table.setRowCount(len(flat_data))
                for r, (k, v) in enumerate(flat_data.items()):
                    self.results_table.setItem(r, 0, QTableWidgetItem(k.replace("_", " ").title()))
                    self.results_table.setItem(r, 1, QTableWidgetItem(str(v)))
        finally:
            self.whois_button.setEnabled(True)

    async def perform_dns(self):
        target = self.target_input.text().strip()
        self.dns_results.clear(); self.dns_button.setEnabled(False)
        try:
            types_to_query = [t for t, cb in self.record_types.items() if cb.isChecked()]
            data = await self.network_tools.get_dns_records(target, types_to_query)
            for r_type, records in data.items():
                self.dns_results.appendPlainText(f"--- {r_type} Records ---\n" + "\n".join(records) + "\n")
        finally:
            self.dns_button.setEnabled(True)

    def load_state(self):
        self.target_input.setText(self.settings.value("lookups/target", "cloudflare.com"))

    def save_state(self):
        self.settings.setValue("lookups/target", self.target_input.text())