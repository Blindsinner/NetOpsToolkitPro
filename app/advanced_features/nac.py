# app/advanced_features/nac.py
# REFACTORED: Added a right-click context menu to emit signals for inter-tool communication.

import json
import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QPushButton,
    QGroupBox, QFormLayout, QLineEdit, QComboBox, QTableWidgetItem,
    QHeaderView, QMessageBox, QApplication, QFileDialog, QMenu
)
from PySide6.QtGui import QColor
from PySide6.QtCore import Qt
from app.config import AppConfig
from app.widgets.base_widget import BaseToolWidget
from app.core.task_manager import TaskManager
from app.core.system_tools import SystemTools
from app.core.nac_engine import NacEngine
from app.core.app_logger import activity_logger
from app.core.signals import signal_manager # Import the global signal manager

KNOWN_MACS_FILE = AppConfig.PROJECT_ROOT / "known_macs.json"

class NacWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.system_tools = SystemTools()
        self.engine = NacEngine()
        self.known_macs = self._load_known_macs()

        layout = QVBoxLayout(self)
        
        controls_group = QGroupBox("Scan Configuration")
        form = QFormLayout(controls_group)
        self.target_range_input = QLineEdit()
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.system_tools.get_usable_interfaces())
        self.scan_btn = QPushButton("Scan Network")
        form.addRow("Target CIDR:", self.target_range_input)
        form.addRow("Scan Interface:", self.interface_combo)
        layout.addWidget(controls_group)
        layout.addWidget(self.scan_btn)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Status", "IP Address", "MAC Address", "Vendor"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        # FIX: Enable custom context menu
        self.results_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        layout.addWidget(self.results_table)
        
        action_layout = QHBoxLayout()
        self.trust_btn = QPushButton("Trust Selected MAC")
        self.untrust_btn = QPushButton("Untrust Selected MAC")
        action_layout.addStretch()
        action_layout.addWidget(self.trust_btn)
        action_layout.addWidget(self.untrust_btn)
        layout.addLayout(action_layout)
        
        export_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy All")
        export_btn = QPushButton("Export to CSV")
        export_layout.addStretch()
        export_layout.addWidget(copy_btn)
        export_layout.addWidget(export_btn)
        layout.addLayout(export_layout)

        # Connections
        self.scan_btn.clicked.connect(self.run_scan)
        self.trust_btn.clicked.connect(lambda: self.update_trust(trust=True))
        self.untrust_btn.clicked.connect(lambda: self.update_trust(trust=False))
        copy_btn.clicked.connect(lambda: self._copy_table_data(self.results_table))
        export_btn.clicked.connect(lambda: self._export_table_to_csv(self.results_table, "nac_scan.csv"))
        # FIX: Connect the context menu signal
        self.results_table.customContextMenuRequested.connect(self.show_context_menu)

        self.load_state()

    # FIX: New method to show the context menu and emit signals
    def show_context_menu(self, pos):
        selected_items = self.results_table.selectedItems()
        if not selected_items:
            return

        row = selected_items[0].row()
        ip_item = self.results_table.item(row, 1)
        if not ip_item:
            return
        
        target_ip = ip_item.text()
        
        menu = QMenu()
        scan_action = menu.addAction("Scan with Nmap (Intense Scan)")
        threat_action = menu.addAction("Query Threat Intelligence")
        
        action = menu.exec(self.results_table.mapToGlobal(pos))
        
        if action == scan_action:
            activity_logger.log("Cross-Tool Action", f"NAC -> Nmap Scan for {target_ip}")
            signal_manager.request_network_scan.emit({"target": target_ip, "scan_type": "Intense Scan"})
        elif action == threat_action:
            activity_logger.log("Cross-Tool Action", f"NAC -> Threat Intel for {target_ip}")
            signal_manager.request_threat_intel.emit(target_ip)

    def _load_known_macs(self):
        if not KNOWN_MACS_FILE.exists(): return {}
        try:
            with open(KNOWN_MACS_FILE, 'r') as f: return json.load(f)
        except (json.JSONDecodeError, IOError): return {}

    def _save_known_macs(self):
        try:
            with open(KNOWN_MACS_FILE, 'w') as f: json.dump(self.known_macs, f, indent=4)
        except IOError as e:
            self.show_error(f"Could not save known MACs file: {e}")

    def load_state(self):
        lan_info = self.system_tools.get_default_lan_info()
        default_target = lan_info.get('cidr', "192.168.1.0/24")
        self.target_range_input.setText(self.settings.value("nac/target", default_target))
        if lan_info and lan_info.get("adapter") in [self.interface_combo.itemText(i) for i in range(self.interface_combo.count())]:
            self.interface_combo.setCurrentText(lan_info.get("adapter"))
        
    def run_scan(self):
        target = self.target_range_input.text().strip()
        interface = self.interface_combo.currentText()
        if not target or not interface:
            self.show_error("Target CIDR and a usable Interface are required.")
            return
        
        activity_logger.log("NAC Scan Started", f"Target: {target}")
        self.scan_btn.setEnabled(False); self.results_table.setRowCount(0)
        self.task_manager.create_task(self._stream_scan_results(target, interface))

    async def _stream_scan_results(self, target, interface):
        async for device in self.engine.discover_devices(target, interface):
            row = self.results_table.rowCount(); self.results_table.insertRow(row)
            mac = device.get('mac', 'N/A').upper()
            is_known = mac in self.known_macs
            status = "Trusted" if is_known else "Unknown"
            status_item = QTableWidgetItem(status)
            status_item.setForeground(QColor("green") if is_known else QColor("orange"))
            self.results_table.setItem(row, 0, status_item)
            self.results_table.setItem(row, 1, QTableWidgetItem(device.get('ip', 'N/A')))
            self.results_table.setItem(row, 2, QTableWidgetItem(mac))
            self.results_table.setItem(row, 3, QTableWidgetItem(device.get('vendor', 'N/A')))
        self.scan_btn.setEnabled(True)

    def update_trust(self, trust: bool):
        selected_items = self.results_table.selectedItems()
        if not selected_items:
            self.show_error("Please select a device (cell) in the table.")
            return
        row = selected_items[0].row()
        mac_item = self.results_table.item(row, 2)
        if not mac_item: return
        mac = mac_item.text()
        
        if trust:
            self.known_macs[mac] = {"first_seen": str(datetime.datetime.now())}
            activity_logger.log("NAC Device Trusted", mac)
        else:
            if mac in self.known_macs:
                del self.known_macs[mac]
                activity_logger.log("NAC Device Untrusted", mac)
        self._save_known_macs()

        is_known = mac in self.known_macs
        status = "Trusted" if is_known else "Unknown"
        status_item = self.results_table.item(row, 0)
        status_item.setText(status)
        status_item.setForeground(QColor("green") if is_known else QColor("orange"))
