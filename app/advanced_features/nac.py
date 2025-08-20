# -*- coding: utf-8 -*-
import json
import datetime
import asyncio
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QPushButton,
    QGroupBox, QFormLayout, QLineEdit, QComboBox, QTableWidgetItem,
    QHeaderView, QMessageBox, QApplication, QFileDialog
)
from PySide6.QtGui import QColor
from PySide6.QtCore import Qt
from app.config import AppConfig
from app.core.task_manager import TaskManager
from app.core.system_tools import SystemTools
from app.core.nac_engine import NacEngine
from app.core.app_logger import activity_logger

KNOWN_MACS_FILE = AppConfig.PROJECT_ROOT / "known_macs.json"

class NacDialog(QDialog):
    def __init__(self, settings, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        # Store essential components
        self.settings = settings
        self.task_manager = task_manager
        self.system_tools = SystemTools()
        self.engine = NacEngine()
        self.known_macs = self._load_known_macs()

        # Window setup
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.setWindowTitle("Simple Network Access Control (NAC)")
        self.setMinimumSize(800, 600)
        self.resize(800, 600)
        
        # UI Layout
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
        copy_btn.clicked.connect(self._copy_table_data)
        export_btn.clicked.connect(self._export_table_to_csv)

        self.load_state()

    def _load_known_macs(self):
        if not KNOWN_MACS_FILE.exists(): return {}
        try:
            with open(KNOWN_MACS_FILE, 'r') as f: return json.load(f)
        except (json.JSONDecodeError, IOError): return {}

    def _save_known_macs(self):
        try:
            with open(KNOWN_MACS_FILE, 'w') as f: json.dump(self.known_macs, f, indent=4)
        except IOError as e:
            QMessageBox.warning(self, "Save Error", f"Could not save known MACs file: {e}")

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
            QMessageBox.warning(self, "Input Error", "Target CIDR and a usable Interface are required.")
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
            QMessageBox.warning(self, "Selection Error", "Please select a device (cell) in the table.")
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

        # Update the row visually
        is_known = mac in self.known_macs
        status = "Trusted" if is_known else "Unknown"
        status_item = self.results_table.item(row, 0)
        status_item.setText(status)
        status_item.setForeground(QColor("green") if is_known else QColor("orange"))
        
    def _copy_table_data(self):
        table = self.results_table
        header = [table.horizontalHeaderItem(c).text() for c in range(table.columnCount())]
        lines = ["\t".join(header)]
        for r in range(table.rowCount()):
            row_data = [table.item(r, c).text() if table.item(r, c) else "" for c in range(table.columnCount())]
            lines.append("\t".join(row_data))
        QApplication.clipboard().setText("\n".join(lines))
        QMessageBox.information(self, "Success", "Data copied to clipboard.")

    def _export_table_to_csv(self):
        table = self.results_table
        path, _ = QFileDialog.getSaveFileName(self, "Export to CSV", "nac_scan.csv", "CSV Files (*.csv)")
        if not path: return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                header = [table.horizontalHeaderItem(c).text() for c in range(table.columnCount())]
                f.write(",".join(header) + "\n")
                for r in range(table.rowCount()):
                    row_data = [f'"{table.item(r, c).text()}"' if table.item(r, c) else "" for c in range(table.columnCount())]
                    f.write(",".join(row_data) + "\n")
            QMessageBox.information(self, "Success", f"Data successfully exported to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export file: {e}")