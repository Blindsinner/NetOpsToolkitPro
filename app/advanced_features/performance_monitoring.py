# app/advanced_features/performance_monitoring.py
# REFACTORED: Changed from QDialog to BaseToolWidget and implemented shutdown().

import json
import time
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QComboBox, QPushButton, QLineEdit, # QDialog changed to QWidget
    QLabel, QGroupBox, QTableWidget, QTableWidgetItem, QMessageBox,
    QFormLayout, QHeaderView
)
from PySide6.QtCore import QTimer, Qt
from app.config import AppConfig # Using AppConfig for path consistency
from app.widgets.base_widget import BaseToolWidget
from app.core.performance_monitor import PerformanceMonitor

# Path defined using AppConfig for robustness
DEVICES_FILE = AppConfig.PROJECT_ROOT / "device_configs" / "devices.json"

class PerformanceMonitoringWidget(BaseToolWidget): # REFACTORED: Class name and inheritance
    def __init__(self, settings, task_manager): # REFACTORED: Consistent constructor
        super().__init__(settings, task_manager)
        
        self.monitor = PerformanceMonitor()
        self.devices = self._load_devices()
        self.selected_device = None
        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self.update_interface_stats)
        self.last_stats = {}; self.last_timestamp = 0
        
        # REFACTORED: Window setup (setWindowTitle, etc.) is removed.

        main_layout = QVBoxLayout(self)
        selection_group = QGroupBox("Device & SNMP Configuration")
        selection_layout = QGridLayout(selection_group)
        self.device_combo = QComboBox()
        self.device_combo.addItems([d.get("host") for d in self.devices])
        self.snmp_community_input = QLineEdit("public")
        self.snmp_version_combo = QComboBox()
        self.snmp_version_combo.addItems(["2", "1"])
        self.test_snmp_btn = QPushButton("Test SNMP")
        self.fetch_stats_btn = QPushButton("Fetch Basic Stats")
        selection_layout.addWidget(QLabel("Target Device:"), 0, 0)
        selection_layout.addWidget(self.device_combo, 0, 1)
        selection_layout.addWidget(QLabel("SNMP Community:"), 1, 0)
        selection_layout.addWidget(self.snmp_community_input, 1, 1)
        selection_layout.addWidget(QLabel("SNMP Version:"), 2, 0)
        selection_layout.addWidget(self.snmp_version_combo, 2, 1)
        selection_layout.addWidget(self.test_snmp_btn, 3, 0)
        selection_layout.addWidget(self.fetch_stats_btn, 3, 1)
        main_layout.addWidget(selection_group)
        
        results_group = QGroupBox("Device Information")
        self.results_layout = QFormLayout(results_group)
        self.sys_name_label = QLineEdit(); self.sys_descr_label = QLineEdit()
        self.sys_uptime_label = QLineEdit(); self.cpu_load_label = QLineEdit()
        for label in [self.sys_name_label, self.sys_descr_label, self.sys_uptime_label, self.cpu_load_label]:
            label.setReadOnly(True)
        self.results_layout.addRow("System Name:", self.sys_name_label)
        self.results_layout.addRow("Description:", self.sys_descr_label)
        self.results_layout.addRow("Uptime:", self.sys_uptime_label)
        self.results_layout.addRow("Avg. CPU Load:", self.cpu_load_label)
        main_layout.addWidget(results_group)
        
        iface_group = QGroupBox("Real-time Interface Monitor")
        iface_layout = QGridLayout(iface_group)
        self.iface_combo = QComboBox()
        self.start_monitor_btn = QPushButton("Start Monitoring")
        self.stop_monitor_btn = QPushButton("Stop Monitoring")
        self.stop_monitor_btn.setEnabled(False)
        self.iface_table = QTableWidget(1, 5)
        self.iface_table.setHorizontalHeaderLabels(["Status", "In (Bps)", "Out (Bps)", "In (pkts/s)", "Out (pkts/s)"])
        self.iface_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        iface_layout.addWidget(QLabel("Interface:"), 0, 0)
        iface_layout.addWidget(self.iface_combo, 0, 1)
        iface_layout.addWidget(self.start_monitor_btn, 0, 2)
        iface_layout.addWidget(self.stop_monitor_btn, 0, 3)
        iface_layout.addWidget(self.iface_table, 1, 0, 1, 4)
        main_layout.addWidget(iface_group)
        
        self.test_snmp_btn.clicked.connect(lambda: self.task_manager.create_task(self.test_snmp()))
        self.fetch_stats_btn.clicked.connect(lambda: self.task_manager.create_task(self.fetch_basic_stats()))
        self.start_monitor_btn.clicked.connect(self.start_monitoring)
        self.stop_monitor_btn.clicked.connect(self.stop_monitoring)
        
        if not self.devices:
            QMessageBox.information(self, "No Devices", "No devices found in inventory. Please add devices in 'Config Management' first.")
            self.setEnabled(False)

    def shutdown(self):
        """Gracefully stop the monitoring timer when the tab is closed."""
        self.stop_monitoring()

    def _load_devices(self):
        if not DEVICES_FILE.exists(): return []
        try:
            with open(DEVICES_FILE, 'r') as f: return json.load(f)
        except (json.JSONDecodeError, IOError): return []

    def _get_selected_device_info(self):
        host = self.device_combo.currentText()
        if not host: return None
        device_info = next((d for d in self.devices if d["host"] == host), None)
        if device_info:
            device_info["snmp_community"] = self.snmp_community_input.text()
            device_info["snmp_version"] = int(self.snmp_version_combo.currentText())
        return device_info

    async def test_snmp(self):
        device_info = self._get_selected_device_info()
        if not device_info: QMessageBox.warning(self, "Warning", "No device selected."); return
        success, message = await self.monitor.test_snmp(device_info)
        if success: QMessageBox.information(self, "Success", message)
        else: QMessageBox.critical(self, "Failed", message)

    async def fetch_basic_stats(self):
        device_info = self._get_selected_device_info()
        if not device_info: return
        stats = await self.monitor.get_basic_stats(device_info)
        if stats.get("status") == "Success":
            self.sys_name_label.setText(stats.get("sysName", "N/A"))
            self.sys_descr_label.setText(stats.get("sysDescr", "N/A"))
            self.sys_uptime_label.setText(str(stats.get("sysUpTime", "N/A")))
            self.cpu_load_label.setText(stats.get("cpu_load", "N/A"))
            await self.fetch_interfaces(device_info)
        else:
            QMessageBox.critical(self, "Failed", stats.get("error", "Could not fetch stats."))

    async def fetch_interfaces(self, device_info):
        self.iface_combo.clear()
        success, interfaces = await self.monitor.get_interfaces(device_info)
        if success and interfaces:
            try:
                import natsort
                sorted_interfaces = natsort.natsorted(interfaces, key=lambda i: i['description'])
            except ImportError:
                sorted_interfaces = sorted(interfaces, key=lambda i: i['description'])
            
            for iface in sorted_interfaces:
                self.iface_combo.addItem(iface['description'], userData=iface['index'])
        else:
            self.iface_combo.addItem("Could not fetch interfaces")
            
    def start_monitoring(self):
        if self.iface_combo.count() == 0 or self.iface_combo.currentData() is None:
            QMessageBox.warning(self, "Warning", "Please fetch stats and select a valid interface first.")
            return
        self.set_monitoring_state(True); self.last_stats = {}; self.last_timestamp = 0
        self.poll_timer.start(3000)
        self.update_interface_stats()

    def stop_monitoring(self):
        self.poll_timer.stop()
        self.set_monitoring_state(False)

    def set_monitoring_state(self, is_monitoring: bool):
        self.start_monitor_btn.setEnabled(not is_monitoring)
        self.stop_monitor_btn.setEnabled(is_monitoring)
        self.device_combo.setEnabled(not is_monitoring)
        self.fetch_stats_btn.setEnabled(not is_monitoring)
        self.test_snmp_btn.setEnabled(not is_monitoring)
        self.iface_combo.setEnabled(not is_monitoring)

    def update_interface_stats(self):
        device_info = self._get_selected_device_info()
        iface_index = self.iface_combo.currentData()
        if not device_info or not iface_index:
            self.stop_monitoring()
            return
        self.task_manager.create_task(self.get_and_display_iface_stats(device_info, iface_index))

    async def get_and_display_iface_stats(self, device_info, iface_index):
        success, current_stats = await self.monitor.get_interface_stats(device_info, iface_index)
        
        if not success:
            self.iface_table.setItem(0, 0, QTableWidgetItem("Error"))
            return

        current_timestamp = time.time()
        self.iface_table.setItem(0, 0, QTableWidgetItem(current_stats.get("status", "N/A")))

        if self.last_stats and self.last_timestamp > 0:
            delta_time = current_timestamp - self.last_timestamp
            if delta_time > 0:
                in_oct_diff = current_stats['in_octets'] - self.last_stats['in_octets']
                if in_oct_diff < 0: in_oct_diff += 2**32
                
                out_oct_diff = current_stats['out_octets'] - self.last_stats['out_octets']
                if out_oct_diff < 0: out_oct_diff += 2**32

                in_pkt_diff = current_stats['in_pkts'] - self.last_stats['in_pkts']
                if in_pkt_diff < 0: in_pkt_diff += 2**32

                out_pkt_diff = current_stats['out_pkts'] - self.last_stats['out_pkts']
                if out_pkt_diff < 0: out_pkt_diff += 2**32

                in_bps = (in_oct_diff * 8) / delta_time
                out_bps = (out_oct_diff * 8) / delta_time
                in_pps = in_pkt_diff / delta_time
                out_pps = out_pkt_diff / delta_time
                
                self.iface_table.setItem(0, 1, QTableWidgetItem(f"{in_bps:,.2f}"))
                self.iface_table.setItem(0, 2, QTableWidgetItem(f"{out_bps:,.2f}"))
                self.iface_table.setItem(0, 3, QTableWidgetItem(f"{in_pps:,.2f}"))
                self.iface_table.setItem(0, 4, QTableWidgetItem(f"{out_pps:,.2f}"))

        self.last_stats = current_stats
        self.last_timestamp = current_timestamp
