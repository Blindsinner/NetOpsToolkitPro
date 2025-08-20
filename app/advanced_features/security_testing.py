# -*- coding: utf-8 -*-
import json
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QWidget, QFormLayout, QLineEdit,
    QPushButton, QComboBox, QDoubleSpinBox, QPlainTextEdit, QMessageBox,
    QFileDialog, QListWidget
)
from PySide6.QtGui import QFont, QColor
from PySide6.QtCore import Qt
from app.core.task_manager import TaskManager
from app.core.security_tester import SecurityTester
from app.advanced_features.config_management import DEVICES_FILE
from app.core.app_logger import activity_logger

class SecurityTestingDialog(QDialog):
    def __init__(self, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        
        self.task_manager = task_manager
        self.tester = SecurityTester()
        self.devices = self._load_devices()
        self.setWindowTitle("Proactive Security Testing")
        self.setMinimumSize(700, 600)
        self.resize(700, 600)
        main_layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        self.tabs.addTab(self._create_port_knocking_tab(), "Port Knocking")
        self.tabs.addTab(self._create_password_auditor_tab(), "Password Auditor")

    def _load_devices(self):
        if not DEVICES_FILE.exists(): return []
        with open(DEVICES_FILE, 'r') as f: return json.load(f)

    def _create_port_knocking_tab(self):
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        form_layout = QFormLayout()
        self.knock_target_input = QLineEdit("127.0.0.1")
        self.knock_ports_input = QLineEdit("1001, 2002, 3003")
        self.knock_protocol_combo = QComboBox(); self.knock_protocol_combo.addItems(["TCP", "UDP"])
        self.knock_delay_spinbox = QDoubleSpinBox()
        self.knock_delay_spinbox.setRange(0.0, 10.0); self.knock_delay_spinbox.setValue(0.5)
        self.knock_delay_spinbox.setSingleStep(0.1); self.knock_delay_spinbox.setSuffix(" s")
        form_layout.addRow("Target IP:", self.knock_target_input)
        form_layout.addRow("Port Sequence (comma-separated):", self.knock_ports_input)
        form_layout.addRow("Protocol:", self.knock_protocol_combo)
        form_layout.addRow("Delay between knocks:", self.knock_delay_spinbox)
        main_layout.addLayout(form_layout)
        self.knock_button = QPushButton("Execute Knock Sequence")
        main_layout.addWidget(self.knock_button)
        self.knock_log_output = QPlainTextEdit()
        self.knock_log_output.setReadOnly(True); self.knock_log_output.setFont(QFont("Consolas", 10))
        main_layout.addWidget(self.knock_log_output)
        self.knock_button.clicked.connect(self.run_port_knock)
        return widget

    def run_port_knock(self):
        target_ip = self.knock_target_input.text().strip()
        ports_str = self.knock_ports_input.text().strip()
        protocol = self.knock_protocol_combo.currentText()
        delay = self.knock_delay_spinbox.value()
        if not target_ip or not ports_str:
            QMessageBox.warning(self, "Input Error", "Target IP and Port Sequence are required."); return
        try:
            ports = [int(p.strip()) for p in ports_str.split(',')]
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Port sequence must be a comma-separated list of numbers."); return
        activity_logger.log("Port Knock Started", f"Target: {target_ip}, Ports: {ports_str}")
        self.knock_log_output.clear(); self.knock_button.setEnabled(False)
        self.task_manager.create_task(self._stream_knock_logs(target_ip, ports, protocol, delay))
        
    async def _stream_knock_logs(self, *args):
        try:
            async for log_message in self.tester.perform_port_knock(*args):
                self.knock_log_output.appendPlainText(log_message)
        finally:
            self.knock_button.setEnabled(True)

    def _create_password_auditor_tab(self):
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        form_layout = QFormLayout()
        self.audit_device_combo = QComboBox()
        self.audit_device_combo.addItems([d.get("host") for d in self.devices])
        self.audit_user_list = QPlainTextEdit("admin\nroot\ncisco")
        self.audit_pass_list = QPlainTextEdit("password\n1234\ncisco")
        self.audit_run_button = QPushButton("Run Audit")
        form_layout.addRow("Target Device:", self.audit_device_combo)
        form_layout.addRow("Usernames (one per line):", self.audit_user_list)
        form_layout.addRow("Passwords (one per line):", self.audit_pass_list)
        main_layout.addLayout(form_layout)
        main_layout.addWidget(self.audit_run_button)
        self.audit_log = QListWidget()
        main_layout.addWidget(self.audit_log)
        self.audit_run_button.clicked.connect(self.run_password_audit)
        
        if not self.devices:
            self.audit_device_combo.setEnabled(False)
            self.audit_run_button.setEnabled(False)

        return widget

    def run_password_audit(self):
        host = self.audit_device_combo.currentText()
        if not host: QMessageBox.warning(self, "Input Error", "Please select a target device."); return
        device_info = next((d for d in self.devices if d["host"] == host), None)
        if not device_info: QMessageBox.critical(self, "Error", f"Device {host} not found in inventory."); return
        usernames = self.audit_user_list.toPlainText().strip().split('\n')
        passwords = self.audit_pass_list.toPlainText().strip().split('\n')
        activity_logger.log("Password Audit Started", f"Target: {host}")
        self.audit_log.clear(); self.audit_run_button.setEnabled(False)
        self.task_manager.create_task(self._run_audit_combinations(device_info, usernames, passwords))

    async def _run_audit_combinations(self, device_info, usernames, passwords):
        for user in usernames:
            if not user: continue
            for password in passwords:
                if not password: continue
                result, success = await self.tester.audit_password(device_info, user.strip(), password.strip())
                item = QListWidgetItem(result)
                if success: item.setForeground(QColor("lime"))
                elif "ERROR" in result: item.setForeground(QColor("red"))
                self.audit_log.addItem(item)
                if success: break 
        self.audit_run_button.setEnabled(True)