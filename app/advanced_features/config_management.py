# app/advanced_features/config_management.py
# REFACTORED: The main container is now a QWidget, sub-dialogs remain QDialogs.

import json
import os
import difflib
import yaml
from datetime import datetime
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton, # QDialog changed to QWidget
    QHBoxLayout, QHeaderView, QMessageBox, QDialogButtonBox, QFormLayout,
    QLineEdit, QComboBox, QSpinBox, QProgressDialog, QListWidget, QTextBrowser,
    QSplitter, QPlainTextEdit, QTreeWidget, QTreeWidgetItem, QLabel, QDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from app.config import AppConfig
from app.core.task_manager import TaskManager
from app.core.device_connector import DeviceConnector
from app.core.credentials_manager import CredentialsManager
from app.core.compliance_engine import ComplianceEngine
from app.widgets.base_widget import BaseToolWidget

CONFIG_DIR = AppConfig.PROJECT_ROOT / "device_configs"
DEVICES_FILE = CONFIG_DIR / "devices.json"
BACKUP_DIR = CONFIG_DIR / "backups"

class ComplianceDialog(QDialog):
    def __init__(self, devices, parent=None):
        super().__init__(parent)
        self.devices = devices
        self.engine = ComplianceEngine(self.devices, BACKUP_DIR)

        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.setWindowTitle("Configuration Compliance Audit")
        self.setMinimumSize(1000, 700)
        self.resize(1100, 800)

        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_pane = QWidget()
        left_layout = QVBoxLayout(left_pane)
        left_layout.addWidget(QLabel("Compliance Rules (YAML):"))
        self.rules_editor = QPlainTextEdit()
        self.rules_editor.setFont(QFont("Consolas", 11))
        self.rules_editor.setPlainText(self.get_sample_rules())
        run_audit_btn = QPushButton("Run Audit")
        left_layout.addWidget(self.rules_editor)
        left_layout.addWidget(run_audit_btn)
        
        right_pane = QWidget()
        right_layout = QVBoxLayout(right_pane)
        right_layout.addWidget(QLabel("Audit Results:"))
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Device / Rule", "Status", "Details"])
        self.results_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.results_tree.header().setStretchLastSection(True)
        right_layout.addWidget(self.results_tree)
        
        splitter.addWidget(left_pane)
        splitter.addWidget(right_pane)
        splitter.setSizes([400, 700])
        main_layout.addWidget(splitter)
        
        run_audit_btn.clicked.connect(self.run_audit)

    def get_sample_rules(self):
        return """- rule_name: "NTP Servers Correct"
  description: "Ensures the correct NTP servers are configured."
  must_contain:
    - "ntp server 1.1.1.1"
    - "ntp server 8.8.8.8"

- rule_name: "No HTTP Server"
  description: "Ensures insecure HTTP server is disabled."
  must_not_contain:
    - "ip http server"

- rule_name: "Required Logging Config"
  description: "Checks for standard logging setup."
  must_contain:
    - "logging trap informational"
    - "logging host 10.0.0.1"
"""

    def run_audit(self):
        self.results_tree.clear()
        rules_yaml = self.rules_editor.toPlainText()
        results = self.engine.run_audit(rules_yaml)
        
        device_results = {}
        for res in results:
            if res["device"] not in device_results:
                device_results[res["device"]] = []
            device_results[res["device"]].append(res)
            
        for device, items in device_results.items():
            device_is_compliant = all(item["compliant"] for item in items)
            device_item = QTreeWidgetItem(self.results_tree, [device])
            device_item.setForeground(1, QColor("green") if device_is_compliant else QColor("red"))
            device_item.setText(1, "Compliant" if device_is_compliant else "NON-COMPLIANT")
            
            for item in items:
                rule_item = QTreeWidgetItem(device_item, [item["rule"]])
                rule_item.setText(1, "Pass" if item["compliant"] else "FAIL")
                rule_item.setForeground(1, QColor("green") if item["compliant"] else QColor("red"))
                rule_item.setText(2, item["reason"])
        
        self.results_tree.expandAll()

class DiffDialog(QDialog):
    def __init__(self, text1, text2, from_file, to_file, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.setWindowTitle("Configuration Difference")
        self.setMinimumSize(900, 600)
        self.resize(1000, 700)
        layout = QVBoxLayout(self)
        self.text_browser = QTextBrowser()
        layout.addWidget(self.text_browser)
        differ = difflib.HtmlDiff(tabsize=4, wrapcolumn=70)
        html = differ.make_file(text1.splitlines(), text2.splitlines(), fromdesc=from_file, todesc=to_file)
        self.text_browser.setHtml(html)

class BackupViewerDialog(QDialog):
    def __init__(self, device_host, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.setWindowTitle(f"Backups for {device_host}")
        self.setMinimumSize(400, 500)
        self.resize(400, 500)
        layout = QVBoxLayout(self)
        self.backup_list = QListWidget()
        layout.addWidget(self.backup_list)
        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Open | QDialogButtonBox.StandardButton.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)
        self.populate_backups(device_host)

    def populate_backups(self, host):
        device_backup_dir = BACKUP_DIR / host
        if not device_backup_dir.is_dir(): return
        files = sorted(device_backup_dir.iterdir(), key=os.path.getmtime, reverse=True)
        for file_path in files:
            self.backup_list.addItem(file_path.name)
            
    def get_selected_backup_name(self):
        item = self.backup_list.currentItem()
        return item.text() if item else None

class DeviceDialog(QDialog):
    def __init__(self, cred_manager: CredentialsManager, task_manager: TaskManager, device_data=None, parent=None):
        super().__init__(parent)
        self.cred_manager = cred_manager
        self.task_manager = task_manager # Store the task manager
        self.setWindowTitle("Add/Edit Device")
        self.connector = DeviceConnector()
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        self.host_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        self.device_type_combo = QComboBox()
        self.device_type_combo.addItems(self.connector.DEVICE_TYPES.keys())
        form_layout.addRow("Hostname / IP:", self.host_input)
        form_layout.addRow("Device Type:", self.device_type_combo)
        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Password:", self.password_input)
        form_layout.addRow("SSH Port:", self.port_input)
        layout.addLayout(form_layout)
        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        test_button = self.button_box.addButton("Test Connection", QDialogButtonBox.ButtonRole.ActionRole)
        test_button.clicked.connect(self.test_connection)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

        if device_data:
            self.host_input.setText(device_data.get("host", ""))
            self.username_input.setText(device_data.get("username", ""))
            encrypted_pass = device_data.get("password", "")
            if encrypted_pass:
                try:
                    self.password_input.setText(self.cred_manager.decrypt_password(encrypted_pass))
                except ValueError as e:
                    QMessageBox.warning(self, "Decryption Failed", f"Could not decrypt password. You may need to re-enter it.\nError: {e}")
            self.port_input.setValue(device_data.get("port", 22))
            self.device_type_combo.setCurrentText(device_data.get("friendly_name", ""))

    def get_data(self):
        friendly_name = self.device_type_combo.currentText()
        plain_text_pass = self.password_input.text()
        encrypted_pass = self.cred_manager.encrypt_password(plain_text_pass)
        return {
            "host": self.host_input.text().strip(), "username": self.username_input.text().strip(),
            "password": encrypted_pass, "port": self.port_input.value(),
            "friendly_name": friendly_name, "device_type": self.connector.DEVICE_TYPES[friendly_name]
        }
        
    def test_connection(self):
        device_data = self.get_data()
        device_data['password'] = self.password_input.text()
        if not all([device_data["host"], device_data["username"], device_data["password"]]):
            QMessageBox.warning(self, "Input Incomplete", "Please fill in Host, Username, and Password to test.")
            return
        progress = QProgressDialog("Testing connection...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.show()
        async def do_test():
            success, message = await self.connector.test_connection(device_data)
            progress.close()
            if success: QMessageBox.information(self, "Connection Success", message)
            else: QMessageBox.critical(self, "Connection Failed", message)
        self.task_manager.create_task(do_test())

class ConfigManagerWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        
        self.connector = DeviceConnector()
        self.cred_manager = CredentialsManager()
        CONFIG_DIR.mkdir(exist_ok=True)
        BACKUP_DIR.mkdir(exist_ok=True)
        self.devices = self._load_devices()
        
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Host", "Device Type", "Last Backup Status", "Last Backup Time"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        top_btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add Device"); edit_btn = QPushButton("Edit Device"); remove_btn = QPushButton("Remove Device")
        top_btn_layout.addWidget(add_btn); top_btn_layout.addWidget(edit_btn); top_btn_layout.addWidget(remove_btn)
        top_btn_layout.addStretch()
        
        bottom_btn_layout = QHBoxLayout()
        audit_btn = QPushButton("Run Compliance Audit")
        view_backups_btn = QPushButton("View Backups"); check_changes_btn = QPushButton("Check for Changes"); backup_now_btn = QPushButton("Backup Selected")
        backup_now_btn.setStyleSheet("font-weight: bold;")
        bottom_btn_layout.addStretch()
        bottom_btn_layout.addWidget(audit_btn)
        bottom_btn_layout.addWidget(view_backups_btn)
        bottom_btn_layout.addWidget(check_changes_btn)
        bottom_btn_layout.addWidget(backup_now_btn)
        
        layout.addLayout(top_btn_layout); layout.addWidget(self.table); layout.addLayout(bottom_btn_layout)
        
        add_btn.clicked.connect(self.add_device); edit_btn.clicked.connect(self.edit_device); remove_btn.clicked.connect(self.remove_device)
        backup_now_btn.clicked.connect(self.backup_selected_device); view_backups_btn.clicked.connect(self.view_backups)
        check_changes_btn.clicked.connect(self.check_for_changes)
        audit_btn.clicked.connect(self.run_compliance_audit)
        
        self.populate_table()

    def run_compliance_audit(self):
        if not self.devices:
            self.show_error("Please add devices to the inventory before running an audit.")
            return
        dialog = ComplianceDialog(self.devices, self)
        dialog.exec()

    def _get_decrypted_device(self, device_info):
        decrypted_info = device_info.copy()
        try:
            encrypted_pass = device_info.get("password", "")
            if encrypted_pass:
                decrypted_info["password"] = self.cred_manager.decrypt_password(encrypted_pass)
            return decrypted_info
        except ValueError as e:
            self.show_error(f"Could not perform action.\nDecryption Error: {e}")
            self.cred_manager.session_key = None
            return None
            
    def _get_selected_device(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            self.show_error("Please select a device.")
            return None, -1
        row_index = selected_rows[0].row()
        return self.devices[row_index], row_index

    def _load_devices(self):
        try:
            if DEVICES_FILE.exists():
                with open(DEVICES_FILE, 'r') as f: return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self.show_error(f"Failed to load devices file: {e}")
        return []

    def _save_devices(self):
        try:
            with open(DEVICES_FILE, 'w') as f:
                json.dump(self.devices, f, indent=4)
        except IOError as e:
            self.show_error(f"Failed to save devices file: {e}")
            
    def populate_table(self):
        self.table.setRowCount(0); self.table.setRowCount(len(self.devices))
        for row, device in enumerate(self.devices):
            self.table.setItem(row, 0, QTableWidgetItem(device.get("host")))
            self.table.setItem(row, 1, QTableWidgetItem(device.get("friendly_name")))
            self.table.setItem(row, 2, QTableWidgetItem(device.get("last_backup_status", "N/A")))
            self.table.setItem(row, 3, QTableWidgetItem(device.get("last_backup_time", "N/A")))

    def add_device(self):
        if not self.cred_manager.get_master_password(self): return
        dialog = DeviceDialog(self.cred_manager, self.task_manager, parent=self)
        if dialog.exec():
            new_device_data = dialog.get_data()
            if any(d["host"] == new_device_data["host"] for d in self.devices):
                self.show_error("A device with this host already exists.")
                return
            self.devices.append(new_device_data)
            self._save_devices(); self.populate_table()

    def edit_device(self):
        device_data, row_index = self._get_selected_device()
        if not device_data: return
        if not self.cred_manager.get_master_password(self): return
        dialog = DeviceDialog(self.cred_manager, self.task_manager, device_data, self)
        if dialog.exec():
            self.devices[row_index] = dialog.get_data()
            self._save_devices(); self.populate_table()
            
    def remove_device(self):
        device_data, row_index = self._get_selected_device()
        if not device_data: return
        reply = QMessageBox.question(self, "Confirm Deletion", f"Are you sure you want to remove {device_data['host']}?")
        if reply == QMessageBox.StandardButton.Yes:
            del self.devices[row_index]
            self._save_devices(); self.populate_table()

    def _run_device_action(self, action_coro):
        device_info, row_index = self._get_selected_device()
        if not device_info: return
        if not self.cred_manager.get_master_password(self): return
        decrypted_device_info = self._get_decrypted_device(device_info)
        if not decrypted_device_info: return
        self.task_manager.create_task(action_coro(decrypted_device_info, row_index))

    def backup_selected_device(self):
        async def do_backup(device_info, row_index):
            progress = QProgressDialog(f"Backing up {device_info['host']}...", "Cancel", 0, 0, self)
            progress.setWindowModality(Qt.WindowModality.WindowModal); progress.show()
            success, output = await self.connector.fetch_backup(device_info)
            progress.close()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S"); status = "Success" if success else "Failed"
            self.devices[row_index]["last_backup_status"] = status; self.devices[row_index]["last_backup_time"] = timestamp
            self._save_devices(); self.populate_table()
            if success:
                device_backup_dir = BACKUP_DIR / device_info["host"]; device_backup_dir.mkdir(exist_ok=True)
                filename = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
                backup_path = device_backup_dir / filename
                with open(backup_path, 'w', encoding='utf-8') as f: f.write(output)
                self.show_info(f"Configuration for {device_info['host']} saved to:\n{backup_path}")
            else:
                self.show_error(f"Could not back up {device_info['host']}.\n\nError: {output}")
        self._run_device_action(do_backup)
        
    def view_backups(self):
        device_info, _ = self._get_selected_device()
        if not device_info: return
        dialog = BackupViewerDialog(device_info['host'], self)
        if dialog.exec():
            filename = dialog.get_selected_backup_name()
            if filename:
                filepath = BACKUP_DIR / device_info['host'] / filename
                with open(filepath, 'r') as f: content = f.read()
                viewer = QDialog(self); viewer.setWindowTitle(filename); layout = QVBoxLayout(viewer)
                text_edit = QTextBrowser(); text_edit.setHtml(f"<pre>{content}</pre>"); layout.addWidget(text_edit); viewer.exec()

    def check_for_changes(self):
        async def do_diff(device_info, row_index):
            device_backup_dir = BACKUP_DIR / device_info["host"]
            if not device_backup_dir.is_dir() or not any(device_backup_dir.iterdir()):
                self.show_info("No backups exist for this device. Please create one first.")
                return
            latest_backup_path = sorted(device_backup_dir.iterdir(), key=os.path.getmtime, reverse=True)[0]
            progress = QProgressDialog(f"Fetching live config for {device_info['host']}...", "Cancel", 0, 0, self)
            progress.setWindowModality(Qt.WindowModality.WindowModal); progress.show()
            success, live_config = await self.connector.fetch_backup(device_info)
            progress.close()
            if not success:
                self.show_error(f"Could not fetch live config: {live_config}")
                return
            with open(latest_backup_path, 'r') as f: backup_config = f.read()
            if backup_config == live_config:
                self.show_info("Live configuration matches the latest backup.")
            else:
                diff_dialog = DiffDialog(backup_config, live_config, f"Backup ({latest_backup_path.name})", "Live Config", self)
                diff_dialog.exec()
        self._run_device_action(do_diff)
