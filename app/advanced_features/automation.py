# -*- coding: utf-8 -*-
import json
import yaml
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QSplitter, QGroupBox, QListWidget,
    QPlainTextEdit, QPushButton, QFileDialog, QMessageBox, QListWidgetItem,
    QWidget
)
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QFont

from app.advanced_features.config_management import DEVICES_FILE
from app.core.task_manager import TaskManager
from app.core.device_connector import DeviceConnector
# --- FIX: Import the CredentialsManager ---
from app.core.credentials_manager import CredentialsManager

class AutomationLogger(QObject):
    log_signal = Signal(str)
    def log(self, message):
        self.log_signal.emit(message)

class AutomationDialog(QDialog):
    def __init__(self, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        # --- FIX: Added flags for minimize, maximize, and close buttons ---
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        
        self.task_manager = task_manager
        self.devices = self._load_devices()
        self.connector = DeviceConnector()
        self.logger = AutomationLogger()
        # --- FIX: Initialize the CredentialsManager ---
        self.cred_manager = CredentialsManager()

        self.setWindowTitle("Network Automation Engine")
        self.setMinimumSize(1000, 700)
        self.resize(1000, 700)

        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        left_pane = QWidget()
        left_layout = QVBoxLayout(left_pane)
        
        device_group = QGroupBox("Target Devices (from Config Manager)")
        device_layout = QVBoxLayout(device_group)
        self.device_list = QListWidget()
        self.device_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        for device in self.devices:
            self.device_list.addItem(device["host"])
        device_layout.addWidget(self.device_list)
        left_layout.addWidget(device_group)

        action_group = QGroupBox("Actions")
        action_layout = QVBoxLayout(action_group)
        self.load_playbook_btn = QPushButton("Load Playbook")
        self.save_playbook_btn = QPushButton("Save Playbook")
        self.run_playbook_btn = QPushButton("Run Playbook")
        self.run_playbook_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        action_layout.addWidget(self.load_playbook_btn)
        action_layout.addWidget(self.save_playbook_btn)
        action_layout.addWidget(self.run_playbook_btn)
        left_layout.addWidget(action_group)

        right_pane = QWidget()
        right_layout = QVBoxLayout(right_pane)
        
        editor_group = QGroupBox("Playbook Editor (YAML)")
        editor_layout = QVBoxLayout(editor_group)
        self.playbook_editor = QPlainTextEdit()
        self.playbook_editor.setFont(QFont("Consolas", 11))
        self.playbook_editor.setPlaceholderText("Enter or load a playbook...")
        self.playbook_editor.setPlainText(self.get_sample_playbook())
        editor_layout.addWidget(self.playbook_editor)
        right_layout.addWidget(editor_group, stretch=2)

        output_group = QGroupBox("Execution Log")
        output_layout = QVBoxLayout(output_group)
        self.output_log = QPlainTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.output_log)
        right_layout.addWidget(output_group, stretch=1)
        
        splitter.addWidget(left_pane)
        splitter.addWidget(right_pane)
        splitter.setSizes([300, 700])
        main_layout.addWidget(splitter)
        
        self.logger.log_signal.connect(self.append_log)
        self.load_playbook_btn.clicked.connect(self.load_playbook)
        self.save_playbook_btn.clicked.connect(self.save_playbook)
        self.run_playbook_btn.clicked.connect(self.run_playbook)

        if not self.devices:
            QMessageBox.information(self, "No Devices", "No devices found in inventory. Please add devices in 'Config Management' first.")
            self.device_list.setEnabled(False)
            self.run_playbook_btn.setEnabled(False)

    def _load_devices(self):
        if not DEVICES_FILE.exists(): return []
        with open(DEVICES_FILE, 'r') as f: return json.load(f)

    def append_log(self, message):
        self.output_log.appendPlainText(message)
        self.output_log.verticalScrollBar().setValue(self.output_log.verticalScrollBar().maximum())
    
    def get_sample_playbook(self):
        return """- name: "Show version on selected devices"
  hosts: [] # Populated from the list on the left
  tasks:
    - name: "Get IOS Version"
      command: "show version | include IOS"

- name: "Configure a test interface"
  hosts: []
  tasks:
    - name: "Configure Loopback99"
      config:
        - "interface Loopback99"
        - "description Automated by NetOpsToolkitPro"
"""

    def load_playbook(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Playbook", "", "YAML Files (*.yml *.yaml)")
        if path:
            with open(path, 'r', encoding='utf-8') as f:
                self.playbook_editor.setPlainText(f.read())
            self.logger.log(f"INFO: Loaded playbook from {path}")

    def save_playbook(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Playbook", "", "YAML Files (*.yml *.yaml)")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.playbook_editor.toPlainText())
            self.logger.log(f"INFO: Saved playbook to {path}")

    def run_playbook(self):
        playbook_text = self.playbook_editor.toPlainText()
        selected_hosts = [item.text() for item in self.device_list.selectedItems()]
        
        if not selected_hosts:
            QMessageBox.warning(self, "No Targets", "Please select at least one target device.")
            return

        reply = QMessageBox.question(self, "Confirm Execution", 
            f"You are about to run an automation playbook against:\n\n{', '.join(selected_hosts)}\n\n"
            "This can make PERMANENT changes to device configurations. Are you sure you want to proceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.No: return

        self.output_log.clear()
        self.run_playbook_btn.setEnabled(False)
        self.task_manager.create_task(self.execute_playbook(playbook_text, selected_hosts))

    async def execute_playbook(self, playbook_text, selected_hosts):
        try:
            playbook = yaml.safe_load(playbook_text)
            if not isinstance(playbook, list):
                raise ValueError("Playbook must be a YAML list of plays.")
        except (yaml.YAMLError, ValueError) as e:
            self.logger.log(f"ERROR: Invalid playbook format. {e}")
            self.run_playbook_btn.setEnabled(True)
            return

        # --- FIX: Get master password before starting the execution ---
        if not self.cred_manager.get_master_password(self):
            self.logger.log("ERROR: Master password not provided. Aborting playbook.")
            self.run_playbook_btn.setEnabled(True)
            return

        for play in playbook:
            play['hosts'] = selected_hosts
        
        self.logger.log(f"--- Starting playbook execution on {', '.join(selected_hosts)} ---")
        
        for play in playbook:
            play_name = play.get('name', 'Unnamed Play')
            self.logger.log(f"\n>> PLAY: {play_name}")
            
            for host in play.get('hosts', []):
                device_info = next((d for d in self.devices if d["host"] == host), None)
                if not device_info:
                    self.logger.log(f"SKIPPING: Host {host} not found in device inventory.")
                    continue

                # --- FIX: Decrypt the password for the current device ---
                decrypted_device_info = device_info.copy()
                try:
                    encrypted_pass = device_info.get("password", "")
                    if encrypted_pass:
                        decrypted_device_info["password"] = self.cred_manager.decrypt_password(encrypted_pass)
                except Exception as e:
                    self.logger.log(f"ERROR: Could not decrypt password for {host}, skipping. Error: {e}")
                    continue
                
                self.logger.log(f"  >> HOST: {host}")
                for task in play.get('tasks', []):
                    task_name = task.get('name', 'Unnamed Task')
                    self.logger.log(f"    >> TASK: {task_name}")
                    
                    if 'command' in task:
                        # --- FIX: Use decrypted credentials ---
                        success, output = await self.connector.run_command(decrypted_device_info, task['command'])
                        self.logger.log(f"      STATUS: {'OK' if success else 'FAILED'}")
                        self.logger.log(f"      OUTPUT:\n{output}\n")

                    elif 'config' in task:
                        commands = task['config']
                         # --- FIX: Use decrypted credentials ---
                        success, output = await self.connector.send_config(decrypted_device_info, commands)
                        self.logger.log(f"      STATUS: {'OK' if success else 'FAILED'}")
                        self.logger.log(f"      OUTPUT:\n{output}\n")
        
        self.logger.log("--- Playbook execution finished ---")
        self.run_playbook_btn.setEnabled(True)