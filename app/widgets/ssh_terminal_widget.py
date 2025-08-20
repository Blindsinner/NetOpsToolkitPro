# -*- coding: utf-8 -*-
import re
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QPushButton, QPlainTextEdit, QFormLayout, QSpinBox
)
from PySide6.QtGui import QFont, QTextCursor, QColor, QTextCharFormat
from PySide6.QtCore import Qt
from app.widgets.base_widget import BaseToolWidget
from app.core.ssh_client import SshClient
from app.core.app_logger import activity_logger

# --- FIX 1: The class name is now 'SSHTerminalWidget' to fix the ImportError ---
class SSHTerminalWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.client = SshClient()
        self.is_connected = False
        
        main_layout = QVBoxLayout(self)
        
        # --- Connection Bar ---
        conn_layout = QFormLayout()
        self.host_input = QLineEdit()
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535); self.port_input.setValue(22)
        self.user_input = QLineEdit()
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.connect_btn = QPushButton("Connect")
        
        row1 = QHBoxLayout()
        row1.addWidget(self.host_input); row1.addWidget(self.port_input)
        row2 = QHBoxLayout()
        row2.addWidget(self.user_input); row2.addWidget(self.pass_input)
        conn_layout.addRow("Host:Port:", row1)
        conn_layout.addRow("User:Pass:", row2)
        main_layout.addLayout(conn_layout)
        main_layout.addWidget(self.connect_btn)

        # --- Terminal Display ---
        self.terminal_output = QPlainTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFont(QFont("Consolas", 11))
        self.terminal_output.setStyleSheet("background-color: black; color: #CCCCCC;") # Default color
        main_layout.addWidget(self.terminal_output, stretch=1)

        # --- Command Input ---
        self.command_input = QLineEdit()
        self.command_input.setFont(QFont("Consolas", 11))
        self.command_input.setEnabled(False)
        main_layout.addWidget(self.command_input)
        
        # --- Connections ---
        self.client.received.connect(self.on_received)
        self.client.connection_made.connect(self.on_connection_made)
        self.client.connection_lost.connect(self.on_connection_lost)
        self.connect_btn.clicked.connect(self.toggle_connection)
        self.command_input.returnPressed.connect(self.send_command)

        self.load_state()

        # --- ANSI Color Mapping ---
        self.ansi_colors = {
            '30': QColor("black"), '31': QColor("red"), '32': QColor("green"), '33': QColor("yellow"),
            '34': QColor("blue"), '35': QColor("magenta"), '36': QColor("cyan"), '37': QColor("white"),
            '90': QColor("gray"), '91': QColor("#ff8888"), '92': QColor("#88ff88"), '93': QColor("#ffff88"),
            '94': QColor("#8888ff"), '95': QColor("#ff88ff"), '96': QColor("#88ffff"), '97': QColor("#ffffff")
        }
        self.default_format = self.terminal_output.currentCharFormat()

    def on_received(self, data):
        """FIX 2: Correctly processes terminal output to fix crashes and character issues."""
        cursor = self.terminal_output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        # Regex to find color codes, plain text, and backspaces separately
        ansi_pattern = re.compile(r'(\x1b\[[0-?]*[ -/]*[@-~])|([^\x08\x1b]+)|(\x08)')
        
        for match in ansi_pattern.finditer(data):
            # This correctly unpacks the groups from the match object
            sequence, text, backspace = match.groups()

            if text:
                cursor.insertText(text)
            elif backspace:
                cursor.deletePreviousChar()
            elif sequence:
                if sequence.endswith('m'):
                    code = sequence.strip('\x1b[').strip('m')
                    self.process_ansi_code(cursor, code)
                # Ignore other control sequences

        self.terminal_output.verticalScrollBar().setValue(self.terminal_output.verticalScrollBar().maximum())

    def process_ansi_code(self, cursor, code):
        """Applies formatting to the cursor based on the ANSI code."""
        parts = code.split(';')
        
        if not parts or parts == [''] or parts[0] in ('0', ''):
            self.default_format.setForeground(QColor("#CCCCCC"))
            cursor.setCharFormat(self.default_format)
            return
            
        current_format = cursor.charFormat()
        for part in parts:
            if not part: continue
            if part in self.ansi_colors:
                current_format.setForeground(self.ansi_colors[part])
            elif part == '1': # Bold
                current_format.setFontWeight(QFont.Weight.Bold)
            elif part == '22':
                current_format.setFontWeight(QFont.Weight.Normal)
        
        cursor.setCharFormat(current_format)

    def toggle_connection(self):
        if self.is_connected:
            self.client.disconnect()
            self.on_connection_lost("Disconnected by user.")
        else:
            host = self.host_input.text()
            port = self.port_input.value()
            user = self.user_input.text()
            password = self.pass_input.text()
            if not all([host, user, password]):
                self.show_error("Host, User, and Password are required.")
                return
            
            activity_logger.log("SSH Connection Attempt", f"Host: {host}, User: {user}")
            self.set_connection_state(is_connecting=True)
            self.terminal_output.clear()
            self.on_received(f"Connecting to {host}...")
            self.task_manager.create_task(self.client.connect(host, port, user, password))
            
    def on_connection_made(self):
        self.set_connection_state(is_connected=True)

    def on_connection_lost(self, reason):
        if self.is_connected:
            self.on_received(f"\n--- CONNECTION CLOSED ---\nReason: {reason}")
        self.set_connection_state(is_connected=False)

    def send_command(self):
        command = self.command_input.text() + '\n'
        self.task_manager.create_task(self.client.send(command))
        self.command_input.clear()
        
    def set_connection_state(self, is_connected=False, is_connecting=False):
        self.is_connected = is_connected
        self.connect_btn.setText("Disconnect" if is_connected else "Connect")
        self.command_input.setEnabled(is_connected)
        
        if is_connecting:
            self.connect_btn.setText("Connecting...")
            self.connect_btn.setEnabled(False)
        else:
            self.connect_btn.setEnabled(True)

    def load_state(self):
        self.host_input.setText(self.settings.value("ssh/host", ""))
        self.user_input.setText(self.settings.value("ssh/user", ""))

    def save_state(self):
        self.settings.setValue("ssh/host", self.host_input.text())
        self.settings.setValue("ssh/user", self.user_input.text())
    
    def closeEvent(self, event):
        self.client.disconnect()
        super().closeEvent(event)