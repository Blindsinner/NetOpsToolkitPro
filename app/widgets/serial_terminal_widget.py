# -*- coding: utf-8 -*-
import serial.tools.list_ports
import re
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QComboBox,
    QPushButton, QPlainTextEdit, QGridLayout, QLineEdit
)
from PySide6.QtGui import QFont, QTextCursor, QColor, QTextCharFormat
from PySide6.QtCore import QTimer
from app.widgets.base_widget import BaseToolWidget
from app.core.serial_client import SerialClient

class SerialTerminalWidget(BaseToolWidget):
    def __init__(self, settings, task_manager=None):
        super().__init__(settings, None)
        self.client = SerialClient()
        self.is_connected = False

        main_layout = QVBoxLayout(self)
        
        # --- Connection Bar ---
        conn_layout = QGridLayout()
        self.port_combo = QComboBox()
        self.baud_combo = QComboBox()
        self.baud_combo.addItems(['9600', '19200', '38400', '57600', '115200'])
        self.connect_btn = QPushButton("Connect")
        self.refresh_btn = QPushButton("Refresh Ports")
        conn_layout.addWidget(self.port_combo, 0, 0, 1, 2)
        conn_layout.addWidget(self.baud_combo, 1, 0)
        conn_layout.addWidget(self.refresh_btn, 1, 1)
        main_layout.addLayout(conn_layout)
        main_layout.addWidget(self.connect_btn)

        # --- Terminal Display ---
        self.terminal_output = QPlainTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFont(QFont("Consolas", 11))
        self.terminal_output.setStyleSheet("background-color: black; color: #CCCCCC;")
        main_layout.addWidget(self.terminal_output, stretch=1)

        # --- Command Input ---
        self.command_input = QLineEdit()
        self.command_input.setFont(QFont("Consolas", 11))
        self.command_input.setEnabled(False)
        main_layout.addWidget(self.command_input)

        # --- Connections ---
        self.client.received.connect(self.on_received)
        self.client.connection_lost.connect(self.on_connection_lost)
        self.connect_btn.clicked.connect(self.toggle_connection)
        self.refresh_btn.clicked.connect(self.refresh_ports)
        self.command_input.returnPressed.connect(self.send_command)

        self.refresh_ports()
        
        self.ansi_colors = {
            '30': QColor("black"), '31': QColor("red"), '32': QColor("green"), '33': QColor("yellow"),
            '34': QColor("blue"), '35': QColor("magenta"), '36': QColor("cyan"), '37': QColor("white"),
            '90': QColor("gray"), '91': QColor("#ff8888"), '92': QColor("#88ff88"), '93': QColor("#ffff88"),
            '94': QColor("#8888ff"), '95': QColor("#ff88ff"), '96': QColor("#88ffff"), '97': QColor("#ffffff")
        }
        self.default_format = self.terminal_output.currentCharFormat()
        self.default_format.setForeground(QColor("#CCCCCC"))

    def refresh_ports(self):
        self.port_combo.clear()
        ports = sorted([port.device for port in serial.tools.list_ports.comports()])
        self.port_combo.addItems(ports if ports else ["No ports found"])
        
    def on_received(self, data):
        """FINAL FIX: Corrected the regex to avoid the unpack error."""
        cursor = self.terminal_output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        # --- FINAL FIX: The inner group in the OSC sequence is now non-capturing (?:...) ---
        control_chars_pattern = re.compile(r'(\x1b\[[0-?]*[ -/]*[@-~])|(\x1b\].*?(?:\x07|\x1b\\))|(\x1b[= >])|([\x00-\x08\x0b-\x1f\x7f])|(.)')
        
        clean_data = data.replace('\r\n', '\n').replace('\r', '\n')

        for match in control_chars_pattern.finditer(clean_data):
            sgr_sequence, osc_sequence, other_escape, other_control, plain_char = match.groups()

            if sgr_sequence:
                if sgr_sequence.endswith('m'):
                    code = sgr_sequence.strip('\x1b[').strip('m')
                    self.process_ansi_code(cursor, code)
            
            elif plain_char:
                if plain_char == '\b':
                    cursor.deletePreviousChar()
                else:
                    cursor.insertText(plain_char)

        self.terminal_output.verticalScrollBar().setValue(self.terminal_output.verticalScrollBar().maximum())

    def process_ansi_code(self, cursor, code):
        parts = code.split(';')
        
        if not code or parts == [''] or parts[0] == '0':
            cursor.setCharFormat(self.default_format)
            return

        current_format = cursor.charFormat()
        for part in parts:
            if not part: part = '0'
            if part in self.ansi_colors:
                current_format.setForeground(self.ansi_colors[part])
            elif part == '1':
                current_format.setFontWeight(QFont.Weight.Bold)
            elif part == '22':
                current_format.setFontWeight(QFont.Weight.Normal)

        cursor.setCharFormat(current_format)

    def toggle_connection(self):
        if self.is_connected:
            self.client.disconnect()
        else:
            port = self.port_combo.currentText()
            baud = int(self.baud_combo.currentText())
            if "No ports found" in port:
                self.show_error("No serial port selected.")
                return
            
            self.terminal_output.clear()
            self.on_received(f"Connecting to {port} at {baud} baud...")
            self.client.connect(port, baud)
            if self.client.is_running():
                self.is_connected = True
                self.set_connection_state(True)
            else:
                self.on_received("\n--- CONNECTION FAILED ---")

    def on_connection_lost(self):
        self.is_connected = False
        self.set_connection_state(False)
        self.on_received("\n--- CONNECTION CLOSED ---")

    def send_command(self):
        command = self.command_input.text() + '\r\n'
        self.client.send(command)
        self.command_input.clear()

    def set_connection_state(self, is_connected):
        self.is_connected = is_connected
        self.command_input.setEnabled(is_connected)
        self.connect_btn.setText("Disconnect" if is_connected else "Connect")
        self.port_combo.setEnabled(not is_connected)
        self.baud_combo.setEnabled(not is_connected)
        self.refresh_btn.setEnabled(not is_connected)

    def closeEvent(self, event):
        self.client.disconnect()
        super().closeEvent(event)