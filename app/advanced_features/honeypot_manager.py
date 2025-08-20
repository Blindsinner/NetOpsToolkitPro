# -*- coding: utf-8 -*-
import datetime
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox, QFormLayout,
    QSpinBox, QLabel, QComboBox, QMessageBox, QApplication
)
from PySide6.QtCore import Qt
from app.core.task_manager import TaskManager
from app.core.honeypot_engine import HoneypotEngine

class HoneypotManagerDialog(QDialog): # FIX: Inherit from QDialog
    def __init__(self, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        self.task_manager = task_manager
        self.engine = HoneypotEngine(task_manager)
        
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.setWindowTitle("Honeypot Manager")
        self.setMinimumSize(900, 700)
        self.resize(1000, 700)

        main_layout = QVBoxLayout(self)

        listener_group = QGroupBox("Deploy Honeypot")
        form = QFormLayout(listener_group)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535); self.port_input.setValue(21)
        self.persona_combo = QComboBox()
        self.persona_combo.addItems(self.engine.personas.keys())
        self.deploy_btn = QPushButton("Deploy Listener")
        
        form.addRow("Listen Port:", self.port_input)
        form.addRow("Service Persona:", self.persona_combo)
        form.addRow(self.deploy_btn)
        main_layout.addWidget(listener_group)

        active_group = QGroupBox("Active Listeners")
        active_layout = QVBoxLayout(active_group)
        self.listener_table = QTableWidget()
        self.listener_table.setColumnCount(3)
        self.listener_table.setHorizontalHeaderLabels(["Port", "Persona", "Status"])
        self.listener_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.stop_btn = QPushButton("Stop Selected Listener")
        active_layout.addWidget(self.listener_table)
        active_layout.addWidget(self.stop_btn)
        main_layout.addWidget(active_group)
        
        events_group = QGroupBox("Trapped Connections")
        events_layout = QVBoxLayout(events_group)
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(6)
        self.events_table.setHorizontalHeaderLabels(["Timestamp", "Source IP", "Source Port", "Dest Port", "Persona", "Data Sent"])
        self.events_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.events_table.horizontalHeader().setStretchLastSection(True)
        events_layout.addWidget(self.events_table)
        main_layout.addWidget(events_group)

        self.deploy_btn.clicked.connect(self.deploy_honeypot)
        self.stop_btn.clicked.connect(self.stop_honeypot)
        self.engine.connection_trapped.connect(self.log_event)
        self.engine.listener_status_changed.connect(self.update_listener_status)

    def deploy_honeypot(self):
        port = self.port_input.value()
        persona = self.persona_combo.currentText()
        
        for row in range(self.listener_table.rowCount()):
            if self.listener_table.item(row, 0).text() == str(port):
                QMessageBox.warning(self, "Duplicate", f"A listener is already configured for port {port}.")
                return

        row = self.listener_table.rowCount()
        self.listener_table.insertRow(row)
        self.listener_table.setItem(row, 0, QTableWidgetItem(str(port)))
        self.listener_table.setItem(row, 1, QTableWidgetItem(persona))
        self.listener_table.setItem(row, 2, QTableWidgetItem("Starting..."))
        
        self.engine.start_listener(port, persona)

    def stop_honeypot(self):
        selected_items = self.listener_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a listener to stop.")
            return
        
        port_to_stop = int(selected_items[0].text())
        self.engine.stop_listener(port_to_stop)
        
        for row in range(self.listener_table.rowCount()):
            if self.listener_table.item(row, 0).text() == str(port_to_stop):
                self.listener_table.removeRow(row)
                break
                
    def update_listener_status(self, port, status):
        for row in range(self.listener_table.rowCount()):
            if self.listener_table.item(row, 0).text() == str(port):
                self.listener_table.setItem(row, 2, QTableWidgetItem(status))
                break

    def log_event(self, event: dict):
        row = self.events_table.rowCount()
        self.events_table.insertRow(row)
        
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.events_table.setItem(row, 0, QTableWidgetItem(ts))
        self.events_table.setItem(row, 1, QTableWidgetItem(event["source_ip"]))
        self.events_table.setItem(row, 2, QTableWidgetItem(str(event["source_port"])))
        self.events_table.setItem(row, 3, QTableWidgetItem(str(event["dest_port"])))
        self.events_table.setItem(row, 4, QTableWidgetItem(event["persona"]))
        self.events_table.setItem(row, 5, QTableWidgetItem(event["data_sent"]))
        
        self.events_table.scrollToBottom()

    def closeEvent(self, event):
        for port in list(self.engine.listeners.keys()):
            self.engine.stop_listener(port)
        super().closeEvent(event)