# -*- coding: utf-8 -*-
import datetime
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox, QFormLayout,
    QLineEdit, QSpinBox, QLabel, QApplication, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from app.core.task_manager import TaskManager
from app.core.log_server import LogServerThread

class LogIngestorDialog(QDialog): # <-- FIX: Inherit from QDialog
    def __init__(self, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        self.task_manager = task_manager
        self.server_thread = None
        
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.setWindowTitle("Centralized Log Ingestor (Syslog)")
        self.setMinimumSize(900, 600)
        self.resize(1000, 700)

        layout = QVBoxLayout(self)
        
        controls_group = QGroupBox("Syslog Server Controls")
        form = QFormLayout(controls_group)
        self.host_input = QLineEdit("0.0.0.0")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535); self.port_input.setValue(514)
        self.start_btn = QPushButton("Start Server")
        self.stop_btn = QPushButton("Stop Server")
        self.stop_btn.setEnabled(False)
        self.status_label = QLabel("Status: Stopped")
        
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        
        form.addRow("Listen IP:", self.host_input)
        form.addRow("Listen Port:", self.port_input)
        form.addRow(btn_layout)
        form.addRow("Status:", self.status_label)
        layout.addWidget(controls_group)
        
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(5)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "Host", "Facility", "Severity", "Message"])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.log_table.horizontalHeader().setStretchLastSection(True)
        self.log_table.setAlternatingRowColors(True)
        layout.addWidget(self.log_table)

        export_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy All")
        export_btn = QPushButton("Export to CSV")
        export_layout.addStretch()
        export_layout.addWidget(copy_btn)
        export_layout.addWidget(export_btn)
        layout.addLayout(export_layout)

        self.start_btn.clicked.connect(self.start_server)
        self.stop_btn.clicked.connect(self.stop_server)
        copy_btn.clicked.connect(self._copy_table_data)
        export_btn.clicked.connect(self._export_table_to_csv)

    def start_server(self):
        host = self.host_input.text()
        port = self.port_input.value()
        
        self.server_thread = LogServerThread(host, port)
        self.server_thread.message_received.connect(self.add_log_entry)
        self.server_thread.server_started.connect(self.on_server_started)
        self.server_thread.server_stopped.connect(self.on_server_stopped)
        self.server_thread.start()

    def stop_server(self):
        if self.server_thread:
            self.server_thread.stop()
            self.server_thread.wait()
            self.server_thread = None

    def on_server_started(self, host, port):
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.host_input.setEnabled(False); self.port_input.setEnabled(False)
        self.status_label.setText(f"Status: Running and listening on {host}:{port}")
        self.status_label.setStyleSheet("color: lime;")

    def on_server_stopped(self, reason):
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.host_input.setEnabled(True); self.port_input.setEnabled(True)
        self.status_label.setText(f"Status: Stopped. Reason: {reason}")
        self.status_label.setStyleSheet("color: red;")
        
    def add_log_entry(self, log_data: dict):
        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        
        self.log_table.setItem(row, 0, QTableWidgetItem(log_data["timestamp"]))
        self.log_table.setItem(row, 1, QTableWidgetItem(log_data["host"]))
        self.log_table.setItem(row, 2, QTableWidgetItem(log_data["facility"]))
        severity_item = QTableWidgetItem(log_data["severity"])
        severity = log_data["severity"].lower()
        if severity in ["emerg", "alert", "crit", "err"]: severity_item.setForeground(QColor("red"))
        elif severity in ["warning", "warn"]: severity_item.setForeground(QColor("orange"))
        self.log_table.setItem(row, 3, severity_item)
        self.log_table.setItem(row, 4, QTableWidgetItem(log_data["message"]))
        self.log_table.scrollToBottom()

    def _copy_table_data(self):
        table = self.log_table
        header = [table.horizontalHeaderItem(c).text() for c in range(table.columnCount())]
        lines = ["\t".join(header)]
        for r in range(table.rowCount()):
            row_data = [table.item(r, c).text() if table.item(r, c) else "" for c in range(table.columnCount())]
            lines.append("\t".join(row_data))
        QApplication.clipboard().setText("\n".join(lines))
        QMessageBox.information(self, "Success", "Log data copied to clipboard.")

    def _export_table_to_csv(self):
        table = self.log_table
        path, _ = QFileDialog.getSaveFileName(self, "Export to CSV", "syslog_export.csv", "CSV Files (*.csv)")
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

    def closeEvent(self, event):
        self.stop_server()
        super().closeEvent(event)