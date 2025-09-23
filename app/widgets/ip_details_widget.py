# -*- coding: utf-8 -*-
import json
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog
)
from app.widgets.base_widget import BaseToolWidget
from app.core.ip_utils import IPUtils

class IPDetailsWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.ip_utils = IPUtils()
        self.current_details = {}

        layout = QVBoxLayout(self)
        input_layout = QFormLayout()

        self.ip_input = QLineEdit()
        self.subnet_input = QLineEdit()
        input_layout.addRow("IP Address / CIDR:", self.ip_input)
        input_layout.addRow("Subnet Mask / CIDR:", self.subnet_input)

        self.analyze_button = QPushButton("Analyze")
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.horizontalHeader().setStretchLastSection(True)

        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy")
        export_btn = QPushButton("Export")
        btn_layout.addStretch()
        btn_layout.addWidget(copy_btn)
        btn_layout.addWidget(export_btn)

        layout.addLayout(input_layout)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.results_table, 1)
        layout.addLayout(btn_layout)

        self.analyze_button.clicked.connect(self.display_full_info)
        copy_btn.clicked.connect(lambda: self.copy_to_clipboard(self._format_details_text()))
        export_btn.clicked.connect(self.export_details)
        
        self.load_state()

    def display_full_info(self):
        info = self.ip_utils.get_ip_info(self.ip_input.text().strip(), self.subnet_input.text().strip())
        if info.errors:
            self.show_error("\n".join(info.errors))
            return
        
        self.current_details = info.details
        self.results_table.setRowCount(len(self.current_details))
        for row, (key, value) in enumerate(self.current_details.items()):
            self.results_table.setItem(row, 0, QTableWidgetItem(key))
            self.results_table.setItem(row, 1, QTableWidgetItem(str(value)))
        self.results_table.resizeRowsToContents()

    def _format_details_text(self):
        return "\n".join(f"{k}: {v}" for k, v in self.current_details.items())

    def export_details(self):
        if not self.current_details:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Details", "", "JSON (*.json);;Text (*.txt)")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                if path.endswith('.json'):
                    json.dump(self.current_details, f, indent=4)
                else:
                    f.write(self._format_details_text())

    def load_state(self):
        self.ip_input.setText(self.settings.value("ip_details/ip", "8.8.8.8"))
        self.subnet_input.setText(self.settings.value("ip_details/subnet", "24"))

    def save_state(self):
        self.settings.setValue("ip_details/ip", self.ip_input.text())
        self.settings.setValue("ip_details/subnet", self.subnet_input.text())