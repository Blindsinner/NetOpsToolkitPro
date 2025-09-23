# app/advanced_features/header_analyzer_widget.py
from PySide6.QtWidgets import (
    QVBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QHBoxLayout
)
from PySide6.QtGui import QColor
from app.widgets.base_widget import BaseToolWidget
from app.core.header_analyzer_engine import HeaderAnalyzerEngine

class HeaderAnalyzerWidget(BaseToolWidget):
    """UI for the CSP & Security Header Analyzer."""
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.engine = HeaderAnalyzerEngine(self.task_manager)

        layout = QVBoxLayout(self)
        
        config_group = QGroupBox("Scan Configuration")
        form = QFormLayout(config_group)

        self.target_input = QLineEdit("https://example.com")
        self.start_button = QPushButton("Analyze Headers")
        
        form.addRow("Target URL:", self.target_input)
        form.addRow(self.start_button)
        
        results_group = QGroupBox("Results")
        results_vbox = QVBoxLayout(results_group)
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Header", "Value", "Comment / Recommendation"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.horizontalHeader().setStretchLastSection(True)

        export_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy Results")
        export_btn = QPushButton("Export Results")
        export_layout.addStretch()
        export_layout.addWidget(copy_btn)
        export_layout.addWidget(export_btn)
        
        results_vbox.addWidget(self.results_table)
        results_vbox.addLayout(export_layout)
        
        layout.addWidget(config_group)
        layout.addWidget(results_group)

        # Connections
        self.start_button.clicked.connect(self.start_scan)
        self.engine.scan_complete.connect(self.display_results)
        self.engine.scan_error.connect(self.on_scan_error)
        copy_btn.clicked.connect(lambda: self._copy_table_data(self.results_table))
        export_btn.clicked.connect(lambda: self._export_table_to_csv(self.results_table, "header_analysis.csv"))

    def start_scan(self):
        target_url = self.target_input.text().strip()
        if not target_url:
            self.show_error("Target URL is required.")
            return

        self.start_button.setEnabled(False)
        self.results_table.setRowCount(0)
        self.engine.start_analysis(target_url)

    def on_scan_error(self, message):
        self.show_error(message)
        self.start_button.setEnabled(True)

    def display_results(self, results: dict):
        self.results_table.setRowCount(len(results))
        for row, (header, data) in enumerate(results.items()):
            header_item = QTableWidgetItem(header)
            value_item = QTableWidgetItem(data['value'])
            comment_item = QTableWidgetItem(data['comment'])

            if not data['present']:
                # If the header is missing, color the row yellow/orange
                header_item.setBackground(QColor("#FFF3CD"))
                value_item.setBackground(QColor("#FFF3CD"))
                comment_item.setBackground(QColor("#FFF3CD"))

            self.results_table.setItem(row, 0, header_item)
            self.results_table.setItem(row, 1, value_item)
            self.results_table.setItem(row, 2, comment_item)
        
        self.results_table.resizeRowsToContents()
        self.start_button.setEnabled(True)
