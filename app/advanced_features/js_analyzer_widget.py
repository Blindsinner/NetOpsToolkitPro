# app/advanced_features/js_analyzer_widget.py
from PySide6.QtWidgets import (
    QVBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QGroupBox, QTreeWidget, QTreeWidgetItem,
    QHBoxLayout, QLabel
)
from app.widgets.base_widget import BaseToolWidget
from app.core.js_recon_engine import JSReconEngine

class JSAnalyzerWidget(BaseToolWidget):
    """UI for the JS File Scraper and Analyzer."""
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.engine = JSReconEngine(self.task_manager)
        self.js_file_items = {}

        layout = QVBoxLayout(self)
        
        config_group = QGroupBox("Scan Configuration")
        form = QFormLayout(config_group)

        self.target_input = QLineEdit("https://example.com")
        self.start_button = QPushButton("Find & Analyze JS Files")
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setEnabled(False)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)

        form.addRow("Target URL:", self.target_input)
        form.addRow(button_layout)
        
        results_group = QGroupBox("Results")
        results_vbox = QVBoxLayout(results_group)
        self.status_label = QLabel("Status: Idle")
        self.results_tree = QTreeWidget()
        self.results_tree.setColumnCount(2)
        self.results_tree.setHeaderLabels(["File / Finding Type", "Match"])
        self.results_tree.header().setStretchLastSection(True)
        
        results_vbox.addWidget(self.status_label)
        results_vbox.addWidget(self.results_tree)

        layout.addWidget(config_group)
        layout.addWidget(results_group)

        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.engine.js_file_found.connect(self.add_js_file)
        self.engine.secret_found.connect(self.add_secret)
        self.engine.progress_updated.connect(self.update_status)
        self.engine.scan_finished.connect(self.on_scan_finished)

    def start_scan(self):
        base_url = self.target_input.text().strip()
        if not base_url:
            self.show_error("Target URL is required.")
            return

        self.start_button.setEnabled(False); self.stop_button.setEnabled(True)
        self.results_tree.clear(); self.js_file_items.clear()
        self.engine.start_scan(base_url)

    def stop_scan(self):
        self.engine.stop_scan()
        
    def add_js_file(self, url: str):
        if url not in self.js_file_items:
            item = QTreeWidgetItem(self.results_tree, [url.split('/')[-1]])
            item.setToolTip(0, url)
            self.js_file_items[url] = item

    def add_secret(self, secret_data: dict):
        js_file = secret_data.get("js_file")
        if js_file not in self.js_file_items:
            self.add_js_file(js_file)
            
        parent_item = self.js_file_items[js_file]
        QTreeWidgetItem(parent_item, [secret_data.get("type"), secret_data.get("match")])
        parent_item.setExpanded(True)

    def update_status(self, message: str):
        self.status_label.setText(f"Status: {message}")

    def on_scan_finished(self, message: str):
        self.status_label.setText(f"Status: {message}")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def shutdown(self):
        self.stop_scan()
