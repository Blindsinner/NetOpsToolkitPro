# app/advanced_features/directory_bruteforcer_widget.py
from PySide6.QtWidgets import (
    QVBoxLayout, QFormLayout, QLineEdit, QPushButton, QComboBox, QCheckBox,
    QGroupBox, QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
    QHBoxLayout, QSpinBox, QLabel
)
from PySide6.QtGui import QColor
from app.widgets.base_widget import BaseToolWidget
from app.core.recon_engine import ReconEngine

class DirectoryBruteforcerWidget(BaseToolWidget):
    """UI for the Directory and File Bruteforcer."""
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.engine = ReconEngine(self.task_manager)

        layout = QVBoxLayout(self)
        
        config_group = QGroupBox("Scan Configuration")
        form = QFormLayout(config_group)

        self.target_input = QLineEdit("https://example.com")
        self.wordlist_input = QLineEdit()
        wordlist_browse_btn = QPushButton("Browse...")
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(self.wordlist_input)
        wordlist_layout.addWidget(wordlist_browse_btn)

        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 500); self.threads_input.setValue(50)

        self.status_code_group = QGroupBox("Report Status Codes")
        self.status_code_group.setCheckable(False)
        status_layout = QHBoxLayout(self.status_code_group)
        self.status_codes_cbs = {
            code: QCheckBox(str(code)) for code in [200, 204, 301, 302, 307, 401, 403]
        }
        # Default checked codes
        for code in [200, 301, 302, 403]:
            self.status_codes_cbs[code].setChecked(True)
        for cb in self.status_codes_cbs.values():
            status_layout.addWidget(cb)
        
        self.start_button = QPushButton("Start Scan")
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setEnabled(False)
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)

        form.addRow("Target URL:", self.target_input)
        form.addRow("Wordlist:", wordlist_layout)
        form.addRow("Threads:", self.threads_input)
        form.addRow(self.status_code_group)
        form.addRow(button_layout)

        results_group = QGroupBox("Results")
        results_vbox = QVBoxLayout(results_group)
        self.status_label = QLabel("Status: Idle")
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Found Path", "Status Code", "Content Length"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setSortingEnabled(True)
        results_vbox.addWidget(self.status_label)
        results_vbox.addWidget(self.results_table)

        layout.addWidget(config_group)
        layout.addWidget(results_group)

        # Connections
        wordlist_browse_btn.clicked.connect(self._browse_wordlist)
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.engine.path_found.connect(self.add_result)
        self.engine.progress_updated.connect(self.update_status)
        self.engine.scan_finished.connect(self.on_scan_finished)

    def _browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.wordlist_input.setText(path)

    def start_scan(self):
        base_url = self.target_input.text().strip()
        wordlist = self.wordlist_input.text().strip()
        if not base_url or not wordlist:
            self.show_error("Target URL and Wordlist are required.")
            return

        self.start_button.setEnabled(False); self.stop_button.setEnabled(True)
        self.results_table.setRowCount(0)
        
        status_codes = {code for code, cb in self.status_codes_cbs.items() if cb.isChecked()}
        threads = self.threads_input.value()
        
        self.engine.start_directory_bruteforce(base_url, wordlist, threads, status_codes)

    def stop_scan(self):
        self.engine.stop_scan()
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)

    def add_result(self, result: dict):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        path_item = QTableWidgetItem(result['path'])
        status_item = QTableWidgetItem(str(result['status']))
        length_item = QTableWidgetItem(str(result['length']))
        
        status_code = result['status']
        if 200 <= status_code < 300:
            status_item.setForeground(QColor("lime"))
        elif 400 <= status_code < 500:
            status_item.setForeground(QColor("orange"))

        self.results_table.setItem(row, 0, path_item)
        self.results_table.setItem(row, 1, status_item)
        self.results_table.setItem(row, 2, length_item)

    def update_status(self, message: str):
        self.status_label.setText(f"Status: {message}")

    def on_scan_finished(self, message: str):
        self.status_label.setText(f"Status: {message}")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def shutdown(self):
        self.engine.stop_scan()
