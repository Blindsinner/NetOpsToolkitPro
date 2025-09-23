# app/advanced_features/recon_suite.py
# CORRECTED: Subdomain scanner now shows results in real-time and has a Stop button.

import asyncio
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget, QLineEdit, QPushButton,
    QTableWidget, QFormLayout, QTableWidgetItem, QHeaderView, QLabel, QHBoxLayout
)
from app.config import AppConfig
from app.core.recon_engine import ReconEngine
from app.core.app_logger import activity_logger
from app.widgets.base_widget import BaseToolWidget

class ReconSuiteWidget(BaseToolWidget):
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(settings, task_manager, parent)
        # FIX: The recon engine now requires the task_manager
        self.engine = ReconEngine(self.task_manager, AppConfig.PROJECT_ROOT / "subdomains.txt")
        
        main_layout = QVBoxLayout(self)
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        tabs.addTab(self._create_subdomain_tab(), "Subdomain Scanner")

    def _create_subdomain_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        form_layout = QFormLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g., example.com")
        
        # FIX: Added a Stop button
        self.scan_btn = QPushButton("Find Subdomains")
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.setEnabled(False)
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.scan_btn)
        button_layout.addWidget(self.stop_scan_btn)
        
        form_layout.addRow(QLabel("Target Domain:"), self.domain_input)
        
        self.status_label = QLabel("Status: Idle")
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Subdomain", "IP Address(es)", "Source"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        layout.addLayout(form_layout)
        layout.addLayout(button_layout) # Use the layout with both buttons
        layout.addWidget(self.status_label)
        layout.addWidget(self.results_table)

        export_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy All")
        export_btn = QPushButton("Export to CSV")
        export_layout.addStretch()
        export_layout.addWidget(copy_btn)
        export_layout.addWidget(export_btn)
        layout.addLayout(export_layout)
        
        self.scan_btn.clicked.connect(self.start_subdomain_scan)
        # FIX: Connect the stop button
        self.stop_scan_btn.clicked.connect(self.stop_subdomain_scan)
        copy_btn.clicked.connect(lambda: self._copy_table_data(self.results_table))
        export_btn.clicked.connect(lambda: self._export_table_to_csv(self.results_table, "subdomains.csv"))
        return widget

    def start_subdomain_scan(self):
        target = self.domain_input.text().strip()
        if not target:
            self.status_label.setText("Status: Please enter a target domain.")
            return

        activity_logger.log("Subdomain Scan Started", f"Target: {target}")
        self.results_table.setRowCount(0)
        self.scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.task_manager.create_task(self._stream_subdomain_results(target))

    # FIX: New method to stop the scan
    def stop_subdomain_scan(self):
        self.engine.stop_subdomain_scan()
        self.status_label.setText("Status: Stopping scan...")
        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)

    async def _stream_subdomain_results(self, domain):
        try:
            self.status_label.setText("Status: Querying certificate logs...")
            # FIX: This loop now processes results as they arrive
            async for result in self.engine.find_subdomains(domain):
                if self.results_table.rowCount() == 1:
                    self.status_label.setText("Status: Brute-forcing common names (this can take a while)...")
                
                if "error" in result:
                    self.status_label.setText(f"Status: Error - {result['error']}")
                    continue

                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                self.results_table.setItem(row, 0, QTableWidgetItem(result["subdomain"]))
                self.results_table.setItem(row, 2, QTableWidgetItem(result["source"]))
                
                # Resolve IP in a separate, non-blocking task
                self.task_manager.create_task(self._resolve_and_update_ip(row, result["subdomain"]))
        finally:
            self.status_label.setText("Status: Scan finished or stopped.")
            self.scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)

    async def _resolve_and_update_ip(self, row, subdomain):
        import dns.resolver
        resolver = dns.resolver.Resolver(); resolver.nameservers = ['8.8.8.8']
        ips = []
        try:
            answer = await asyncio.get_running_loop().run_in_executor(
                None, lambda: resolver.resolve(subdomain, 'A')
            )
            ips = [str(r) for r in answer]
        except Exception: pass
        
        # Check if the widget and row still exist before updating
        if self and self.results_table.rowCount() > row:
            self.results_table.setItem(row, 1, QTableWidgetItem(", ".join(ips)))
