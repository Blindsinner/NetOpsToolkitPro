# app/widgets/network_scan_widget.py
# REFACTORED: Added a public method to allow external triggering of scans.

import asyncio
import shutil
import xml.etree.ElementTree as ET
from PySide6.QtWidgets import (
    QVBoxLayout, QFormLayout, QLineEdit, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QLabel, QHBoxLayout
)
from app.widgets.base_widget import BaseToolWidget

class NetworkScanWidget(BaseToolWidget):
    NMAP_SCANS = {
        "LAN Host Discovery (Scapy ARP)": "ARP",
        "Fast LAN Scan (Nmap, ARP-based)": "-sn -PR".split(),
        "Intense Scan": "-T4 -A -v".split(),
        "Host Discovery (Ping Scan)": "-sn".split(),
        "Quick Scan (Top 100 ports)": "-T4 -F".split(),
        "Vulnerability Scan (Common Ports)": "-sV --script vuln".split(),
        "Full TCP Port Scan": "-p-".split(),
        "Firewall Discovery (ACK Scan)": "-sA".split(),
    }

    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        layout = QVBoxLayout(self)
        self.form_layout = QFormLayout()
        
        self.target_input = QLineEdit()
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(self.NMAP_SCANS.keys())
        self.interface_label = QLabel("Scan Interface:")
        self.interface_combo = QComboBox()
        
        self.form_layout.addRow("Target(s)/CIDR:", self.target_input)
        self.form_layout.addRow(self.interface_label, self.interface_combo)
        self.form_layout.addRow("Scan Type:", self.scan_type_combo)
        
        self.scan_button = QPushButton("Start Scan")
        self.results_table = QTableWidget()
        layout.addLayout(self.form_layout)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.results_table, 1)

        export_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy All")
        export_btn = QPushButton("Export to CSV")
        export_layout.addStretch()
        export_layout.addWidget(copy_btn)
        export_layout.addWidget(export_btn)
        layout.addLayout(export_layout)
        
        self.scan_button.clicked.connect(lambda: self.task_manager.create_task(self.perform_scan()))
        self.scan_type_combo.currentTextChanged.connect(self.on_scan_type_change)
        copy_btn.clicked.connect(lambda: self._copy_table_data(self.results_table))
        export_btn.clicked.connect(lambda: self._export_table_to_csv(self.results_table, "nmap_scan.csv"))
        
        self.nmap_path = shutil.which("nmap")
        if not self.nmap_path:
            for i in range(self.scan_type_combo.count()):
                scan_name = self.scan_type_combo.itemText(i)
                if self.NMAP_SCANS[scan_name] != "ARP":
                    self.scan_type_combo.model().item(i).setEnabled(False)
            self.scan_type_combo.setToolTip("Nmap not found. Please install and add to PATH.")
        
        self.load_state()
        self.on_scan_type_change(self.scan_type_combo.currentText())

    # FIX: New public method to be called by the signal handler
    def start_scan_on_target(self, target: str, scan_type: str = None):
        """Public method to programmatically start a scan."""
        self.target_input.setText(target)
        if scan_type and scan_type in self.NMAP_SCANS:
            self.scan_type_combo.setCurrentText(scan_type)
        
        self.show_info(f"Received request to scan {target}...")
        self.task_manager.create_task(self.perform_scan())

    def on_scan_type_change(self, s: str):
        is_arp = s == "LAN Host Discovery (Scapy ARP)"
        self.interface_label.setVisible(is_arp)
        self.interface_combo.setVisible(is_arp)
        if is_arp:
            self.interface_combo.clear()
            lan_info = self.system_tools.get_default_lan_info()
            adapters = self.system_tools.get_usable_interfaces()
            self.interface_combo.addItems(adapters)
            if lan_info and lan_info['adapter'] in adapters:
                self.interface_combo.setCurrentText(lan_info['adapter'])

    async def perform_scan(self):
        target = self.target_input.text().strip()
        scan_type = self.scan_type_combo.currentText()
        self.scan_button.setEnabled(False)
        self.results_table.setRowCount(0)
        
        try:
            if scan_type == "LAN Host Discovery (Scapy ARP)":
                await self.run_arp_scan(target, self.interface_combo.currentText())
            else:
                await self.run_nmap_scan(target, scan_type)
        except Exception as e:
            if not isinstance(e, asyncio.CancelledError): self.show_error(f"An error occurred during the scan:\n{e}")
        finally:
            if self and self.scan_button: self.scan_button.setEnabled(True)

    async def run_arp_scan(self, t, iface):
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "MAC Address"])
        results = await self.network_tools.run_arp_scan(t, iface)
        if not results: self.show_info("ARP scan complete. No hosts found.")
        for res in results:
            row = self.results_table.rowCount(); self.results_table.insertRow(row)
            self.results_table.setItem(row, 0, QTableWidgetItem(res['ip']))
            self.results_table.setItem(row, 1, QTableWidgetItem(res['mac']))
        self.results_table.resizeColumnsToContents()

    async def run_nmap_scan(self, t, s):
        if not self.nmap_path: self.show_error("Nmap not found."); return
        
        xml_output = await self.network_tools.run_nmap_scan(t, self.NMAP_SCANS[s])
        root = ET.fromstring(xml_output); hosts = root.findall('host')
        
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Host", "Status", "Open Ports", "Services", "Vuln/Script Info"])
        
        if not hosts: self.show_info("Scan completed. No online hosts found."); return
        
        for host in hosts:
            row = self.results_table.rowCount(); self.results_table.insertRow(row)
            status_elem = host.find('status'); status = status_elem.get('state') if status_elem is not None else 'unknown'
            addr_elem = host.find('address'); addr = addr_elem.get('addr') if addr_elem is not None else 'N/A'
            hostname_elem = host.find('hostnames/hostname'); hostname = hostname_elem.get('name') if hostname_elem is not None else ''
            self.results_table.setItem(row, 0, QTableWidgetItem(f"{addr} ({hostname})" if hostname else addr))
            self.results_table.setItem(row, 1, QTableWidgetItem(status))
            
            if status == 'up':
                ports, services, script_outputs = [], [], []
                for port in host.findall('ports/port'):
                    state_elem = port.find('state')
                    if state_elem is not None and state_elem.get('state') == 'open':
                        ports.append(f"{port.get('portid')}/{port.get('protocol')}")
                        service_elem = port.find('service'); services.append(service_elem.get('name', '') if service_elem is not None else '')
                        for script in port.findall('script'):
                            script_id = script.get('id', 'unknown'); script_output = script.get('output', '').strip()
                            if script_output: script_outputs.append(f"Port {port.get('portid')}: {script_id} - {script_output.replace('\\n', ' ')}")
                self.results_table.setItem(row, 2, QTableWidgetItem(", ".join(ports)))
                self.results_table.setItem(row, 3, QTableWidgetItem(", ".join(s for s in services if s)))
                self.results_table.setItem(row, 4, QTableWidgetItem("\n".join(script_outputs)))
        
        self.results_table.resizeColumnsToContents(); self.results_table.resizeRowsToContents()

    def load_state(self):
        lan_info = self.system_tools.get_default_lan_info()
        default_target = lan_info['cidr'] if lan_info else "192.168.1.0/24"
        self.target_input.setText(self.settings.value("scanner/target", default_target))

    def save_state(self):
        self.settings.setValue("scanner/target", self.target_input.text())
