# app/advanced_features/security_testing.py
# UPDATED: Adds Recon widgets, VulnerabilityScannerWidget, Browser Automation, and a safe Red Team tab.

import platform
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QGroupBox, QLabel, QLineEdit,
    QPushButton, QTextEdit, QTabWidget, QFormLayout,
    QComboBox, QSpinBox, QHBoxLayout, QFileDialog, QApplication
)
from PySide6.QtCore import Qt

from app.advanced_features.red_team_tools_widget import RedTeamToolsWidget
from app.widgets.base_widget import BaseToolWidget
from app.core.task_manager import TaskManager
from app.core.security_tester import SecurityTester

# Original widgets
from app.advanced_features.password_audit_widget import PasswordAuditWidget
from app.advanced_features.directory_bruteforcer_widget import DirectoryBruteforcerWidget
from app.advanced_features.js_analyzer_widget import JSAnalyzerWidget
from app.advanced_features.header_analyzer_widget import HeaderAnalyzerWidget
from app.advanced_features.vulnerability_scanner_widget import VulnerabilityScannerWidget

# New Recon widgets
from app.advanced_features.recon.asn_widget import ASNWidget
from app.advanced_features.recon.wayback_widget import WaybackWidget
from app.advanced_features.recon.cloud_enum_widget import CloudEnumWidget
from app.advanced_features.browser_automation_widget import BrowserAutomationWidget
from app.advanced_features.recon.ipintel_widget import IPIntelWidget
from app.advanced_features.recon.whois_widget import WhoisWidget


class SecurityTestingWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)

        self.security_tester = SecurityTester(self.settings, self.task_manager)

        main_layout = QVBoxLayout(self)
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Original tabs
        self.tab_widget.addTab(self._create_recon_web_tab(), "🌐 Recon & Web Scan")
        self.tab_widget.addTab(self._create_vuln_analysis_tab(), "⚡ Vulnerability Analysis")
        self.tab_widget.addTab(PasswordAuditWidget(settings, task_manager), "🔑 Password Auditor")
        self.tab_widget.addTab(self._create_infra_audit_tab(), "🛡️ Infrastructure & Audits")
        self.tab_widget.addTab(self._create_exploitation_tab(), "🕵️ Exploitation (Simulated)")
        self.tab_widget.addTab(RedTeamToolsWidget(self.settings, self.task_manager), "🟥 Phishing Composer")
        # New: Browser Automation
        self.tab_widget.addTab(BrowserAutomationWidget(self.settings, self.task_manager), "🤖 Browser Automation")

    # --------------------------
    # RECON + WEB
    # --------------------------
    def _create_recon_web_tab(self):
        recon_widget = QWidget()
        recon_layout = QVBoxLayout(recon_widget)

        recon_tabs = QTabWidget()
        recon_layout.addWidget(recon_tabs)

        # Original sub-tabs
        recon_tabs.addTab(DirectoryBruteforcerWidget(self.settings, self.task_manager), "Directory Bruteforcer")
        recon_tabs.addTab(JSAnalyzerWidget(self.settings, self.task_manager), "JS File Analyzer")
        recon_tabs.addTab(HeaderAnalyzerWidget(self.settings, self.task_manager), "Security Header Analyzer")

        # New Recon widgets
        recon_tabs.addTab(ASNWidget(self.settings, self.task_manager), "ASN Intelligence")
        recon_tabs.addTab(IPIntelWidget(self.settings, self.task_manager), "IP Intelligence")
        recon_tabs.addTab(WhoisWidget(self.settings, self.task_manager), "WHOIS & DNS")
        recon_tabs.addTab(WaybackWidget(self.settings, self.task_manager), "Wayback Discovery")
        recon_tabs.addTab(CloudEnumWidget(self.settings, self.task_manager), "Cloud Enumeration")

        # Other Recon (kept)
        other_recon_widget = QWidget()
        layout = QGridLayout(other_recon_widget)
        self.recon_results_output = QTextEdit(readOnly=True)

        # Subdomain Enumeration
        sub_group = QGroupBox("Subdomain Enumeration")
        sub_form = QFormLayout(sub_group)
        self.sub_target = QLineEdit(placeholderText="e.g. example.com")
        self.run_sub_btn = QPushButton("Find Subdomains")
        self.stop_sub_btn = QPushButton("Stop Scan")
        self.stop_sub_btn.setEnabled(False)
        sub_button_layout = QHBoxLayout()
        sub_button_layout.addWidget(self.run_sub_btn)
        sub_button_layout.addWidget(self.stop_sub_btn)
        sub_form.addRow("Domain:", self.sub_target)
        sub_form.addRow(sub_button_layout)

        # Wappalyzer
        web_group = QGroupBox("Web Technology Detection (Wappalyzer)")
        web_form = QFormLayout(web_group)
        self.web_target = QLineEdit(placeholderText="e.g. https://example.com")
        self.run_web_btn = QPushButton("Detect Technologies")
        web_form.addRow("URL:", self.web_target)
        web_form.addRow(self.run_web_btn)

        layout.addWidget(sub_group, 0, 0)
        layout.addWidget(web_group, 0, 1)

        # Nikto (Linux only)
        if platform.system() == "Linux":
            nikto_group = QGroupBox("Web Server Scan (Nikto)")
            nikto_form = QFormLayout(nikto_group)
            self.nikto_target = QLineEdit(placeholderText="e.g. example.com or IP")
            self.run_nikto_btn = QPushButton("Run Nikto Scan")
            nikto_form.addRow("Host/IP:", self.nikto_target)
            nikto_form.addRow(self.run_nikto_btn)
            layout.addWidget(nikto_group, 1, 0, 1, 2)
            self.run_nikto_btn.clicked.connect(
                lambda: self._run_and_append_task(self.nikto_target, self.security_tester.run_nikto, self.recon_results_output)
            )

        layout.addWidget(self.recon_results_output, 2, 0, 1, 2)
        recon_tabs.addTab(other_recon_widget, "Other Recon")

        # Signals
        self.run_sub_btn.clicked.connect(self.on_run_subdomain_scan)
        self.stop_sub_btn.clicked.connect(self.on_stop_subdomain_scan)
        self.run_web_btn.clicked.connect(
            lambda: self._run_and_append_task(self.web_target, self.security_tester.run_wappalyzer, self.recon_results_output)
        )

        return recon_widget

    def on_run_subdomain_scan(self):
        target = self.sub_target.text().strip()
        if not target:
            self.show_error("Please provide a target domain.")
            return

        self.run_sub_btn.setEnabled(False)
        self.stop_sub_btn.setEnabled(True)
        self.recon_results_output.setText(f"Starting subdomain scan for '{target}'.\n")

        async def stream_results():
            self.recon_results_output.append("Querying certificate logs.")
            count = 0
            async for result in self.security_tester.run_subdomain_scan(target):
                if count == 1:
                    self.recon_results_output.append("\nBrute-forcing common names.")
                if "error" in result:
                    self.recon_results_output.append(f"[ERROR] {result['error']}")
                else:
                    self.recon_results_output.append(f"- {result['subdomain']} (Source: {result['source']})")
                QApplication.processEvents()
                count += 1
            self.recon_results_output.append(f"\n--- Scan Finished ({count} results) ---")
            self.run_sub_btn.setEnabled(True)
            self.stop_sub_btn.setEnabled(False)

        self.task_manager.create_task(stream_results())

    def on_stop_subdomain_scan(self):
        self.security_tester.stop_subdomain_scan()
        self.run_sub_btn.setEnabled(True)
        self.stop_sub_btn.setEnabled(False)
        self.recon_results_output.append("\n--- Scan Stopped By User ---")

    # --------------------------
    # VULNERABILITY ANALYSIS
    # --------------------------
    def _create_vuln_analysis_tab(self):
        vuln_widget = QWidget()
        vuln_layout = QVBoxLayout(vuln_widget)
        vuln_tabs = QTabWidget()
        vuln_layout.addWidget(vuln_tabs)

        # Web App Scanner
        vuln_tabs.addTab(VulnerabilityScannerWidget(self.settings, self.task_manager), "Web App Scanner")

        # Network & CVE analysis
        other_vuln_widget = QWidget()
        layout = QGridLayout(other_vuln_widget)
        self.vuln_results_output = QTextEdit(readOnly=True)

        # Nmap
        nmap_group = QGroupBox("Nmap Port & Vulnerability Scanner")
        nmap_form = QFormLayout(nmap_group)
        self.nmap_target = QLineEdit(placeholderText="e.g. 192.168.1.1 or example.com")
        self.nmap_scan_type = QComboBox()
        self.nmap_scan_type.addItems(["Quick Scan", "Standard Scan", "Vulnerability Scan"])
        self.run_nmap_btn = QPushButton("Run Nmap Scan")
        nmap_form.addRow("Target:", self.nmap_target)
        nmap_form.addRow("Scan Type:", self.nmap_scan_type)
        nmap_form.addRow(self.run_nmap_btn)

        # Vulners
        vulners_group = QGroupBox("Vulners CVE Search")
        vulners_form = QFormLayout(vulners_group)
        self.vulners_query = QLineEdit(placeholderText="e.g. Apache 2.4.49")
        self.run_vulners_btn = QPushButton("Search Vulners")
        vulners_form.addRow("Service/Product:", self.vulners_query)
        vulners_form.addRow(self.run_vulners_btn)

        layout.addWidget(nmap_group, 0, 0)
        layout.addWidget(vulners_group, 0, 1)
        layout.addWidget(self.vuln_results_output, 1, 0, 1, 2)

        vuln_tabs.addTab(other_vuln_widget, "Network & CVE Analysis")

        # Signals
        self.run_nmap_btn.clicked.connect(self.on_run_nmap)
        self.run_vulners_btn.clicked.connect(
            lambda: self._run_and_append_task(self.vulners_query, self.security_tester.search_vulners, self.vuln_results_output)
        )
        return vuln_widget

    # --------------------------
    # INFRASTRUCTURE & AUDITS
    # --------------------------
    def _create_infra_audit_tab(self):
        widget = QWidget()
        layout = QGridLayout(widget)
        self.audit_results_output = QTextEdit(readOnly=True)

        # DDoS Simulation (controlled)
        ddos_group = QGroupBox("DDoS Simulation (Controlled)")
        ddos_form = QFormLayout(ddos_group)
        self.ddos_target = QLineEdit(placeholderText="Internal IP to test")
        self.ddos_port = QSpinBox(); self.ddos_port.setRange(1, 65535); self.ddos_port.setValue(80)
        self.ddos_duration = QSpinBox(); self.ddos_duration.setRange(1, 300); self.ddos_duration.setValue(10); self.ddos_duration.setSuffix(" s")
        self.ddos_method = QComboBox(); self.ddos_method.addItems(["TCP SYN Flood", "UDP Flood", "ICMP Flood"])
        self.run_ddos_btn = QPushButton("Start Simulation")
        ddos_form.addRow(QLabel("⚠️ Use only on internal networks you own!"))
        ddos_form.addRow("Target IP:", self.ddos_target)
        ddos_form.addRow("Port:", self.ddos_port)
        ddos_form.addRow("Duration:", self.ddos_duration)
        ddos_form.addRow("Method:", self.ddos_method)
        ddos_form.addRow(self.run_ddos_btn)

        # Local audits
        local_audit_group = QGroupBox("Local System Audits")
        local_audit_layout = QVBoxLayout(local_audit_group)
        self.run_wifi_btn = QPushButton("Scan WiFi Networks")
        self.run_usb_btn = QPushButton("Audit USB Devices")
        local_audit_layout.addWidget(self.run_wifi_btn)
        local_audit_layout.addWidget(self.run_usb_btn)

        # Breach audit
        leak_group = QGroupBox("Password Leak Audit (HIBP)")
        leak_form = QFormLayout(leak_group)
        self.leak_accounts = QLineEdit(placeholderText="user@example.com, another@test.com")
        self.run_leak_btn = QPushButton("Check for Breaches")
        leak_form.addRow("Accounts (CSV):", self.leak_accounts)
        leak_form.addRow(self.run_leak_btn)

        layout.addWidget(ddos_group, 0, 0)
        layout.addWidget(local_audit_group, 0, 1)
        layout.addWidget(leak_group, 1, 0, 1, 2)
        layout.addWidget(self.audit_results_output, 2, 0, 1, 2)

        # Signals
        self.run_ddos_btn.clicked.connect(self.on_run_ddos)
        self.run_wifi_btn.clicked.connect(self.on_run_wifi)
        self.run_usb_btn.clicked.connect(self.on_run_usb)
        self.run_leak_btn.clicked.connect(
            lambda: self._run_and_append_task(self.leak_accounts, self.security_tester.run_password_leak_audit, self.audit_results_output)
        )
        return widget

    # --------------------------
    # EXPLOITATION (SIMULATED)
    # --------------------------
    def _create_exploitation_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.exploit_results_output = QTextEdit(readOnly=True)

        if platform.system() == "Linux":
            main_grid = QGridLayout()

            # Hydra
            hydra_group = QGroupBox("Login Brute-Force Simulation (Hydra)")
            hydra_layout = QFormLayout(hydra_group)
            self.hydra_target = QLineEdit("192.168.1.25")
            self.hydra_service = QLineEdit("ssh")
            self.hydra_userlist = QLineEdit("users.txt")
            self.hydra_passlist = QLineEdit("passwords.txt")
            self.run_hydra_btn = QPushButton("Run Hydra Simulation")
            user_browse_btn = QPushButton("Browse…")
            pass_browse_btn = QPushButton("Browse…")
            user_layout = QHBoxLayout(); user_layout.addWidget(self.hydra_userlist); user_layout.addWidget(user_browse_btn)
            pass_layout = QHBoxLayout(); pass_layout.addWidget(self.hydra_passlist); pass_layout.addWidget(pass_browse_btn)
            hydra_layout.addRow("Target IP:", self.hydra_target)
            hydra_layout.addRow("Service (ssh, ftp):", self.hydra_service)
            hydra_layout.addRow("User List File:", user_layout)
            hydra_layout.addRow("Password List File:", pass_layout)
            hydra_layout.addRow(self.run_hydra_btn)

            # Searchsploit
            searchsploit_group = QGroupBox("Exploit-DB Search (Searchsploit)")
            ss_layout = QFormLayout(searchsploit_group)
            self.ss_query = QLineEdit(placeholderText="e.g. Windows 10 RDP")
            self.run_ss_btn = QPushButton("Search for Exploits")
            ss_layout.addRow("Search Query:", self.ss_query)
            ss_layout.addRow(self.run_ss_btn)

            main_grid.addWidget(hydra_group, 0, 0)
            main_grid.addWidget(searchsploit_group, 0, 1)
            layout.addLayout(main_grid)

            # Signals
            self.run_hydra_btn.clicked.connect(self.on_run_hydra)
            user_browse_btn.clicked.connect(lambda: self._browse_file(self.hydra_userlist, "Select User List"))
            pass_browse_btn.clicked.connect(lambda: self._browse_file(self.hydra_passlist, "Select Password List"))
            self.run_ss_btn.clicked.connect(
                lambda: self._run_and_append_task(self.ss_query, self.security_tester.search_exploitdb, self.exploit_results_output)
            )
        else:
            info_label = QLabel("Advanced exploitation simulations are only available on Linux.")
            info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(info_label)

        layout.addWidget(self.exploit_results_output)
        return widget

    # --------------------------
    # HELPERS & TASKS
    # --------------------------
    def _browse_file(self, line_edit_widget, dialog_title):
        file_path, _ = QFileDialog.getOpenFileName(self, dialog_title, "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            line_edit_widget.setText(file_path)

    def _run_and_append_task(self, input_widget, async_function, output_widget):
        target = input_widget.text().strip()
        if not target:
            self.show_error("Please provide a target or query.")
            return
        output_widget.append(f"\n--- Running task on '{target}' ---\n")

        async def task_wrapper():
            result = await async_function(target)
            output_widget.append(result)
            output_widget.append("\n--- Task Finished ---")

        self.task_manager.create_task(task_wrapper())

    def on_run_nmap(self):
        target = self.nmap_target.text()
        if not target:
            self.show_error("Please provide a target for the Nmap scan.")
            return
        scan_type = self.nmap_scan_type.currentText()
        self.vuln_results_output.setText(f"Running Nmap '{scan_type}' on {target}...")

        async def task_wrapper():
            result = await self.security_tester.run_nmap_scan(target, scan_type)
            self.vuln_results_output.setText(result)

        self.task_manager.create_task(task_wrapper())

    def on_run_ddos(self):
        target = self.ddos_target.text()
        if not target:
            self.show_error("Please provide a target IP for the simulation.")
            return
        port = self.ddos_port.value()
        duration = self.ddos_duration.value()
        method = self.ddos_method.currentText()
        self.audit_results_output.setText(
            f"Starting {method} simulation against {target}:{port} for {duration} seconds."
        )

        async def task_wrapper():
            result = await self.security_tester.run_ddos_simulation(target, port, method, duration)
            self.audit_results_output.setText(result)

        self.task_manager.create_task(task_wrapper())

    def on_run_wifi(self):
        self.audit_results_output.setText("Scanning for WiFi networks.")

        async def task_wrapper():
            result = await self.security_tester.run_wifi_audit()
            self.audit_results_output.setText(result)

        self.task_manager.create_task(task_wrapper())

    def on_run_usb(self):
        self.audit_results_output.setText("Auditing USB devices.")

        async def task_wrapper():
            result = await self.security_tester.run_usb_audit()
            self.audit_results_output.setText(result)

        self.task_manager.create_task(task_wrapper())

    def on_run_hydra(self):
        target = self.hydra_target.text()
        service = self.hydra_service.text()
        userlist = self.hydra_userlist.text()
        passlist = self.hydra_passlist.text()
        if not all([target, service, userlist, passlist]):
            self.show_error("Please fill in all Hydra fields.")
            return
        self.exploit_results_output.setText(f"Running Hydra against {target} ({service})...")

        async def task_wrapper():
            result = await self.security_tester.run_hydra_brute_force(target, service, userlist, passlist)
            self.exploit_results_output.setText(result)

        self.task_manager.create_task(task_wrapper())
