# -*- coding: utf-8 -*-
import asyncio
import platform
import shutil
from PySide6.QtWidgets import (
    QGridLayout, QLineEdit, QComboBox, QPushButton,
    QPlainTextEdit, QLabel, QInputDialog, QGroupBox, QHBoxLayout
)
from PySide6.QtCore import Qt
from app.widgets.base_widget import BaseToolWidget
from app.core.app_logger import activity_logger

class DiagnosticsWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.os_name = platform.system().lower()
        self._define_commands()
        
        layout = QGridLayout(self)
        
        # --- Command Selection Group ---
        cmd_group = QGroupBox("Pre-defined Commands")
        cmd_layout = QGridLayout(cmd_group)
        self.target_input = QLineEdit()
        self.command_combo = QComboBox()
        self.run_button = QPushButton("Run Command")
        
        cmd_layout.addWidget(QLabel("Command:"), 0, 0)
        cmd_layout.addWidget(self.command_combo, 0, 1)
        cmd_layout.addWidget(QLabel("Target / Argument:"), 1, 0)
        cmd_layout.addWidget(self.target_input, 1, 1)
        
        # --- Output and Controls ---
        self.output_box = QPlainTextEdit()
        self.output_box.setReadOnly(True)
        self.copy_log_button = QPushButton("Copy Log")
        
        # --- Quick Actions Group ---
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions_group)
        self.flush_dns_btn = QPushButton("Flush DNS Cache")
        self.reset_tcp_btn = QPushButton("Reset TCP/IP Stack")
        actions_layout.addWidget(self.flush_dns_btn)
        actions_layout.addWidget(self.reset_tcp_btn)
        
        # --- Add widgets to main layout ---
        layout.addWidget(cmd_group, 0, 0, 2, 1)
        layout.addWidget(self.run_button, 0, 1)
        layout.addWidget(actions_group, 1, 1)
        layout.addWidget(self.output_box, 2, 0, 1, 2)
        layout.addWidget(self.copy_log_button, 3, 0, 1, 2, Qt.AlignmentFlag.AlignRight)
        
        self.setLayout(layout)
        
        self.populate_commands()
        self.command_combo.currentTextChanged.connect(self.on_command_change)
        self.run_button.clicked.connect(self._start_command)
        self.flush_dns_btn.clicked.connect(self._run_flush_dns)
        self.reset_tcp_btn.clicked.connect(self._run_reset_tcp)
        self.copy_log_button.clicked.connect(lambda: self.copy_to_clipboard(self.output_box.toPlainText()))
        
        self.load_state()
        self.on_command_change(self.command_combo.currentText())

    def _define_commands(self):
        """Defines a comprehensive, platform-aware list of network commands."""
        # Lambdas take one argument 't' for target/parameter
        self.COMMANDS = {
            # --- Manual Command ---
            "Manual Command": (lambda t: t.split(), True, [], "Enter the full command to run"),

            # === CONNECTIVITY & PATH ANALYSIS ===
            "Connectivity: Ping": (lambda t: (["ping", "-c", "4"] if self.os_name != "windows" else ["ping", "-n", "4"]) + [t], True, [], None),
            "Connectivity: Continuous Ping": (lambda t: (["ping"] if self.os_name != "windows" else ["ping", "-t"]) + [t], True, [], None),
            "Connectivity: Traceroute": (lambda t: (["tracert"] if self.os_name == "windows" else ["traceroute"]) + [t], True, [], None),
            "Connectivity: PathPing (Windows)": (lambda t: ["pathping", t], True, ["windows"], None),
            "Connectivity: MTR (Linux/macOS)": (lambda t: ["mtr", t], True, ["linux", "darwin"], None),
            
            # === INTERFACE & IP CONFIGURATION ===
            "Interface: IP Configuration Details": (lambda _: ["ipconfig", "/all"] if self.os_name == "windows" else ["ifconfig", "-a"], False, [], None),
            "Interface: Modern IP Details (Linux)": (lambda _: ["ip", "addr"], False, ["linux"], None),
            "Interface: NetworkSetup Details (macOS)": (lambda t: ["networksetup", "-getinfo", t], True, ["darwin"], "Enter Network Service (e.g., Wi-Fi)"),
            
            # === NETWORK STATE TABLES ===
            "Tables: ARP Cache": (lambda _: ["arp", "-a"], False, [], None),
            "Tables: Routing Table": (lambda _: ["route", "print"] if self.os_name == "windows" else ["netstat", "-nr"], False, [], None),
            "Tables: Modern Routing Table (Linux)": (lambda _: ["ip", "route"], False, ["linux"], None),
            
            # === ACTIVE CONNECTIONS & SOCKETS ===
            "Connections: Netstat (All + PID)": (lambda _: ["netstat", "-ano"], False, ["windows"], None),
            "Connections: Netstat (TCP/UDP + Program)": (lambda _: ["netstat", "-antup"], False, ["linux"], None),
            "Connections: Netstat (Verbose) (macOS)": (lambda _: ["netstat", "-anv"], False, ["darwin"], None),
            "Connections: Modern Socket Stats (Linux)": (lambda _: ["ss", "-tulnp"], False, ["linux"], None),
            "Connections: List Open Files by Port": (lambda p: ["lsof", f"-i:{p}"], True, ["linux", "darwin"], "Enter port (e.g., :443)"),

            # === DNS & NAME RESOLUTION ===
            "DNS: NSLookup": (lambda t: ["nslookup", t], True, [], None),
            "DNS: Dig (Advanced)": (lambda t: ["dig", t, "+all"], True, ["linux", "darwin"], None),
            "DNS: Host (Simple)": (lambda t: ["host", "-a", t], True, ["linux", "darwin"], None),
            "DNS: Show Local Cache (Windows)": (lambda _: ["ipconfig", "/displaydns"], False, ["windows"], None),
            "DNS: Show Resolver Info (macOS)": (lambda _: ["scutil", "--dns"], False, ["darwin"], None),
            
            # === WIRELESS NETWORKING ===
            "Wireless: Show Interfaces (Windows)": (lambda _: ["netsh", "wlan", "show", "interfaces"], False, ["windows"], None),
            "Wireless: Scan Networks (Windows)": (lambda _: ["netsh", "wlan", "show", "networks", "mode=bssid"], False, ["windows"], None),
            "Wireless: Scan Networks (macOS)": (lambda _: ["/System/Library/PrivateFrameworks/Apple8O211.framework/Versions/Current/Resources/airport", "-s"], False, ["darwin"], None),
            "Wireless: Show Config (Linux)": (lambda _: ["iwconfig"], False, ["linux"], None),
            
            # === FIREWALL ===
            "Firewall: Show All Rules (Windows)": (lambda _: ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], False, ["windows"], None),
            "Firewall: Show Rules (iptables) (Linux)": (lambda _: ["iptables", "-L", "-v", "-n"], False, ["linux"], None),
            "Firewall: Show Rules (pfctl) (macOS)": (lambda _: ["pfctl", "-s", "rules"], False, ["darwin"], None),
        }

    def populate_commands(self):
        self.command_combo.clear()
        
        # Group commands for readability in the dropdown
        groups = {}
        for name, cmd_data in self.COMMANDS.items():
            if not cmd_data[2] or self.os_name in cmd_data[2]:
                group = name.split(':')[0]
                if group not in groups:
                    groups[group] = []
                groups[group].append(name)
        
        # Add items grouped by category
        for group_name in sorted(groups.keys()):
            # Add a non-selectable group header
            self.command_combo.addItem(f"--- {group_name} ---")
            header_item = self.command_combo.model().item(self.command_combo.count() - 1)
            header_item.setEnabled(False)
            
            # Add the commands for that group
            for cmd_name in sorted(groups[group_name]):
                self.command_combo.addItem(cmd_name)

    def on_command_change(self, cmd_name):
        if not cmd_name or "---" in cmd_name:
            self.run_button.setEnabled(False)
            return
            
        self.run_button.setEnabled(True)
        _, needs_target, _, prompt = self.COMMANDS[cmd_name]
        self.target_input.setEnabled(needs_target or bool(prompt))
        self.target_input.setPlaceholderText(prompt if prompt else "e.g., google.com or 1.1.1.1")

    def _start_command(self):
        cmd_name = self.command_combo.currentText()
        target = self.target_input.text().strip()
        
        if not cmd_name or "---" in cmd_name: return
        
        builder, _, _, prompt = self.COMMANDS[cmd_name]
        arg = target
        
        if cmd_name == "Manual Command" and not target:
            self.show_error("Please enter a command to run.")
            return

        if prompt and cmd_name != "Manual Command":
            arg, ok = QInputDialog.getText(self, "Additional Input", prompt, text=target)
            if not ok: return
        
        self._execute_command(builder(arg), f"{cmd_name} on '{arg}'" if arg else cmd_name)

    def _run_flush_dns(self):
        cmd_map = {
            "windows": ["ipconfig", "/flushdns"],
            "linux": ["sudo", "systemd-resolve", "--flush-caches"],
            "darwin": ["sudo", "killall", "-HUP", "mDNSResponder"]
        }
        cmd = cmd_map.get(self.os_name)
        if cmd:
            self._execute_command(cmd, "Flush DNS")
        else:
            self.show_error("Flush DNS is not configured for this OS.")

    def _run_reset_tcp(self):
        cmd_map = {
            "windows": ["netsh", "int", "ip", "reset"],
        }
        cmd = cmd_map.get(self.os_name)
        if cmd:
            QMessageBox.warning(self, "Admin privileges required", 
                "This action requires running the application as an administrator and may require a reboot. The command will be generated for you to run manually.")
            self.output_box.clear()
            self.output_box.appendPlainText(f"--- Please run the following command in an administrative terminal: ---\n\n{' '.join(cmd)}")
        else:
            self.show_error("Reset TCP/IP is not applicable or configured for this OS.")

    def _execute_command(self, cmd: list, log_name: str):
        if not shutil.which(cmd[0]):
            self.show_error(f"Command '{cmd[0]}' not found. Please ensure it is installed and in your system's PATH.")
            return

        activity_logger.log("Diagnostic Command Run", log_name)
        self.run_button.setEnabled(False)
        self.output_box.clear()
        self.output_box.appendPlainText(f"--- Running: {' '.join(cmd)} ---\n")
        self.task_manager.create_task(self._stream_command(cmd))

    async def _stream_command(self, cmd):
        try:
            async for line in self.network_tools.run_diagnostic_command(cmd):
                self.output_box.appendPlainText(line)
        except asyncio.CancelledError:
            self.output_box.appendPlainText("\n--- Task Canceled ---")
        finally:
            if self and self.output_box:
                self.output_box.appendPlainText(f"\n--- Command finished ---")
                self.run_button.setEnabled(True)

    def load_state(self):
        self.target_input.setText(self.settings.value("diagnostics/target", "google.com"))

    def save_state(self):
        self.settings.setValue("diagnostics/target", self.target_input.text())