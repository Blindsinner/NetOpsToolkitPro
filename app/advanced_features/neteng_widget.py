from __future__ import annotations
import ipaddress
import shutil
import subprocess
from typing import Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QPlainTextEdit, QTabWidget, QMessageBox
)
from PySide6.QtCore import Qt

def _which_or_warn(parent: QWidget, name: str) -> Optional[str]:
    path = shutil.which(name)
    if not path:
        QMessageBox.warning(parent, "Missing tool", f"'{name}' not found in PATH.")
    return path

class NetEngWidget(QWidget):
    """
    Handy NetEng station: ping, traceroute, port check, and subnet math.
    Uses system tools (ping/traceroute) and stdlib only.
    """
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.task_manager = task_manager

        self.tabs = QTabWidget(self)

        # PING TAB
        ping_tab = QWidget(self)
        ping_layout = QVBoxLayout(ping_tab)
        row = QHBoxLayout()
        self.ping_host = QLineEdit(self)
        self.ping_host.setPlaceholderText("8.8.8.8")
        btn_ping = QPushButton("Ping", self)
        row.addWidget(QLabel("Host:"))
        row.addWidget(self.ping_host)
        row.addWidget(btn_ping)
        ping_layout.addLayout(row)
        self.ping_out = QPlainTextEdit(self); self.ping_out.setReadOnly(True)
        ping_layout.addWidget(self.ping_out)
        btn_ping.clicked.connect(self._run_ping)

        # TRACEROUTE TAB
        tr_tab = QWidget(self)
        tr_layout = QVBoxLayout(tr_tab)
        row2 = QHBoxLayout()
        self.tr_host = QLineEdit(self)
        self.tr_host.setPlaceholderText("1.1.1.1")
        btn_tr = QPushButton("Traceroute", self)
        row2.addWidget(QLabel("Host:"))
        row2.addWidget(self.tr_host)
        row2.addWidget(btn_tr)
        tr_layout.addLayout(row2)
        self.tr_out = QPlainTextEdit(self); self.tr_out.setReadOnly(True)
        tr_layout.addWidget(self.tr_out)
        btn_tr.clicked.connect(self._run_traceroute)

        # PORT CHECK TAB (TCP connect)
        port_tab = QWidget(self)
        port_layout = QVBoxLayout(port_tab)
        row3 = QHBoxLayout()
        self.port_host = QLineEdit(self); self.port_host.setPlaceholderText("example.com")
        self.port_num = QLineEdit(self); self.port_num.setPlaceholderText("443")
        btn_port = QPushButton("Check", self)
        row3.addWidget(QLabel("Host:")); row3.addWidget(self.port_host)
        row3.addWidget(QLabel("Port:")); row3.addWidget(self.port_num)
        row3.addWidget(btn_port)
        port_layout.addLayout(row3)
        self.port_out = QPlainTextEdit(self); self.port_out.setReadOnly(True)
        port_layout.addWidget(self.port_out)
        btn_port.clicked.connect(self._run_portcheck)

        # SUBNET TAB
        net_tab = QWidget(self)
        net_layout = QVBoxLayout(net_tab)
        row4 = QHBoxLayout()
        self.subnet_cidr = QLineEdit(self); self.subnet_cidr.setPlaceholderText("10.0.0.0/24")
        btn_calc = QPushButton("Calculate", self)
        row4.addWidget(QLabel("CIDR:")); row4.addWidget(self.subnet_cidr); row4.addWidget(btn_calc)
        net_layout.addLayout(row4)
        self.subnet_out = QPlainTextEdit(self); self.subnet_out.setReadOnly(True)
        net_layout.addWidget(self.subnet_out)
        btn_calc.clicked.connect(self._run_subnet)

        # assemble
        self.tabs.addTab(ping_tab, "📶 Ping")
        self.tabs.addTab(tr_tab, "🧭 Traceroute")
        self.tabs.addTab(port_tab, "🔌 Port Check")
        self.tabs.addTab(net_tab, "🧮 Subnet Calc")

        root = QVBoxLayout(self)
        root.addWidget(self.tabs)

    # ----- runners
    def _run_ping(self):
        host = (self.ping_host.text() or "").strip()
        if not host:
            self.ping_out.setPlainText("Enter a host.")
            return
        ping = _which_or_warn(self, "ping")
        if not ping: return
        try:
            # Use 4 echo requests; -n numeric; -W timeout (sec) varies; Kali ping uses -w deadline
            proc = subprocess.run([ping, "-c", "4", "-n", host],
                                  text=True, capture_output=True, timeout=30)
            self.ping_out.setPlainText(proc.stdout or proc.stderr)
        except Exception as e:
            self.ping_out.setPlainText(f"Error: {e}")

    def _run_traceroute(self):
        host = (self.tr_host.text() or "").strip()
        if not host:
            self.tr_out.setPlainText("Enter a host.")
            return
        tr = _which_or_warn(self, "traceroute")
        if not tr: return
        try:
            proc = subprocess.run([tr, "-n", host],
                                  text=True, capture_output=True, timeout=120)
            self.tr_out.setPlainText(proc.stdout or proc.stderr)
        except Exception as e:
            self.tr_out.setPlainText(f"Error: {e}")

    def _run_portcheck(self):
        import socket
        host = (self.port_host.text() or "").strip()
        port = (self.port_num.text() or "").strip()
        if not host or not port:
            self.port_out.setPlainText("Enter host and port.")
            return
        try:
            port_i = int(port)
            with socket.create_connection((host, port_i), timeout=5) as s:
                self.port_out.setPlainText(f"SUCCESS: TCP connect to {host}:{port_i}")
        except Exception as e:
            self.port_out.setPlainText(f"FAIL: {e}")

    def _run_subnet(self):
        cidr = (self.subnet_cidr.text() or "").strip()
        if not cidr:
            self.subnet_out.setPlainText("Enter CIDR like 10.0.0.0/24")
            return
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            lines = [
                f"Network:   {net.network_address}",
                f"Broadcast: {net.broadcast_address}",
                f"Netmask:   {net.netmask}",
                f"Hosts:     {net.num_addresses}",
                f"Usable:    {max(0, net.num_addresses - (2 if net.version == 4 and net.num_addresses>=2 else 0))}",
                "",
                "First 10 hosts:"
            ]
            hosts = list(net.hosts())
            for h in hosts[:10]:
                lines.append(f"  - {h}")
            self.subnet_out.setPlainText("\n".join(lines))
        except Exception as e:
            self.subnet_out.setPlainText(f"Error: {e}")
