# app/advanced_features/blue_team_widget.py
from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QPlainTextEdit, QFileDialog, QTabWidget
)
from PySide6.QtCore import Qt
from app.core.blueteam.log_analyzer import analyze_log, format_report as format_log_report
from app.core.blueteam.pcap_inspector import summarize_pcap, format_report as format_pcap_report
from app.core.neteng.config_audit import audit_config, format_report as format_cfg_report

class BlueTeamWidget(QWidget):
    """
    Enterprise-safe blue team station: log triage, pcap summary, and offline config audit.
    """
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.task_manager = task_manager

        self.tabs = QTabWidget(self)

        # LOG TAB
        log_tab = QWidget(self)
        log_layout = QVBoxLayout(log_tab)
        row = QHBoxLayout()
        self.log_path = QLineEdit(self)
        self.log_path.setPlaceholderText("/var/log/syslog")
        btn_browse_log = QPushButton("Browse…", self)
        btn_analyze_log = QPushButton("Analyze", self)
        row.addWidget(QLabel("Log file:"))
        row.addWidget(self.log_path)
        row.addWidget(btn_browse_log)
        row.addWidget(btn_analyze_log)
        log_layout.addLayout(row)
        self.log_out = QPlainTextEdit(self)
        self.log_out.setReadOnly(True)
        log_layout.addWidget(self.log_out)

        btn_browse_log.clicked.connect(self._pick_log_file)
        btn_analyze_log.clicked.connect(self._run_log_analyze)

        # PCAP TAB
        pcap_tab = QWidget(self)
        pcap_layout = QVBoxLayout(pcap_tab)
        row2 = QHBoxLayout()
        self.pcap_path = QLineEdit(self)
        self.pcap_path.setPlaceholderText("/path/to/traffic.pcap")
        btn_browse_pcap = QPushButton("Browse…", self)
        btn_analyze_pcap = QPushButton("Summarize", self)
        row2.addWidget(QLabel("PCAP file:"))
        row2.addWidget(self.pcap_path)
        row2.addWidget(btn_browse_pcap)
        row2.addWidget(btn_analyze_pcap)
        pcap_layout.addLayout(row2)
        self.pcap_out = QPlainTextEdit(self)
        self.pcap_out.setReadOnly(True)
        pcap_layout.addWidget(self.pcap_out)

        btn_browse_pcap.clicked.connect(self._pick_pcap_file)
        btn_analyze_pcap.clicked.connect(self._run_pcap_summary)

        # CONFIG AUDIT TAB
        cfg_tab = QWidget(self)
        cfg_layout = QVBoxLayout(cfg_tab)
        row3 = QHBoxLayout()
        self.cfg_path = QLineEdit(self)
        self.cfg_path.setPlaceholderText("/path/to/router_config.txt")
        btn_browse_cfg = QPushButton("Browse…", self)
        btn_audit_cfg = QPushButton("Audit", self)
        row3.addWidget(QLabel("Config file:"))
        row3.addWidget(self.cfg_path)
        row3.addWidget(btn_browse_cfg)
        row3.addWidget(btn_audit_cfg)
        cfg_layout.addLayout(row3)
        self.cfg_out = QPlainTextEdit(self)
        self.cfg_out.setReadOnly(True)
        cfg_layout.addWidget(self.cfg_out)

        btn_browse_cfg.clicked.connect(self._pick_cfg_file)
        btn_audit_cfg.clicked.connect(self._run_cfg_audit)

        # assemble
        self.tabs.addTab(log_tab, "📜 Log Analyzer")
        self.tabs.addTab(pcap_tab, "🧪 PCAP Inspector")
        self.tabs.addTab(cfg_tab, "🧰 Config Audit")

        root = QVBoxLayout(self)
        root.addWidget(self.tabs)

    # ---- slots
    def _pick_log_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select log file", "", "Text files (*.log *.txt *);;All files (*)")
        if f: self.log_path.setText(f)

    def _run_log_analyze(self):
        path = self.log_path.text().strip()
        if not path:
            self.log_out.setPlainText("Please choose a log file.")
            return
        try:
            with open(path, "r", errors="ignore") as fh:
                stats = analyze_log(fh)
            self.log_out.setPlainText(format_log_report(stats))
        except Exception as e:
            self.log_out.setPlainText(f"Error: {e}")

    def _pick_pcap_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select PCAP file", "", "PCAP files (*.pcap *.pcapng);;All files (*)")
        if f: self.pcap_path.setText(f)

    def _run_pcap_summary(self):
        path = self.pcap_path.text().strip()
        if not path:
            self.pcap_out.setPlainText("Please choose a PCAP file.")
            return
        try:
            stats = summarize_pcap(path)
            self.pcap_out.setPlainText(format_pcap_report(stats))
        except Exception as e:
            self.pcap_out.setPlainText(f"Error: {e}")

    def _pick_cfg_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select network config", "", "Text files (*.txt *.cfg *);;All files (*)")
        if f: self.cfg_path.setText(f)

    def _run_cfg_audit(self):
        path = self.cfg_path.text().strip()
        if not path:
            self.cfg_out.setPlainText("Please choose a config file.")
            return
        try:
            with open(path, "r", errors="ignore") as fh:
                text = fh.read()
            result = audit_config(text)
            self.cfg_out.setPlainText(format_cfg_report(result))
        except Exception as e:
            self.cfg_out.setPlainText(f"Error: {e}")
