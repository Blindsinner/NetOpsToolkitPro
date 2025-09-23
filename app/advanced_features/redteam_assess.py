# app/advanced_features/redteam_assess.py
from __future__ import annotations

from PySide6.QtCore import Qt, QSettings, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QWidget, QTabWidget, QVBoxLayout, QLabel, QFormLayout, QPushButton, QHBoxLayout,
    QLineEdit, QGroupBox, QGridLayout, QCheckBox, QSpinBox, QComboBox
)

from app.widgets.base_widget import BaseToolWidget
from app.assets.icon_manager import icon_manager

def _mask(val: str, last: int = 4) -> str:
    if not val:
        return "<span style='color:#999'>not set</span>"
    if len(val) <= last:
        return "•" * (last - len(val)) + val
    return "•" * (len(val) - last) + val[-last:]

# ---------------------------
# Panels
# ---------------------------

class ChainPanel(QWidget):
    run_requested = Signal(dict)
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent); self.settings = settings
        lay = QVBoxLayout(self); lay.setAlignment(Qt.AlignTop)
        lay.addWidget(QLabel("<b>Naabu → Nuclei Chain</b>"))
        desc = QLabel("Discovers open ports with Naabu and runs Nuclei templates on discovered HTTP(S) services.")
        desc.setWordWrap(True); lay.addWidget(desc)

        grid = QGridLayout()
        grid.addWidget(QLabel("Target (domain/IP/URL)"), 0, 0)
        self.ed_target = QLineEdit(); self.ed_target.setPlaceholderText("example.com / 1.2.3.4 / https://app.example.com")
        grid.addWidget(self.ed_target, 0, 1)

        grid.addWidget(QLabel("Naabu Rate"), 1, 0)
        self.ed_rate = QLineEdit("2000"); grid.addWidget(self.ed_rate, 1, 1)

        grid.addWidget(QLabel("Naabu Ports"), 2, 0)
        self.ed_ports = QLineEdit("top-1000"); grid.addWidget(self.ed_ports, 2, 1)

        grid.addWidget(QLabel("Nuclei Templates Dir"), 3, 0)
        self.ed_templates = QLineEdit(self.settings.value("scanner/nuclei_templates_path", ""))
        grid.addWidget(self.ed_templates, 3, 1)

        grid.addWidget(QLabel("Extra Nuclei Args"), 4, 0)
        self.ed_nuclei_extra = QLineEdit(""); self.ed_nuclei_extra.setPlaceholderText("-severity high,critical -rl 150")
        grid.addWidget(self.ed_nuclei_extra, 4, 1)

        self.cb_chain_https = QCheckBox("Only probe HTTP(S) services"); self.cb_chain_https.setChecked(True)
        grid.addWidget(self.cb_chain_https, 5, 1)

        lay.addLayout(grid)
        self.btn_run = QPushButton("Run Chain (Naabu → Nuclei)")
        lay.addWidget(self.btn_run, 0, Qt.AlignLeft)
        self.btn_run.clicked.connect(self._emit)

    def _emit(self):
        target = self.ed_target.text().strip()
        if not target:
            return
        job = {
            "type": "chain_naabu_nuclei",
            "target": target,
            "naabu_rate": self.ed_rate.text().strip() or "2000",
            "naabu_ports": self.ed_ports.text().strip() or "top-1000",
            "only_http": self.cb_chain_https.isChecked(),
            "nuclei_templates": self.ed_templates.text().strip(),
            "nuclei_extra": self.ed_nuclei_extra.text().strip(),
        }
        self.run_requested.emit(job)

    def update_icons(self, color: QColor):
        self.btn_run.setIcon(icon_manager.get_icon("play", color))

class NaabuPanel(QWidget):
    run_requested = Signal(dict)
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self); lay.setAlignment(Qt.AlignTop)
        lay.addWidget(QLabel("<b>Naabu (Standalone)</b>"))

        grid = QGridLayout()
        grid.addWidget(QLabel("Target (domain/IP)"), 0, 0)
        self.ed_target = QLineEdit(); self.ed_target.setPlaceholderText("example.com / 1.2.3.4")
        grid.addWidget(self.ed_target, 0, 1)

        grid.addWidget(QLabel("Ports"), 1, 0)
        self.ed_ports = QLineEdit("top-1000"); grid.addWidget(self.ed_ports, 1, 1)

        grid.addWidget(QLabel("Rate"), 2, 0)
        self.ed_rate = QLineEdit("2000"); grid.addWidget(self.ed_rate, 2, 1)

        self.cb_http_probe = QCheckBox("Probe HTTP(S) services (-silent -json)")
        self.cb_http_probe.setChecked(True)
        grid.addWidget(self.cb_http_probe, 3, 1)

        lay.addLayout(grid)
        self.btn_run = QPushButton("Run Naabu"); lay.addWidget(self.btn_run, 0, Qt.AlignLeft)
        self.btn_run.clicked.connect(self._emit)

    def _emit(self):
        target = self.ed_target.text().strip()
        if not target:
            return
        job = {
            "type": "naabu",
            "target": target,
            "ports": self.ed_ports.text().strip(),
            "rate": self.ed_rate.text().strip(),
            "probe_http": self.cb_http_probe.isChecked(),
        }
        self.run_requested.emit(job)

    def update_icons(self, color: QColor):
        self.btn_run.setIcon(icon_manager.get_icon("bolt", color))

class NucleiPanel(QWidget):
    run_requested = Signal(dict)
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent); self.settings = settings
        lay = QVBoxLayout(self); lay.setAlignment(Qt.AlignTop)
        lay.addWidget(QLabel("<b>Nuclei (Standalone)</b>"))

        grid = QGridLayout()
        grid.addWidget(QLabel("Target/URLs file or single URL"), 0, 0)
        self.ed_target = QLineEdit(); self.ed_target.setPlaceholderText("https://example.com or /path/urls.txt")
        grid.addWidget(self.ed_target, 0, 1)

        grid.addWidget(QLabel("Templates Dir"), 1, 0)
        self.ed_templates = QLineEdit(self.settings.value("scanner/nuclei_templates_path", ""))  # fixed key
        grid.addWidget(self.ed_templates, 1, 1)

        grid.addWidget(QLabel("Extra Args"), 2, 0)
        self.ed_extra = QLineEdit("-severity medium,high,critical")
        grid.addWidget(self.ed_extra, 2, 1)

        lay.addLayout(grid)
        self.btn_run = QPushButton("Run Nuclei"); lay.addWidget(self.btn_run, 0, Qt.AlignLeft)
        self.btn_run.clicked.connect(self._emit)

    def _emit(self):
        tgt = self.ed_target.text().strip()
        if not tgt:
            return
        job = {"type": "nuclei", "input": tgt, "templates": self.ed_templates.text().strip(), "extra": self.ed_extra.text().strip()}
        self.run_requested.emit(job)

    def update_icons(self, color: QColor):
        self.btn_run.setIcon(icon_manager.get_icon("target", color))

class ZapPanel(QWidget):
    open_settings = Signal()
    run_requested = Signal(dict)
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent); self.settings = settings
        lay = QVBoxLayout(self); lay.setAlignment(Qt.AlignTop)
        lay.addWidget(QLabel("<b>OWASP ZAP</b>"))

        form = QFormLayout()
        host = self.settings.value("scanner/zap_api_host", "127.0.0.1")
        port = int(self.settings.value("scanner/zap_api_port", 8090))
        key  = self.settings.value("scanner/zap_api_key", "")
        lbl = QLabel(f"http://{host}:{port}  (key: {_mask(key)})"); lbl.setTextFormat(Qt.TextFormat.RichText)
        form.addRow("API:", lbl); lay.addLayout(form)

        gb = QGroupBox("Quick Actions"); gb_l = QFormLayout(gb)
        self.ed_url = QLineEdit(); self.ed_url.setPlaceholderText("https://target.example.com")
        self.cb_spider_then_ascan = QCheckBox("Spider then Active Scan"); self.cb_spider_then_ascan.setChecked(True)
        self.spider_max = QSpinBox(); self.spider_max.setRange(1, 100000); self.spider_max.setValue(300)
        self.ascan_pol = QComboBox(); self.ascan_pol.addItems(["Default", "API & OWASP Top 10", "Full"])
        gb_l.addRow("URL:", self.ed_url)
        gb_l.addRow("", self.cb_spider_then_ascan)
        gb_l.addRow("Spider Max Children:", self.spider_max)
        gb_l.addRow("Active Scan Policy:", self.ascan_pol)
        lay.addWidget(gb)

        row = QHBoxLayout()
        self.btn_kick = QPushButton("Start Scan"); row.addWidget(self.btn_kick)
        self.btn_to_settings = QPushButton("Manage ZAP Settings"); row.addWidget(self.btn_to_settings)
        row.addStretch(); lay.addLayout(row)

        self.btn_kick.clicked.connect(self._emit)
        self.btn_to_settings.clicked.connect(self.open_settings.emit)

    def _emit(self):
        url = self.ed_url.text().strip()
        if not url:
            return
        job = {
            "type": "zap_quick_scan",
            "url": url,
            "spider_first": self.cb_spider_then_ascan.isChecked(),
            "spider_max_children": self.spider_max.value(),
            "ascan_policy": self.ascan_pol.currentText(),
        }
        self.run_requested.emit(job)

    def update_icons(self, color: QColor):
        self.btn_kick.setIcon(icon_manager.get_icon("play", color))
        self.btn_to_settings.setIcon(icon_manager.get_icon("settings", color))

class AmassPanel(QWidget):
    run_requested = Signal(dict)
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent); self.settings = settings
        lay = QVBoxLayout(self); lay.setAlignment(Qt.AlignTop)
        lay.addWidget(QLabel("<b>Amass</b>"))

        grid = QGridLayout()
        grid.addWidget(QLabel("Domain"), 0, 0)
        self.ed_domain = QLineEdit(); self.ed_domain.setPlaceholderText("example.com")
        grid.addWidget(self.ed_domain, 0, 1)

        self.cb_enum = QCheckBox("Enum"); self.cb_enum.setChecked(True)
        self.cb_brute = QCheckBox("Brute"); self.cb_brute.setChecked(False)
        self.cb_passive = QCheckBox("Passive"); self.cb_passive.setChecked(True)
        grid.addWidget(self.cb_enum, 1, 1); grid.addWidget(self.cb_brute, 2, 1); grid.addWidget(self.cb_passive, 3, 1)

        lay.addLayout(grid)
        self.btn_run = QPushButton("Run Amass"); lay.addWidget(self.btn_run, 0, Qt.AlignLeft)
        self.btn_run.clicked.connect(self._emit)

    def _emit(self):
        domain = self.ed_domain.text().strip()
        if not domain:
            return
        job = {
            "type": "amass",
            "domain": domain,
            "enum": self.cb_enum.isChecked(),
            "brute": self.cb_brute.isChecked(),
            "passive": self.cb_passive.isChecked(),
            "config": self.settings.value("scanner/amass_config_path", ""),
        }
        self.run_requested.emit(job)

    def update_icons(self, color: QColor):
        self.btn_run.setIcon(icon_manager.get_icon("search", color))

class IntelPanel(QWidget):
    open_settings = Signal()
    run_requested = Signal(dict)
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent); self.settings = settings
        lay = QVBoxLayout(self); lay.setAlignment(Qt.AlignTop)
        lay.addWidget(QLabel("<b>External Intelligence</b>"))

        shodan_key = self.settings.value("security/shodan_api_key", "")
        censys_id = self.settings.value("security/censys_api_id", "")
        censys_secret = self.settings.value("security/censys_api_secret", "")
        creds = QLabel(f"Shodan: {_mask(shodan_key)} &nbsp;&nbsp; Censys: {censys_id or '<i>not set</i>'} / {_mask(censys_secret)}")
        creds.setTextFormat(Qt.TextFormat.RichText); lay.addWidget(creds)

        gb = QGroupBox("Query"); gb_l = QFormLayout(gb)
        self.combo = QComboBox(); self.combo.addItems(["Shodan", "Censys Hosts", "Censys Certificates"])
        self.ed_query = QLineEdit(); self.ed_query.setPlaceholderText('Example: org:"Target Corp" port:443')
        gb_l.addRow("Engine:", self.combo); gb_l.addRow("Query:", self.ed_query)
        lay.addWidget(gb)

        row = QHBoxLayout()
        self.btn_search = QPushButton("Search"); row.addWidget(self.btn_search)
        self.btn_settings = QPushButton("Manage API Keys"); row.addWidget(self.btn_settings)
        row.addStretch(); lay.addLayout(row)

        self.btn_settings.clicked.connect(self.open_settings.emit)
        self.btn_search.clicked.connect(self._emit)

    def _emit(self):
        q = self.ed_query.text().strip()
        if not q:
            return
        engine = self.combo.currentText()
        self.run_requested.emit({"type": "intel_search", "engine": engine, "query": q})

    def update_icons(self, color: QColor):
        self.btn_search.setIcon(icon_manager.get_icon("search", color))
        self.btn_settings.setIcon(icon_manager.get_icon("settings", color))

class WebTechPanel(QWidget):
    run_requested = Signal(dict)
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self); lay.setAlignment(Qt.AlignTop)
        lay.addWidget(QLabel("<b>Web Technology Fingerprint (Wappalyzer)</b>"))
        form = QFormLayout()
        self.ed_url = QLineEdit(); self.ed_url.setPlaceholderText("https://www.example.com")
        form.addRow("URL:", self.ed_url); lay.addLayout(form)
        self.btn_run = QPushButton("Analyze"); lay.addWidget(self.btn_run, 0, Qt.AlignLeft)
        self.btn_run.clicked.connect(self._emit)

    def _emit(self):
        url = self.ed_url.text().strip()
        if not url:
            return
        self.run_requested.emit({"type": "wappalyzer", "url": url})

    def update_icons(self, color: QColor):
        self.btn_run.setIcon(icon_manager.get_icon("insights", color))

class OpenVASPanel(QWidget):
    run_requested = Signal(dict)
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self); lay.setAlignment(Qt.AlignTop)
        lay.addWidget(QLabel("<b>Greenbone / OpenVAS</b>"))
        hint = QLabel("Requires local GVM setup (gvm-setup, gvm-start). This panel queues simple scans via gvm-tools.")
        hint.setWordWrap(True); lay.addWidget(hint)

        grid = QGridLayout()
        grid.addWidget(QLabel("Target (IP/Host)"), 0, 0)
        self.ed_target = QLineEdit(); grid.addWidget(self.ed_target, 0, 1)
        grid.addWidget(QLabel("Task Name"), 1, 0)
        self.ed_task = QLineEdit("Quick scan"); grid.addWidget(self.ed_task, 1, 1)

        lay.addLayout(grid)
        self.btn_run = QPushButton("Create & Run Task"); lay.addWidget(self.btn_run, 0, Qt.AlignLeft)
        self.btn_run.clicked.connect(self._emit)

    def _emit(self):
        target = self.ed_target.text().strip()
        if not target:
            return
        self.run_requested.emit({"type": "openvas_quick", "target": target, "task_name": self.ed_task.text().strip() or "Quick scan"})

    def update_icons(self, color: QColor):
        self.btn_run.setIcon(icon_manager.get_icon("shield", color))

class ProwlerPanel(QWidget):
    run_requested = Signal(dict)
    open_settings = Signal()
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent); self.settings = settings
        lay = QVBoxLayout(self); lay.setAlignment(Qt.AlignTop)
        lay.addWidget(QLabel("<b>Prowler (AWS)</b>"))

        form = QFormLayout()
        self.ed_profile = QLineEdit("default")
        self.ed_regions = QLineEdit("us-east-1,us-west-2")
        self.ed_services = QLineEdit("iam,ec2,s3,rds,cloudtrail,eks")
        self.ed_output = QLineEdit("prowler-output")
        self.cb_html = QCheckBox("Generate HTML report"); self.cb_html.setChecked(True)
        self.cb_csv = QCheckBox("Generate CSV"); self.cb_csv.setChecked(True)
        form.addRow("AWS Profile:", self.ed_profile)
        form.addRow("Regions (comma):", self.ed_regions)
        form.addRow("Services (comma):", self.ed_services)
        form.addRow("Output Directory:", self.ed_output)
        form.addRow("", self.cb_html); form.addRow("", self.cb_csv)
        lay.addLayout(form)

        row = QHBoxLayout()
        self.btn_run = QPushButton("Run Prowler"); row.addWidget(self.btn_run)
        self.btn_env = QPushButton("AWS Credentials Help"); row.addWidget(self.btn_env)
        row.addStretch(); lay.addLayout(row)

        self.btn_run.clicked.connect(self._emit)
        self.btn_env.clicked.connect(self.open_settings.emit)

    def _emit(self):
        self.run_requested.emit({
            "type": "prowler_aws",
            "profile": self.ed_profile.text().strip() or "default",
            "regions": [r.strip() for r in self.ed_regions.text().split(",") if r.strip()],
            "services": [s.strip() for s in self.ed_services.text().split(",") if s.strip()],
            "output_dir": self.ed_output.text().strip() or "prowler-output",
            "html": self.cb_html.isChecked(),
            "csv": self.cb_csv.isChecked(),
        })

    def update_icons(self, color: QColor):
        self.btn_run.setIcon(icon_manager.get_icon("play", color))
        self.btn_env.setIcon(icon_manager.get_icon("help", color))

# ---------------------------
# Main widget
# ---------------------------

class RedTeamAssessWidget(BaseToolWidget):
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(settings, task_manager, parent)
        self.tabs = QTabWidget(self)
        outer = QVBoxLayout(self); outer.setContentsMargins(0, 0, 0, 0); outer.addWidget(self.tabs)

        self.p_chain   = ChainPanel(self.settings)
        self.p_naabu   = NaabuPanel()
        self.p_nuclei  = NucleiPanel(self.settings)
        self.p_zap     = ZapPanel(self.settings)
        self.p_amass   = AmassPanel(self.settings)
        self.p_intel   = IntelPanel(self.settings)
        self.p_webtech = WebTechPanel()
        self.p_openvas = OpenVASPanel()
        self.p_prowler = ProwlerPanel(self.settings)

        self.tabs.addTab(self.p_chain, "Chain (Naabu→Nuclei)")
        self.tabs.addTab(self.p_naabu, "Naabu")
        self.tabs.addTab(self.p_nuclei, "Nuclei")
        self.tabs.addTab(self.p_zap, "ZAP")
        self.tabs.addTab(self.p_amass, "Amass")
        self.tabs.addTab(self.p_intel, "External Intel")
        self.tabs.addTab(self.p_webtech, "Web Tech")
        self.tabs.addTab(self.p_openvas, "OpenVAS")
        self.tabs.addTab(self.p_prowler, "Prowler (AWS)")

        for panel in [self.p_chain, self.p_naabu, self.p_nuclei, self.p_zap, self.p_amass, self.p_intel, self.p_webtech, self.p_openvas, self.p_prowler]:
            panel.run_requested.connect(self._submit_job)
        for panel in [self.p_zap, self.p_intel, self.p_prowler]:
            panel.open_settings.connect(self._go_settings)

    def _submit_job(self, job: dict):
        self.task_manager.submit(job)
        self.show_info(f"Queued: {job.get('type','task')}. See output pane for progress.")

    def _go_settings(self):
        try:
            main_win = self.window()
            if hasattr(main_win, "nav_bar"):
                for i in range(main_win.nav_bar.count()):
                    if main_win.nav_bar.item(i).text().strip().lower() == "settings":
                        main_win.nav_bar.setCurrentRow(i); break
        except Exception:
            pass

    def update_icons(self, color: QColor):
        self.tabs.setTabIcon(0, icon_manager.get_icon("bolt", color))
        self.tabs.setTabIcon(1, icon_manager.get_icon("bolt", color))
        self.tabs.setTabIcon(2, icon_manager.get_icon("target", color))
        self.tabs.setTabIcon(3, icon_manager.get_icon("security", color))
        self.tabs.setTabIcon(4, icon_manager.get_icon("search", color))
        self.tabs.setTabIcon(5, icon_manager.get_icon("insights", color))
        self.tabs.setTabIcon(6, icon_manager.get_icon("insights", color))
        self.tabs.setTabIcon(7, icon_manager.get_icon("shield", color))
        self.tabs.setTabIcon(8, icon_manager.get_icon("cloud", color))

        self.p_chain.update_icons(color); self.p_naabu.update_icons(color); self.p_nuclei.update_icons(color)
        self.p_zap.update_icons(color); self.p_amass.update_icons(color); self.p_intel.update_icons(color)
        self.p_webtech.update_icons(color); self.p_openvas.update_icons(color); self.p_prowler.update_icons(color)

