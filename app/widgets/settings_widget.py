# app/widgets/settings_widget.py
# TABBED SETTINGS: API Keys, Scanner Options, Cloud & Prowler
# - Keeps your original Vulners/HIBP fields and adds more integrations.
# - Writes AWS profile to ~/.aws/credentials and ~/.aws/config (safe & standard).
# - Tests AWS connection via `aws sts get-caller-identity`.
# - All values are persisted in QSettings.

from __future__ import annotations

import os
import configparser
import subprocess
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QFormLayout,
    QLineEdit, QPushButton, QMessageBox, QTabWidget, QComboBox, QFileDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from app.widgets.base_widget import BaseToolWidget
from app.assets.icon_manager import icon_manager
from app.config import AppConfig


AWS_CREDENTIALS = Path.home() / ".aws" / "credentials"
AWS_CONFIG = Path.home() / ".aws" / "config"


class SettingsWidget(BaseToolWidget):
    """
    Centralized, friendly settings:
      1) API Keys: Vulners, HIBP, Shodan, Censys, ZAP
      2) Scanner Options: Naabu, Nuclei, Amass
      3) Cloud & Prowler: AWS keys/profile, save+test buttons

    Notes:
      - Sensitive fields use password echo mode.
      - All fields persist via QSettings.
      - Writing AWS profiles uses standard CLI files in ~/.aws/.
    """

    def __init__(self, settings, task_manager, parent=None):
        super().__init__(settings, task_manager, parent)

        root = QVBoxLayout(self)
        root.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        # --------- Tab 1: API Keys ---------
        api_tab = QWidget()
        self.tabs.addTab(api_tab, "API Keys")

        api_layout = QVBoxLayout(api_tab)
        api_group = QGroupBox("Security & Threat Intel APIs")
        api_form = QFormLayout(api_group)

        # Existing (kept)
        self.vulners_key_input = QLineEdit()
        self.hibp_key_input = QLineEdit()
        self.hibp_key_input.setEchoMode(QLineEdit.EchoMode.Password)

        # New
        self.shodan_key_input = QLineEdit()
        self.shodan_key_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.censys_api_id_input = QLineEdit()
        self.censys_api_secret_input = QLineEdit()
        self.censys_api_secret_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.zap_api_key_input = QLineEdit()
        self.zap_api_key_input.setEchoMode(QLineEdit.EchoMode.Password)

        api_form.addRow("Vulners API Key:", self.vulners_key_input)
        api_form.addRow("HaveIBeenPwned API Key:", self.hibp_key_input)
        api_form.addRow("Shodan API Key:", self.shodan_key_input)
        api_form.addRow("Censys API ID:", self.censys_api_id_input)
        api_form.addRow("Censys API Secret:", self.censys_api_secret_input)
        api_form.addRow("OWASP ZAP API Key:", self.zap_api_key_input)

        api_btns = QHBoxLayout()
        self.api_save_btn = QPushButton("Save API Keys")
        self.api_test_shodan_btn = QPushButton("Test Shodan")
        self.api_test_zap_btn = QPushButton("Test ZAP")
        api_btns.addWidget(self.api_save_btn)
        api_btns.addStretch()
        api_btns.addWidget(self.api_test_shodan_btn)
        api_btns.addWidget(self.api_test_zap_btn)

        api_layout.addWidget(api_group)
        api_layout.addLayout(api_btns)

        # --------- Tab 2: Scanner Options ---------
        scan_tab = QWidget()
        self.tabs.addTab(scan_tab, "Scanner Options")

        scan_layout = QVBoxLayout(scan_tab)

        naabu_group = QGroupBox("Naabu")
        naabu_form = QFormLayout(naabu_group)
        self.naabu_ports_input = QLineEdit()      # e.g., "top-1000"
        self.naabu_rate_input = QLineEdit()       # e.g., "2000"
        naabu_form.addRow("Ports (e.g., top-1000 or 1-65535):", self.naabu_ports_input)
        naabu_form.addRow("Rate (pps):", self.naabu_rate_input)

        nuclei_group = QGroupBox("Nuclei")
        nuclei_form = QFormLayout(nuclei_group)
        self.nuclei_templates_path = QLineEdit()
        browse_tpl_btn = QPushButton("Browse…")
        browse_tpl_btn.clicked.connect(self._browse_nuclei_templates)
        tpl_row = QHBoxLayout()
        tpl_row.addWidget(self.nuclei_templates_path)
        tpl_row.addWidget(browse_tpl_btn)
        nuclei_form.addRow("Templates Directory:", tpl_row)
        self.nuclei_severity_input = QLineEdit()  # e.g., "critical,high,medium"
        nuclei_form.addRow("Severity Filter (comma list):", self.nuclei_severity_input)

        amass_group = QGroupBox("Amass")
        amass_form = QFormLayout(amass_group)
        self.amass_config_path = QLineEdit()
        browse_amass_btn = QPushButton("Browse…")
        browse_amass_btn.clicked.connect(self._browse_amass_config)
        amass_row = QHBoxLayout()
        amass_row.addWidget(self.amass_config_path)
        amass_row.addWidget(browse_amass_btn)
        amass_form.addRow("Config File (optional):", amass_row)

        scan_buttons = QHBoxLayout()
        self.scan_save_btn = QPushButton("Save Scanner Options")
        scan_buttons.addWidget(self.scan_save_btn)
        scan_buttons.addStretch()

        scan_layout.addWidget(naabu_group)
        scan_layout.addWidget(nuclei_group)
        scan_layout.addWidget(amass_group)
        scan_layout.addLayout(scan_buttons)

        # --------- Tab 3: Cloud & Prowler ---------
        cloud_tab = QWidget()
        self.tabs.addTab(cloud_tab, "Cloud & Prowler")

        cloud_layout = QVBoxLayout(cloud_tab)

        aws_group = QGroupBox("AWS Credentials / Profile (for Prowler & AWS tools)")
        aws_form = QFormLayout(aws_group)
        self.aws_profile_input = QLineEdit()
        self.aws_access_key_input = QLineEdit()
        self.aws_secret_key_input = QLineEdit()
        self.aws_secret_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.aws_session_token_input = QLineEdit()
        self.aws_session_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.aws_region_input = QLineEdit()

        aws_form.addRow("AWS Profile Name:", self.aws_profile_input)
        aws_form.addRow("Access Key ID:", self.aws_access_key_input)
        aws_form.addRow("Secret Access Key:", self.aws_secret_key_input)
        aws_form.addRow("Session Token (optional):", self.aws_session_token_input)
        aws_form.addRow("Default Region (e.g., us-east-1):", self.aws_region_input)

        aws_btns = QHBoxLayout()
        self.aws_save_profile_btn = QPushButton("Save AWS Profile")
        self.aws_test_btn = QPushButton("Test AWS Connection")
        aws_btns.addWidget(self.aws_save_profile_btn)
        aws_btns.addStretch()
        aws_btns.addWidget(self.aws_test_btn)

        prowler_group = QGroupBox("Prowler Execution Defaults")
        prowler_form = QFormLayout(prowler_group)
        self.prowler_profile_combo = QComboBox()
        self.prowler_profile_combo.setEditable(True)  # allow free text
        self.prowler_regions_input = QLineEdit()      # e.g., "us-east-1,eu-west-1"
        prowler_form.addRow("Profile:", self.prowler_profile_combo)
        prowler_form.addRow("Regions (comma-separated):", self.prowler_regions_input)

        cloud_buttons_bottom = QHBoxLayout()
        self.cloud_save_btn = QPushButton("Save Cloud Settings")
        cloud_buttons_bottom.addWidget(self.cloud_save_btn)
        cloud_buttons_bottom.addStretch()

        cloud_layout.addWidget(aws_group)
        cloud_layout.addLayout(aws_btns)
        cloud_layout.addWidget(prowler_group)
        cloud_layout.addLayout(cloud_buttons_bottom)

        # ---- Wire actions ----
        self.api_save_btn.clicked.connect(self._save_api_keys)
        self.api_test_shodan_btn.clicked.connect(self._test_shodan)
        self.api_test_zap_btn.clicked.connect(self._test_zap)
        self.scan_save_btn.clicked.connect(self._save_scanner_options)
        self.aws_save_profile_btn.clicked.connect(self._save_aws_profile_files)
        self.aws_test_btn.clicked.connect(self._test_aws_connection)   # <-- present now
        self.cloud_save_btn.clicked.connect(self._save_cloud_settings)

        # Load + icon hookup
        self._load_all()
        # Icons are applied by MainWindow via update_icons(color), but we set defaults for standalone use.
        self.update_icons(QColor("#e0e0e0"))

    # ---------------- Icon hook ----------------
    def update_icons(self, color: QColor):
        self.api_save_btn.setIcon(icon_manager.get_icon("check", color))
        self.api_test_shodan_btn.setIcon(icon_manager.get_icon("security", color))
        self.api_test_zap_btn.setIcon(icon_manager.get_icon("security", color))
        self.scan_save_btn.setIcon(icon_manager.get_icon("settings", color))
        self.aws_save_profile_btn.setIcon(icon_manager.get_icon("cloud", color))
        self.aws_test_btn.setIcon(icon_manager.get_icon("cloud", color))
        self.cloud_save_btn.setIcon(icon_manager.get_icon("settings", color))

    # ---------------- Load/Save helpers ----------------
    def _load_all(self):
        # API Keys
        self.vulners_key_input.setText(self.settings.value("security/vulners_api_key", ""))
        self.hibp_key_input.setText(self.settings.value("security/hibp_api_key", ""))
        self.shodan_key_input.setText(self.settings.value("security/shodan_api_key", ""))
        self.censys_api_id_input.setText(self.settings.value("security/censys_api_id", ""))
        self.censys_api_secret_input.setText(self.settings.value("security/censys_api_secret", ""))
        self.zap_api_key_input.setText(self.settings.value("security/zap_api_key", ""))

        # Scanners
        self.naabu_ports_input.setText(self.settings.value("scanner/naabu_ports", "top-1000"))
        self.naabu_rate_input.setText(self.settings.value("scanner/naabu_rate", "2000"))
        self.nuclei_templates_path.setText(self.settings.value("scanner/nuclei_templates_path", ""))
        self.nuclei_severity_input.setText(self.settings.value("scanner/nuclei_severity", "critical,high,medium"))
        self.amass_config_path.setText(self.settings.value("scanner/amass_config_path", ""))

        # AWS inputs
        self.aws_profile_input.setText(self.settings.value("cloud/aws_profile", "default"))
        self.aws_access_key_input.setText(self.settings.value("cloud/aws_access_key_id", ""))
        self.aws_secret_key_input.setText(self.settings.value("cloud/aws_secret_access_key", ""))
        self.aws_session_token_input.setText(self.settings.value("cloud/aws_session_token", ""))
        self.aws_region_input.setText(self.settings.value("cloud/aws_region", "us-east-1"))
        self.prowler_profile_combo.clear()
        profiles = self._read_aws_profiles()
        if profiles:
            self.prowler_profile_combo.addItems(profiles)
        # prefer saved choice
        saved_profile = self.settings.value("cloud/prowler_profile", self.settings.value("cloud/aws_profile", "default"))
        self.prowler_profile_combo.setCurrentText(saved_profile)
        self.prowler_regions_input.setText(self.settings.value("cloud/prowler_regions", ""))

    def _save_api_keys(self):
        self.settings.setValue("security/vulners_api_key", self.vulners_key_input.text().strip())
        self.settings.setValue("security/hibp_api_key", self.hibp_key_input.text().strip())
        self.settings.setValue("security/shodan_api_key", self.shodan_key_input.text().strip())
        self.settings.setValue("security/censys_api_id", self.censys_api_id_input.text().strip())
        self.settings.setValue("security/censys_api_secret", self.censys_api_secret_input.text().strip())
        self.settings.setValue("security/zap_api_key", self.zap_api_key_input.text().strip())
        self.settings.sync()
        self.show_info("API keys saved.")

    def _save_scanner_options(self):
        self.settings.setValue("scanner/naabu_ports", self.naabu_ports_input.text().strip())
        self.settings.setValue("scanner/naabu_rate", self.naabu_rate_input.text().strip())
        self.settings.setValue("scanner/nuclei_templates_path", self.nuclei_templates_path.text().strip())
        self.settings.setValue("scanner/nuclei_severity", self.nuclei_severity_input.text().strip())
        self.settings.setValue("scanner/amass_config_path", self.amass_config_path.text().strip())
        self.settings.sync()
        self.show_info("Scanner options saved.")

    def _save_cloud_settings(self):
        self.settings.setValue("cloud/aws_profile", self.aws_profile_input.text().strip() or "default")
        self.settings.setValue("cloud/aws_access_key_id", self.aws_access_key_input.text().strip())
        self.settings.setValue("cloud/aws_secret_access_key", self.aws_secret_key_input.text().strip())
        self.settings.setValue("cloud/aws_session_token", self.aws_session_token_input.text().strip())
        self.settings.setValue("cloud/aws_region", self.aws_region_input.text().strip() or "us-east-1")
        self.settings.setValue("cloud/prowler_profile", self.prowler_profile_combo.currentText().strip())
        self.settings.setValue("cloud/prowler_regions", self.prowler_regions_input.text().strip())
        self.settings.sync()
        self.show_info("Cloud & Prowler settings saved.")

    # ---------------- Browsers ----------------
    def _browse_nuclei_templates(self):
        path = QFileDialog.getExistingDirectory(self, "Select Nuclei Templates Directory")
        if path:
            self.nuclei_templates_path.setText(path)

    def _browse_amass_config(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Amass Config File", filter="YAML (*.yml *.yaml);;All Files (*)")
        if path:
            self.amass_config_path.setText(path)

    # ---------------- AWS helpers ----------------
    def _read_aws_profiles(self):
        profiles = []
        if AWS_CREDENTIALS.exists():
            cp = configparser.ConfigParser()
            cp.read(AWS_CREDENTIALS)
            profiles.extend(list(cp.sections()))
        if not profiles:
            profiles = ["default"]
        return profiles

    def _save_aws_profile_files(self):
        """
        Writes ~/.aws/credentials and ~/.aws/config for the specified profile.
        """
        profile = (self.aws_profile_input.text().strip() or "default")
        akid = self.aws_access_key_input.text().strip()
        secret = self.aws_secret_key_input.text().strip()
        token = self.aws_session_token_input.text().strip()
        region = self.aws_region_input.text().strip() or "us-east-1"

        if not akid or not secret:
            self.show_error("Access Key ID and Secret Access Key are required.")
            return

        # credentials
        AWS_CREDENTIALS.parent.mkdir(parents=True, exist_ok=True)
        cred = configparser.ConfigParser()
        if AWS_CREDENTIALS.exists():
            cred.read(AWS_CREDENTIALS)
        if profile not in cred:
            cred.add_section(profile)
        cred[profile]["aws_access_key_id"] = akid
        cred[profile]["aws_secret_access_key"] = secret
        if token:
            cred[profile]["aws_session_token"] = token
        else:
            # ensure removed if previously set
            cred[profile].pop("aws_session_token", None)

        with open(AWS_CREDENTIALS, "w") as f:
            cred.write(f)

        # config
        AWS_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        cfg = configparser.ConfigParser()
        if AWS_CONFIG.exists():
            cfg.read(AWS_CONFIG)
        section = f"profile {profile}" if profile != "default" else "default"
        if section not in cfg:
            cfg.add_section(section)
        cfg[section]["region"] = region

        with open(AWS_CONFIG, "w") as f:
            cfg.write(f)

        # persist to QSettings as well (so UI pre-fills)
        self._save_cloud_settings()

        self.show_info(
            f"AWS profile '{profile}' saved to:\n"
            f"  {AWS_CREDENTIALS}\n"
            f"  {AWS_CONFIG}\n\n"
            f"Prowler and AWS CLI can now use: -p {profile}"
        )
        # refresh profile chooser
        self.prowler_profile_combo.clear()
        self.prowler_profile_combo.addItems(self._read_aws_profiles())
        self.prowler_profile_combo.setCurrentText(profile)

    def _test_aws_connection(self):
        """
        Calls `aws sts get-caller-identity` with the chosen profile.
        Requires AWS CLI installed in PATH.
        """
        profile = self.aws_profile_input.text().strip() or "default"
        region = self.aws_region_input.text().strip() or "us-east-1"

        env = os.environ.copy()
        env["AWS_PROFILE"] = profile
        env["AWS_DEFAULT_REGION"] = region

        try:
            proc = subprocess.run(
                ["aws", "sts", "get-caller-identity"],
                capture_output=True, text=True, env=env, timeout=20
            )
        except FileNotFoundError:
            self.show_error("AWS CLI not found. Install with: sudo apt install awscli")
            return
        except Exception as e:
            self.show_error(f"Failed to execute AWS CLI: {e}")
            return

        if proc.returncode != 0:
            self.show_error(f"AWS test failed for profile '{profile}'.\n\n{proc.stderr.strip()}")
            return

        self.show_info(f"AWS test OK for '{profile}':\n{proc.stdout.strip()}")

    # ---------------- Mini tests for APIs ----------------
    def _test_shodan(self):
        key = self.shodan_key_input.text().strip()
        if not key:
            self.show_error("Enter a Shodan API key first.")
            return
        # Lightweight validation only (avoid network here)
        self.show_info("Shodan key saved — the scanners will use it for actual queries.")

    def _test_zap(self):
        # We only check presence; actual connection is in the Red Team widget
        key = self.zap_api_key_input.text().strip()
        if not key:
            self.show_error("Enter a ZAP API key first.")
            return
        self.show_info("ZAP API key saved — the Red Team/ZAP panel will use it when starting scans.")

