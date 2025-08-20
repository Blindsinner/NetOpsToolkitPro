# -*- coding: utf-8 -*-
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QPushButton, QSizePolicy
)
from app.widgets.base_widget import BaseToolWidget
from app.advanced_features.threat_detection import ThreatIntelDialog
from app.advanced_features.incident_response import PacketCaptureDialog
from app.advanced_features.nac import NacDialog
from app.advanced_features.security_testing import SecurityTestingDialog
from app.advanced_features.user_activity import UserActivityDialog
from app.advanced_features.crypto_tools import CryptoToolsDialog
from app.advanced_features.log_ingestor import LogIngestorDialog
from app.advanced_features.honeypot_manager import HoneypotManagerDialog # <-- NEW IMPORT

class CybersecurityWidget(BaseToolWidget):
    """A container for all Cybersecurity tools."""
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(settings, task_manager, parent)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        grid_layout = QGridLayout()
        grid_layout.setSpacing(15)
        main_layout.addLayout(grid_layout)

        features = [
            ("Threat Intelligence", self.open_threat_intel, 0, 0, 1, 1),
            ("Packet Capture", self.open_incident_response, 0, 1, 1, 1),
            ("Simple NAC", self.open_nac, 0, 2, 1, 1),
            ("Security Testing", self.open_security_testing, 1, 0, 1, 1),
            ("User Activity Log", self.open_user_activity, 1, 1, 1, 1),
            ("Cryptography Tools", self.open_crypto_tools, 1, 2, 1, 1),
            ("Log Ingestor", self.open_log_ingestor, 2, 0, 1, 1),
            # --- ADD NEW BUTTON ---
            ("Honeypot Manager", self.open_honeypot_manager, 2, 1, 1, 1),
        ]

        for name, func, row, col, r_span, c_span in features:
            button = QPushButton(name)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            button.setMinimumHeight(80)
            button.clicked.connect(func)
            grid_layout.addWidget(button, row, col, r_span, c_span)

        main_layout.addStretch()

    def open_threat_intel(self):
        dialog = ThreatIntelDialog(self.settings, self.task_manager, self)
        dialog.exec()
        
    def open_incident_response(self):
        dialog = PacketCaptureDialog(self)
        dialog.exec()
        
    def open_nac(self):
        dialog = NacDialog(self.settings, self.task_manager, self)
        dialog.exec()

    def open_security_testing(self):
        dialog = SecurityTestingDialog(self.task_manager, self)
        dialog.exec()

    def open_user_activity(self):
        dialog = UserActivityDialog(self)
        dialog.exec()
        
    def open_crypto_tools(self):
        dialog = CryptoToolsDialog(self)
        dialog.exec()
        
    def open_log_ingestor(self):
        dialog = LogIngestorDialog(self.task_manager, self)
        dialog.exec()
        
    def open_honeypot_manager(self): # <-- NEW METHOD
        dialog = HoneypotManagerDialog(self.task_manager, self)
        dialog.exec()