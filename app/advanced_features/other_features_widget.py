# -*- coding: utf-8 -*-
from PySide6.QtWidgets import (
    QVBoxLayout, QGridLayout, QPushButton, QMessageBox, QSizePolicy
)
from app.widgets.base_widget import BaseToolWidget
from app.advanced_features.crypto_tools import CryptoToolsDialog
from app.advanced_features.config_management import ConfigManagerDialog
from app.advanced_features.performance_monitoring import PerfMonDialog
from app.advanced_features.automation import AutomationDialog
from app.advanced_features.topology import TopologyDialog
from app.advanced_features.threat_detection import ThreatIntelDialog
from app.advanced_features.incident_response import PacketCaptureDialog
from app.advanced_features.security_testing import SecurityTestingDialog
from app.advanced_features.user_activity import UserActivityDialog
from app.advanced_features.nac import NacDialog

class OtherFeaturesWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        grid_layout = QGridLayout()
        grid_layout.setSpacing(15)
        main_layout.addLayout(grid_layout)

        features = [
            ("Cryptography Tools", self.open_crypto_tools, 0, 0, 1, 1),
            ("Config Management", self.open_config_manager, 0, 1, 1, 1),
            ("Performance Monitoring", self.open_perf_mon, 0, 2, 1, 1),
            ("Network Automation", self.open_automation, 1, 0, 1, 1),
            ("Topology Visualizer", self.open_topology, 1, 1, 1, 1),
            ("Threat Detection", self.open_threat_intel, 1, 2, 1, 1),
            ("Incident Response", self.open_incident_response, 2, 0, 1, 1),
            ("User Activity", self.open_user_activity, 2, 1, 1, 1),
            ("Security Testing", self.open_security_testing, 2, 2, 1, 1),
            ("Simple NAC", self.open_nac, 3, 0, 1, 1),
        ]

        for name, func, row, col, r_span, c_span in features:
            button = QPushButton(name)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            button.setMinimumHeight(80)
            button.clicked.connect(func)
            grid_layout.addWidget(button, row, col, r_span, c_span)

        main_layout.addStretch()

    def open_crypto_tools(self):
        dialog = CryptoToolsDialog(self)
        dialog.exec()

    def open_config_manager(self):
        dialog = ConfigManagerDialog(self.task_manager, self)
        dialog.exec()
        
    def open_perf_mon(self):
        dialog = PerfMonDialog(self.settings, self.task_manager, self)
        dialog.exec()

    def open_automation(self):
        dialog = AutomationDialog(self.task_manager, self)
        dialog.exec()
        
    def open_topology(self):
        dialog = TopologyDialog(self.task_manager, self)
        dialog.exec()

    def open_threat_intel(self):
        dialog = ThreatIntelDialog(self.settings, self.task_manager, self)
        dialog.exec()
        
    def open_incident_response(self):
        dialog = PacketCaptureDialog(self)
        dialog.exec()

    def open_security_testing(self):
        dialog = SecurityTestingDialog(self.task_manager, self)
        dialog.exec()

    def open_user_activity(self):
        dialog = UserActivityDialog(self)
        dialog.exec()
        
    def open_nac(self):
        dialog = NacDialog(self.settings, self.task_manager, self)
        dialog.exec()