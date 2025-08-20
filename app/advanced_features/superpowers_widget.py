# -*- coding: utf-8 -*-
from PySide6.QtWidgets import QWidget, QVBoxLayout, QGridLayout, QPushButton, QSizePolicy
from app.widgets.base_widget import BaseToolWidget
from app.advanced_features.ai_assistant_dialog import AIAssistantDialog
from app.advanced_features.automation import AutomationDialog
from app.advanced_features.log_ingestor import LogIngestorDialog

class SuperpowersWidget(BaseToolWidget):
    """A container for advanced, cross-functional tools."""
    # --- FIX: The __init__ method now correctly handles the arguments from main_window.py ---
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(settings, task_manager, parent)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        grid_layout = QGridLayout()
        grid_layout.setSpacing(15)
        main_layout.addLayout(grid_layout)

        features = [
            ("Unified Dashboard", self.open_dashboard, 0, 0, 1, 2),
            ("AI Assistant", self.open_ai_assistant, 1, 0, 1, 1),
            ("SOAR Lite (Playbooks)", self.open_automation, 1, 1, 1, 1),
        ]

        for name, func, row, col, r_span, c_span in features:
            button = QPushButton(name)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            button.setMinimumHeight(80)
            button.clicked.connect(func)
            grid_layout.addWidget(button, row, col, r_span, c_span)

        main_layout.addStretch()

    def open_dashboard(self):
        # This can be expanded into a full dashboard later
        dialog = LogIngestorDialog(self.task_manager, self)
        dialog.exec()

    def open_ai_assistant(self):
        dialog = AIAssistantDialog(self.settings, self.task_manager, self)
        dialog.exec()
        
    def open_automation(self):
        dialog = AutomationDialog(self.task_manager, self)
        dialog.exec()