# app/advanced_features/superpowers_widget.py
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QPushButton, QLabel,
    QSizePolicy, QMessageBox
)
from PySide6.QtCore import Qt

# The AIAssistantDialog expects a QSettings object, not an AppConfig object.
# This version of the file correctly passes it.
from app.advanced_features.ai_assistant_dialog import AIAssistantDialog

class SuperpowersWidget(QWidget):
    """
    A widget to group and display the most advanced, cross-functional "Superpower" features.
    """
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(parent)
        # This 'settings' is the QSettings object from main_window.py
        self.settings = settings
        self.task_manager = task_manager

        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # --- AI Assistant Section ---
        ai_group = QGroupBox("AI Assistant")
        ai_layout = QVBoxLayout()
        
        ai_desc_label = QLabel(
            "Your AI-powered copilot for network and security operations. "
            "Ask questions, get explanations for logs, generate commands, and more."
        )
        ai_desc_label.setWordWrap(True)
        
        self.launch_ai_btn = QPushButton("Launch AI Assistant")
        self.launch_ai_btn.clicked.connect(self.open_ai_assistant)
        
        ai_layout.addWidget(ai_desc_label)
        ai_layout.addWidget(self.launch_ai_btn)
        ai_group.setLayout(ai_layout)
        
        main_layout.addWidget(ai_group)
        ai_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def open_ai_assistant(self):
        """
        Launches the AI Assistant dialog, passing the correct QSettings object.
        """
        try:
            # FIX: Pass self.settings (the QSettings object) instead of creating a new AppConfig.
            dialog = AIAssistantDialog(self.settings, self.task_manager, self)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open AI Assistant: {e}")