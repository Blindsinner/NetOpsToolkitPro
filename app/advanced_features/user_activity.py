# -*- coding: utf-8 -*-
from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
from PySide6.QtCore import Qt
from app.config import AppConfig

class UserActivityDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        
        self.setWindowTitle("User Activity Log")
        self.setMinimumSize(800, 500)
        self.resize(800, 500)
        layout = QVBoxLayout(self)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view)
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        btn_layout.addStretch()
        btn_layout.addWidget(refresh_btn)
        layout.addLayout(btn_layout)
        refresh_btn.clicked.connect(self.load_log)
        self.load_log()
        
    def load_log(self):
        self.log_view.clear()
        try:
            if AppConfig.ACTIVITY_LOG_FILE.exists():
                with open(AppConfig.ACTIVITY_LOG_FILE, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    self.log_view.setText("".join(reversed(lines)))
        except Exception as e:
            self.log_view.setText(f"Error loading activity log: {e}")