# app/advanced_features/cybersecurity_widget.py
# REFACTORED: Corrected the constructor calls in open_tool_in_tab.
# ENHANCED: Writes app activity entries whenever tools are opened/closed,
#           using the root-level user_activity.txt file.

from datetime import datetime
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QTabWidget, QLabel, QMessageBox, QTabBar
)
from PySide6.QtCore import Qt
from app.widgets.base_widget import BaseToolWidget
from app.assets.icon_manager import icon_manager

# Import the WIDGET versions of the tools
from app.advanced_features.nac import NacWidget
from app.advanced_features.honeypot_manager import HoneypotManagerWidget
from app.advanced_features.threat_detection import ThreatIntelWidget
from app.advanced_features.incident_response import PacketCaptureWidget
from app.advanced_features.user_activity import UserActivityWidget
from app.advanced_features.crypto_tools import CryptoToolsWidget
from app.advanced_features.log_ingestor import LogIngestorWidget

# -----------------------------------------------------------------------------
# Activity logging to root-level user_activity.txt
# -----------------------------------------------------------------------------
USER_ACTIVITY_FILE = Path(__file__).resolve().parents[2] / "user_activity.txt"

def _write_activity(action: str, details: str = "") -> None:
    """
    Append a single line to user_activity.txt in the format:
    YYYY-MM-DD HH:MM:SS - ACTION - DETAILS
    """
    try:
        USER_ACTIVITY_FILE.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(USER_ACTIVITY_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ts} - {action} - {details}\n")
    except Exception:
        # Silent fail; UI should never crash because activity logging failed.
        pass


class CybersecurityWidget(BaseToolWidget):
    """A container for Cybersecurity-specific tools, now with a tabbed workspace."""
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(settings, task_manager, parent)

        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        tool_panel = QWidget()
        tool_panel.setObjectName("ToolPanel")
        tool_panel.setFixedWidth(200)
        tool_layout = QVBoxLayout(tool_panel)
        tool_layout.setContentsMargins(10, 10, 10, 10)
        tool_layout.setSpacing(10)

        self.workspace_tabs = QTabWidget()
        self.workspace_tabs.setTabsClosable(True)
        self.workspace_tabs.tabCloseRequested.connect(self.close_tab)

        welcome_label = QLabel("Welcome to the Cybersecurity Domain.\n\nSelect a tool from the left to begin.")
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.workspace_tabs.addTab(welcome_label, "Welcome")
        self.workspace_tabs.tabBar().setTabButton(0, QTabBar.ButtonPosition.RightSide, None)

        main_layout.addWidget(tool_panel)
        main_layout.addWidget(self.workspace_tabs, stretch=1)

        self.tools = {
            "Threat Intelligence": ThreatIntelWidget,
            "Packet Capture": PacketCaptureWidget,
            "Network Access Control": NacWidget,
            "User Activity Log": UserActivityWidget,
            "Cryptography Tools": CryptoToolsWidget,
            "Log Ingestor": LogIngestorWidget,
            "Honeypot Manager": HoneypotManagerWidget,
        }

        for name, widget_class in self.tools.items():
            button = QPushButton(name)
            button.setMinimumHeight(40)
            button.clicked.connect(lambda checked=False, n=name, wc=widget_class: self.open_tool_in_tab(n, wc))
            tool_layout.addWidget(button)

        tool_layout.addStretch()

        # Log that the Cybersecurity domain was opened
        _write_activity("Open Domain", "Cybersecurity")

    def open_tool_in_tab(self, name, widget_class):
        # Reuse existing tab if already open
        for i in range(self.workspace_tabs.count()):
            if self.workspace_tabs.tabText(i) == name:
                self.workspace_tabs.setCurrentIndex(i)
                return

        try:
            # Standardized constructor calls
            tool_widget = widget_class(self.settings, self.task_manager)
        except Exception as e:
            QMessageBox.critical(self, "Error Loading Tool", f"Could not instantiate the '{name}' widget.\nError: {e}")
            return

        index = self.workspace_tabs.addTab(tool_widget, name)
        self.workspace_tabs.setCurrentIndex(index)

        # Write activity when a tool tab is opened
        _write_activity("Open Tool", name)

    def close_tab(self, index):
        # Do not close the welcome tab
        if index == 0:
            return

        name = self.workspace_tabs.tabText(index)
        widget = self.workspace_tabs.widget(index)
        if hasattr(widget, 'shutdown'):
            try:
                widget.shutdown()
            except Exception:
                pass

        self.workspace_tabs.removeTab(index)
        widget.deleteLater()

        # Write activity when a tool tab is closed
        _write_activity("Close Tool", name)

