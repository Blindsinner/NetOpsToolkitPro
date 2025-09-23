# app/widgets/network_ops_widget.py
# UPDATED: Added an `update_icons` method to be called on theme change.

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QPushButton, QLabel, QMessageBox, QTabBar
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from app.widgets.base_widget import BaseToolWidget
from app.assets.icon_manager import icon_manager

# Import all tool widgets
from app.widgets.dashboard_widget import HealthDashboardWidget
from app.widgets.real_time_subnet_widget import RealTimeSubnetWidget
from app.widgets.ip_details_widget import IPDetailsWidget
from app.widgets.lookup_widget import LookupWidget
from app.widgets.network_scan_widget import NetworkScanWidget
from app.widgets.diagnostics_widget import DiagnosticsWidget
from app.widgets.local_info_widget import LocalInfoWidget
from app.widgets.adapter_manager_widget import AdapterManagerWidget
from app.widgets.serial_terminal_widget import SerialTerminalWidget
from app.widgets.ssh_terminal_widget import SSHTerminalWidget
from app.advanced_features.config_management import ConfigManagerWidget
from app.advanced_features.performance_monitoring import PerformanceMonitoringWidget
from app.advanced_features.automation import AutomationWidget
from app.advanced_features.topology import TopologyWidget

class NetworkOpsWidget(BaseToolWidget):
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

        dashboard_widget = HealthDashboardWidget(self.settings, self.task_manager)
        self.workspace_tabs.addTab(dashboard_widget, "Health Dashboard")
        self.workspace_tabs.tabBar().setTabButton(0, QTabBar.ButtonPosition.RightSide, None)

        main_layout.addWidget(tool_panel)
        main_layout.addWidget(self.workspace_tabs, stretch=1)

        self.tools = {
            "Health Dashboard": (HealthDashboardWidget, "dashboard"),
            "SSH Terminal": (SSHTerminalWidget, "terminal"),
            "Network Scanner": (NetworkScanWidget, "scanner"),
            "Serial Terminal": (SerialTerminalWidget, "terminal"),
            "Diagnostics": (DiagnosticsWidget, "tools"),
            "--- Advanced ---": (None, None),
            "Config Management": (ConfigManagerWidget, "config"),
            "Performance Monitor": (PerformanceMonitoringWidget, "performance"),
            "Automation Engine": (AutomationWidget, "automation"),
            "Topology Visualizer": (TopologyWidget, "topology"),
            "--- Calculators ---": (None, None),
            "Real-Time Subnetter": (RealTimeSubnetWidget, "tools"),
            "IP Details": (IPDetailsWidget, "tools"),
            "Lookups": (LookupWidget, "tools"),
            "--- Local Machine ---": (None, None),
            "Local Network Info": (LocalInfoWidget, "tools"),
            "Adapter Manager": (AdapterManagerWidget, "tools"),
        }

        for name, (widget_class, icon_name) in self.tools.items():
            if name in ["Health Dashboard"]: continue # Already added
            if widget_class is None:
                separator = QLabel(name); separator.setStyleSheet("font-weight: bold; margin-top: 10px;")
                tool_layout.addWidget(separator)
                continue
            button = QPushButton(name)
            button.setMinimumHeight(40)
            button.clicked.connect(lambda checked=False, n=name, wc=widget_class: self.open_tool_in_tab(n, wc))
            tool_layout.addWidget(button)
        
        tool_layout.addStretch()

    def update_icons(self, color: QColor):
        """Public method called by MainWindow to update all icons in this widget."""
        for i in range(self.workspace_tabs.count()):
            tab_name = self.workspace_tabs.tabText(i)
            if tab_name in self.tools:
                icon_name = self.tools[tab_name][1]
                if icon_name:
                    self.workspace_tabs.setTabIcon(i, icon_manager.get_icon(icon_name, color))

    def open_tool_in_tab(self, name, widget_class):
        for i in range(self.workspace_tabs.count()):
            if self.workspace_tabs.tabText(i) == name:
                self.workspace_tabs.setCurrentIndex(i)
                return

        try:
            tool_widget = widget_class(self.settings, self.task_manager)
        except Exception as e:
            self.show_error(f"Could not instantiate the '{name}' widget.\nError: {e}")
            return

        icon_name = self.tools[name][1]
        icon = icon_manager.get_icon(icon_name, QColor("black")) # Temporarily use black, will be re-colored by update_icons
        index = self.workspace_tabs.addTab(tool_widget, icon, name)
        self.workspace_tabs.setCurrentIndex(index)

    def close_tab(self, index):
        if index == 0: return

        widget = self.workspace_tabs.widget(index)
        if hasattr(widget, 'shutdown'):
            widget.shutdown()
        
        self.workspace_tabs.removeTab(index)
        widget.deleteLater()
