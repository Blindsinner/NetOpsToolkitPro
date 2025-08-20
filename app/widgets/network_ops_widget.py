# -*- coding: utf-8 -*-
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget, QPushButton, QGridLayout, QSizePolicy
)
from PySide6.QtCore import Qt
from app.widgets.base_widget import BaseToolWidget
from app.widgets.real_time_subnet_widget import RealTimeSubnetWidget
from app.widgets.ip_details_widget import IPDetailsWidget
from app.widgets.lookup_widget import LookupWidget
from app.widgets.network_scan_widget import NetworkScanWidget
from app.widgets.diagnostics_widget import DiagnosticsWidget
from app.widgets.local_info_widget import LocalInfoWidget
from app.widgets.adapter_manager_widget import AdapterManagerWidget
from app.widgets.serial_terminal_widget import SerialTerminalWidget
from app.widgets.ssh_terminal_widget import SSHTerminalWidget
from app.advanced_features.config_management import ConfigManagerDialog
from app.advanced_features.performance_monitoring import PerformanceMonitoringDialog
from app.advanced_features.automation import AutomationDialog
from app.advanced_features.topology import TopologyDialog
# --- NEW: Import the icon manager ---
from app.assets.icon_manager import icon_manager

class NetworkOpsWidget(BaseToolWidget):
    """A container widget for all core Network Operations tools."""
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(settings, task_manager, parent)
        self.settings = settings
        self.task_manager = task_manager
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10) # Add some padding
        
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.setElideMode(Qt.TextElideMode.ElideRight)
        
        layout.addWidget(self.tab_widget)

        self.add_basic_tools()
        self.add_advanced_tools_dashboard()

    def add_basic_tools(self):
        """Adds the core tool widgets as their own tabs."""
        # --- NEW: Added icon names to the tool list ---
        basic_tools = [
            (SSHTerminalWidget, "SSH Terminal", "terminal"),
            (NetworkScanWidget, "Network Scanner", "scanner"),
            (SerialTerminalWidget, "Serial Terminal", "terminal"),
            (DiagnosticsWidget, "Diagnostics", "tools"),
            (RealTimeSubnetWidget, "Real-Time Subnetter", "tools"),
            (IPDetailsWidget, "IP Details", "tools"),
            (LookupWidget, "Lookups", "tools"),
            (LocalInfoWidget, "Local Network Info", "tools"),
            (AdapterManagerWidget, "Adapter Manager", "tools"),
        ]
        # --- NEW: The loop now unpacks the icon name ---
        for widget_class, tab_name, icon_name in basic_tools:
            widget = widget_class(self.settings, self.task_manager)
            # --- NEW: Add tab with the corresponding icon ---
            self.tab_widget.addTab(widget, icon_manager.get_icon(icon_name), tab_name)

    def add_advanced_tools_dashboard(self):
        """Creates a single tab with a grid of buttons to launch advanced dialogs."""
        dashboard_widget = QWidget()
        main_layout = QVBoxLayout(dashboard_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        grid_layout = QGridLayout()
        grid_layout.setSpacing(15)
        main_layout.addLayout(grid_layout)

        advanced_tools = [
            ("Config Management", lambda: ConfigManagerDialog(self.task_manager, self).exec()),
            ("Performance Monitor", lambda: PerformanceMonitoringDialog(self.task_manager, self).exec()),
            ("Automation Engine", lambda: AutomationDialog(self.task_manager, self).exec()),
            ("Topology Visualizer", lambda: TopologyDialog(self.settings, self.task_manager, self).exec()),
        ]

        for i, (name, func) in enumerate(advanced_tools):
            row, col = divmod(i, 2)
            button = QPushButton(name)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            button.setMinimumHeight(80)
            button.clicked.connect(func)
            grid_layout.addWidget(button, row, col)

        main_layout.addStretch()
        
        # --- NEW: Add the "Advanced Tools" tab with an icon ---
        self.tab_widget.addTab(dashboard_widget, icon_manager.get_icon("tools"), "Advanced Tools")