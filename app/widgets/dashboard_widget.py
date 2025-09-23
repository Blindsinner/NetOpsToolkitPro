# app/widgets/dashboard_widget.py
# REFACTORED: Moved the initial health check from __init__ to showEvent to prevent event loop errors.

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QHBoxLayout, QPushButton, QCheckBox, QLabel, QAbstractItemView
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from app.widgets.base_widget import BaseToolWidget
from app.core.health_engine import HealthEngine

class HealthDashboardWidget(BaseToolWidget):
    """A widget that displays a real-time overview of network device health."""
    
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.engine = HealthEngine(self.task_manager)
        self.initial_check_done = False # Flag to ensure the first check runs only once

        # UI Setup
        main_layout = QVBoxLayout(self)
        controls_layout = QHBoxLayout()
        self.status_label = QLabel("Status: Idle")
        self.refresh_button = QPushButton("Refresh Now")
        self.auto_refresh_checkbox = QCheckBox("Auto-Refresh every 60s")
        self.auto_refresh_checkbox.setChecked(True)
        
        controls_layout.addWidget(self.status_label)
        controls_layout.addStretch()
        controls_layout.addWidget(self.auto_refresh_checkbox)
        controls_layout.addWidget(self.refresh_button)
        
        self.health_table = QTableWidget()
        self.health_table.setColumnCount(4)
        self.health_table.setHorizontalHeaderLabels(["Device Host", "Status", "Ping RTT", "CPU Load"])
        self.health_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.health_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.health_table.setSortingEnabled(True)

        main_layout.addLayout(controls_layout)
        main_layout.addWidget(self.health_table)

        # Timer for auto-refresh
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(60000) # 60 seconds
        self.refresh_timer.timeout.connect(self.start_health_check)
        
        # Connections
        self.refresh_button.clicked.connect(self.start_health_check)
        self.engine.device_health_updated.connect(self.update_device_row)
        self.engine.all_checks_finished.connect(self.on_checks_finished)
        self.auto_refresh_checkbox.stateChanged.connect(self.toggle_auto_refresh)

        # Initial state setup
        self.populate_initial_devices()
        if self.auto_refresh_checkbox.isChecked():
            self.refresh_timer.start()
    
    def showEvent(self, event):
        """
        Overridden method that is called when the widget is shown.
        This is the correct place to start the initial background task.
        """
        super().showEvent(event)
        if not self.initial_check_done:
            self.initial_check_done = True
            # Use a single-shot timer to delay the check slightly, ensuring everything is fully initialized.
            QTimer.singleShot(50, self.start_health_check)

    def populate_initial_devices(self):
        """Fills the table with devices from the inventory before checks run."""
        self.engine.devices = self.engine._load_devices() # Ensure device list is fresh
        self.health_table.setSortingEnabled(False)
        self.health_table.setRowCount(0) # Clear the table first
        self.health_table.setRowCount(len(self.engine.devices))
        for row, device in enumerate(self.engine.devices):
            host = device.get("host", "Unknown Device")
            self.health_table.setItem(row, 0, QTableWidgetItem(host))
            for col in range(1, 4):
                self.health_table.setItem(row, col, QTableWidgetItem("Pending..."))
        self.health_table.setSortingEnabled(True)

    def start_health_check(self):
        """Initiates a full run of the health checks."""
        if self.engine.is_running:
            return
        
        self.status_label.setText("Status: Running checks...")
        self.refresh_button.setEnabled(False)
        self.populate_initial_devices()
        self.engine.run_all_checks(self)

    def on_checks_finished(self, message):
        """Slot for when the engine has finished all checks."""
        self.status_label.setText(f"Status: {message}")
        self.refresh_button.setEnabled(True)

    def update_device_row(self, health_data: dict):
        """Updates a single row in the table with new health data."""
        host = health_data.get("host")
        if not host:
            return

        items = self.health_table.findItems(host, Qt.MatchFlag.MatchExactly)
        if not items:
            return
        
        row = items[0].row()

        status_item = QTableWidgetItem(health_data.get("status", "Unknown"))
        if health_data.get("status") == "Up":
            status_item.setForeground(QColor("lime"))
        else:
            status_item.setForeground(QColor("red"))
        
        self.health_table.setItem(row, 1, status_item)
        self.health_table.setItem(row, 2, QTableWidgetItem(health_data.get("rtt", "N/A")))
        self.health_table.setItem(row, 3, QTableWidgetItem(health_data.get("cpu_load", "N/A")))
    
    def toggle_auto_refresh(self, state):
        if state == Qt.CheckState.Checked.value:
            self.refresh_timer.start()
        else:
            self.refresh_timer.stop()

    def shutdown(self):
        """Ensure timer is stopped when tab is closed."""
        self.refresh_timer.stop()
