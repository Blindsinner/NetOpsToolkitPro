# -*- coding: utf-8 -*-
from PySide6.QtWidgets import (
    QVBoxLayout, QComboBox, QFormLayout, QGridLayout,
    QPushButton, QMessageBox, QInputDialog
)
from app.widgets.base_widget import BaseToolWidget

class AdapterManagerWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        layout = QVBoxLayout(self)
        self.adapter_combo = QComboBox()
        self.populate_adapters()
        
        form_layout = QFormLayout()
        form_layout.addRow("Select Adapter:", self.adapter_combo)
        
        grid_layout = QGridLayout()
        self.disable_button = QPushButton("Disable")
        self.enable_button = QPushButton("Enable")
        self.mtu_button = QPushButton("Change MTU")
        self.flush_dns_button = QPushButton("Flush System DNS")
        self.reset_tcp_button = QPushButton("Reset TCP/IP Stack")
        
        grid_layout.addWidget(self.disable_button, 0, 0)
        grid_layout.addWidget(self.enable_button, 0, 1)
        grid_layout.addWidget(self.mtu_button, 0, 2)
        grid_layout.addWidget(self.flush_dns_button, 1, 0, 1, 2)
        grid_layout.addWidget(self.reset_tcp_button, 1, 2)
        
        layout.addLayout(form_layout)
        layout.addLayout(grid_layout)
        layout.addStretch()
        
        self.disable_button.clicked.connect(lambda: self.show_command("disable"))
        self.enable_button.clicked.connect(lambda: self.show_command("enable"))
        self.mtu_button.clicked.connect(self.show_mtu_command)
        self.flush_dns_button.clicked.connect(lambda: self.show_command("flush_dns"))
        self.reset_tcp_button.clicked.connect(lambda: self.show_command("reset_tcp"))

    def populate_adapters(self):
        self.adapter_combo.addItems(self.system_tools.get_local_network_info().keys())

    def show_command(self, action, value=None):
        adapter = self.adapter_combo.currentText()
        if action not in ["flush_dns", "reset_tcp"] and not adapter:
            self.show_error("Please select a network adapter.")
            return
            
        cmd = self.system_tools.get_adapter_commands(adapter, action, value)
        self.show_command_dialog(cmd)

    def show_mtu_command(self):
        mtu, ok = QInputDialog.getInt(self, "Change MTU", "Enter new MTU value:", 1500, 68, 65535)
        if ok: self.show_command("mtu", str(mtu))

    def show_command_dialog(self, cmd):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Generated Command")
        msg_box.setText("Run this command in an administrative/root terminal:")
        msg_box.setDetailedText(cmd)
        
        copy_button = msg_box.addButton("Copy Command", QMessageBox.ButtonRole.AcceptRole)
        msg_box.exec()
        
        if msg_box.clickedButton() == copy_button:
            self.copy_to_clipboard(cmd)