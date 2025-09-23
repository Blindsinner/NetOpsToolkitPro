# -*- coding: utf-8 -*-
import ipaddress
from PySide6.QtWidgets import (
    QVBoxLayout, QFormLayout, QLineEdit, QGroupBox,
    QSlider, QLabel, QHBoxLayout
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
from app.widgets.base_widget import BaseToolWidget

class RealTimeSubnetWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        layout = QVBoxLayout(self)
        
        input_group = QGroupBox("Input")
        form_layout = QFormLayout(input_group)
        self.ip_input = QLineEdit()
        self.cidr_slider = QSlider(Qt.Orientation.Horizontal)
        self.cidr_label = QLabel()
        self.cidr_slider.setRange(1, 32)
        
        slider_layout = QHBoxLayout()
        slider_layout.addWidget(self.cidr_slider)
        slider_layout.addWidget(self.cidr_label)
        
        form_layout.addRow("Base IP Address:", self.ip_input)
        form_layout.addRow("CIDR Prefix:", slider_layout)
        layout.addWidget(input_group)
        
        results_group = QGroupBox("Real-Time Network Details")
        self.results_layout = QFormLayout(results_group)
        self.result_labels = {k: QLineEdit() for k in ["Network", "Netmask", "Wildcard", "Broadcast", "Host Range", "Usable Hosts"]}
        
        for k, v in self.result_labels.items():
            v.setReadOnly(True)
            v.setFont(QFont("Consolas", 11))
            self.results_layout.addRow(f"{k}:", v)
            
        layout.addWidget(results_group)
        layout.addStretch()
        
        self.ip_input.textChanged.connect(self.update_calculations)
        self.cidr_slider.valueChanged.connect(self.update_calculations)
        
        self.load_state()
        self.update_calculations()

    def update_calculations(self, value=None):
        ip_str = self.ip_input.text().strip()
        cidr = self.cidr_slider.value()
        self.cidr_label.setText(f"/{cidr}")
        
        try:
            net = ipaddress.ip_network(f"{ip_str}/{cidr}", strict=False)
            self.result_labels["Network"].setText(str(net.network_address))
            self.result_labels["Netmask"].setText(str(net.netmask))
            self.result_labels["Wildcard"].setText(str(net.hostmask))
            self.result_labels["Broadcast"].setText(str(net.broadcast_address))
            num_hosts = net.num_addresses - 2
            
            if num_hosts >= 0 and net.prefixlen < 31:
                self.result_labels["Host Range"].setText(f"{net.network_address + 1} - {net.broadcast_address - 1}")
            else:
                self.result_labels["Host Range"].setText("N/A")
            
            self.result_labels["Usable Hosts"].setText(f"{max(0, num_hosts):,}")
        except ValueError:
            for label in self.result_labels.values():
                label.setText("Invalid IP")

    def load_state(self):
        self.ip_input.setText(self.settings.value("subnet/ip", "192.168.10.130"))
        self.cidr_slider.setValue(int(self.settings.value("subnet/cidr", 26)))

    def save_state(self):
        self.settings.setValue("subnet/ip", self.ip_input.text())
        self.settings.setValue("subnet/cidr", self.cidr_slider.value())