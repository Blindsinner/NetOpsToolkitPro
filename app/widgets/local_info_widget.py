# -*- coding: utf-8 -*-
from PySide6.QtWidgets import (
    QVBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QHeaderView
)
from app.widgets.base_widget import BaseToolWidget

class LocalInfoWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Interface/Property", "Value"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.refresh_button = QPushButton("Refresh")
        
        layout.addWidget(self.refresh_button)
        layout.addWidget(self.tree)
        
        self.refresh_button.clicked.connect(self.populate_info)
        self.populate_info()

    def populate_info(self):
        self.tree.clear()
        data = self.system_tools.get_local_network_info()
        for iface, addrs in data.items():
            iface_item = QTreeWidgetItem(self.tree, [iface])
            for addr in addrs:
                family = str(addr.family).split('.')[-1]
                QTreeWidgetItem(iface_item, [f"  Family", family])
                QTreeWidgetItem(iface_item, [f"  Address", addr.address])
                if addr.netmask: QTreeWidgetItem(iface_item, [f"  Netmask", addr.netmask])
                if addr.broadcast: QTreeWidgetItem(iface_item, [f"  Broadcast", addr.broadcast])
        self.tree.expandAll()