# -*- coding: utf-8 -*-
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QFormLayout,
    QLineEdit, QPushButton, QComboBox, QGroupBox, QMessageBox
)
from app.core.task_manager import TaskManager
from app.core.cloud_engine import CloudEngine
from app.core.app_logger import activity_logger

class CloudDashboardWidget(QWidget):
    """UI for displaying cloud infrastructure details."""
    def __init__(self, settings, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.task_manager = task_manager
        self.engine = CloudEngine()

        layout = QVBoxLayout(self)
        
        # --- Credentials & Controls ---
        controls_group = QGroupBox("AWS Connection")
        form = QFormLayout(controls_group)
        self.region_combo = QComboBox()
        # A subset of common regions
        self.region_combo.addItems([
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2"
        ])
        self.access_key_input = QLineEdit()
        self.access_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret_key_input = QLineEdit()
        self.secret_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.fetch_btn = QPushButton("Fetch AWS Network Inventory")

        form.addRow("Region:", self.region_combo)
        form.addRow("Access Key ID:", self.access_key_input)
        form.addRow("Secret Access Key:", self.secret_key_input)
        layout.addWidget(controls_group)
        layout.addWidget(self.fetch_btn)
        
        # --- Results Tree ---
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["ID / Name", "Details"])
        self.results_tree.setAlternatingRowColors(True)
        layout.addWidget(self.results_tree)

        self.fetch_btn.clicked.connect(self.fetch_inventory)
        self.load_state()

    def load_state(self):
        self.region_combo.setCurrentText(self.settings.value("aws/region", "us-east-1"))
        self.access_key_input.setText(self.settings.value("aws/access_key", ""))

    def save_state(self):
        self.settings.setValue("aws/region", self.region_combo.currentText())
        self.settings.setValue("aws/access_key", self.access_key_input.text())
        # Note: We don't save the secret key for security.

    def fetch_inventory(self):
        region = self.region_combo.currentText()
        access_key = self.access_key_input.text().strip()
        secret_key = self.secret_key_input.text().strip()

        if not all([region, access_key, secret_key]):
            QMessageBox.warning(self, "Missing Credentials", "Please provide AWS region, access key, and secret key.")
            return

        activity_logger.log("AWS Inventory Fetch Started", f"Region: {region}")
        self.fetch_btn.setText("Fetching...")
        self.fetch_btn.setEnabled(False)
        self.results_tree.clear()
        self.task_manager.create_task(self.run_fetch(region, access_key, secret_key))

    async def run_fetch(self, region, access_key, secret_key):
        inventory = await self.engine.get_aws_network_inventory(region, access_key, secret_key)
        
        if "error" in inventory:
            QMessageBox.critical(self, "AWS Error", f"Could not fetch inventory:\n{inventory['error']}")
        else:
            self.populate_tree(inventory)
        
        self.fetch_btn.setText("Fetch AWS Network Inventory")
        self.fetch_btn.setEnabled(True)
        self.save_state()

    def populate_tree(self, inventory):
        # VPCs
        vpc_root = QTreeWidgetItem(self.results_tree, ["VPCs"])
        for vpc_id, vpc_data in inventory.get('vpcs', {}).items():
            vpc_name = vpc_data.get('tags', {}).get('Name', vpc_id)
            vpc_item = QTreeWidgetItem(vpc_root, [vpc_name, vpc_data.get('cidr')])
            
            # Subnets for this VPC
            subnet_root = QTreeWidgetItem(vpc_item, ["Subnets"])
            for sub_id, sub_data in inventory.get('subnets', {}).items():
                if sub_data['vpc_id'] == vpc_id:
                    sub_name = sub_data.get('tags', {}).get('Name', sub_id)
                    QTreeWidgetItem(subnet_root, [sub_name, f"{sub_data['cidr']} ({sub_data['az']})"])
        
        # Security Groups
        sg_root = QTreeWidgetItem(self.results_tree, ["Security Groups"])
        for sg_id, sg_data in inventory.get('security_groups', {}).items():
            QTreeWidgetItem(sg_root, [sg_data.get('name', sg_id), f"{sg_data.get('description')}"])

        self.results_tree.expandToDepth(1)