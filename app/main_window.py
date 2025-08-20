# -*- coding: utf-8 -*-
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QListWidget, QStackedWidget,
    QMessageBox, QToolButton, QSplitter, QListWidgetItem
)
from PySide6.QtGui import QIcon
from PySide6.QtCore import QSettings, QSize, QPoint, Qt

from app.config import AppConfig, qss_dark_theme, qss_light_theme
from app.core.task_manager import TaskManager
from app.core.app_logger import activity_logger
# --- NEW: Import the icon manager ---
from app.assets.icon_manager import icon_manager

# Import domain widgets
from app.widgets.network_ops_widget import NetworkOpsWidget
from app.advanced_features.cybersecurity_widget import CybersecurityWidget
from app.advanced_features.cloud_dashboard import CloudDashboardWidget
from app.advanced_features.recon_suite import ReconSuiteWidget
from app.advanced_features.superpowers_widget import SuperpowersWidget

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        activity_logger.log("Application Started")
        self.settings = QSettings(AppConfig.ORG_NAME, "AstraCommand")
        self.setWindowTitle(f"Astra Command v{AppConfig.APP_VERSION}")
        
        self.task_manager = TaskManager()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.nav_bar = QListWidget()
        self.nav_bar.setObjectName("NavBar")
        self.nav_bar.setFixedWidth(200)
        # --- NEW: Set icon size for the nav bar ---
        self.nav_bar.setIconSize(QSize(24, 24))
        
        self.stack = QStackedWidget()
        
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.nav_bar)
        self.splitter.addWidget(self.stack)
        self.splitter.setSizes([200, 1080])
        self.splitter.setHandleWidth(1)

        main_layout.addWidget(self.splitter)
        
        self._create_domains()
        self._create_menus()
        
        self.nav_bar.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav_bar.currentRowChanged.connect(self.log_domain_change)
        
        self.load_settings()
        self.nav_bar.setCurrentRow(0)

    def log_domain_change(self, index):
        domain_name = self.nav_bar.item(index).text().strip()
        activity_logger.log("Domain Viewed", f"Switched to '{domain_name}' domain.")

    def _create_domains(self):
        # --- NEW: Define domains with their icons ---
        domains = [
            {"name": "Network Operations", "widget": NetworkOpsWidget, "icon": "network"},
            {"name": "Cybersecurity", "widget": CybersecurityWidget, "icon": "security"},
            {"name": "DevOps & Cloud", "widget": CloudDashboardWidget, "icon": "cloud"},
            {"name": "Red Team Operations", "widget": ReconSuiteWidget, "icon": "red_team"},
            {"name": "Superpowers", "widget": SuperpowersWidget, "icon": "superpowers"}
        ]

        for domain in domains:
            # Add widget to stack
            widget = domain["widget"](self.settings, self.task_manager)
            self.stack.addWidget(widget)
            
            # --- NEW: Create list item with icon and text ---
            item = QListWidgetItem(icon_manager.get_icon(domain["icon"]), domain["name"])
            self.nav_bar.addItem(item)
            
    def _create_menus(self):
        menu_bar = self.menuBar()
        
        self.sidebar_toggle_btn = QToolButton()
        self.sidebar_toggle_btn.setIcon(QIcon(str(AppConfig.ASSETS_DIR / "menu.svg")))
        self.sidebar_toggle_btn.setToolTip("Toggle Sidebar")
        self.sidebar_toggle_btn.clicked.connect(self.toggle_sidebar)
        menu_bar.setCornerWidget(self.sidebar_toggle_btn, Qt.Corner.TopLeftCorner)

        file_menu = menu_bar.addMenu("&File"); file_menu.addAction("E&xit", self.close)
        help_menu = menu_bar.addMenu("&Help"); help_menu.addAction("&About", self.show_about_dialog)
        self.theme_button_container = QWidget()
        theme_layout = QHBoxLayout(self.theme_button_container)
        theme_layout.setContentsMargins(0,0,10,0)
        self.theme_toggle_button = QToolButton(); self.theme_toggle_button.setToolTip("Toggle light/dark theme")
        theme_layout.addWidget(self.theme_toggle_button)
        menu_bar.setCornerWidget(self.theme_button_container)
        self.theme_toggle_button.clicked.connect(self.toggle_theme)

    def toggle_sidebar(self):
        sizes = self.splitter.sizes()
        if sizes[0] > 0:
            self.splitter.setSizes([0, sizes[1]])
        else:
            self.splitter.setSizes([200, sizes[1]])

    def toggle_theme(self):
        is_dark = "#2b2b2b" in self.styleSheet() or "#252526" in self.styleSheet()
        if is_dark: self.set_stylesheet("light"); activity_logger.log("Theme Changed", "Switched to Light Theme")
        else: self.set_stylesheet("dark"); activity_logger.log("Theme Changed", "Switched to Dark Theme")
    
    def set_stylesheet(self, theme: str):
        if theme == "light":
            self.setStyleSheet(qss_light_theme)
            self.theme_toggle_button.setIcon(QIcon(str(AppConfig.ASSETS_DIR / "dark_mode.svg")))
        else: # dark
            self.setStyleSheet(qss_dark_theme)
            self.theme_toggle_button.setIcon(QIcon(str(AppConfig.ASSETS_DIR / "light_mode.svg")))

    def show_about_dialog(self):
        QMessageBox.about(self, f"About Astra Command", f"Version: {AppConfig.APP_VERSION}\nThe all-in-one command platform for technical operations.")

    def load_settings(self):
        self.resize(self.settings.value("window_size", QSize(1280, 720)))
        self.move(self.settings.value("window_pos", QPoint(100, 100)))
        if self.settings.contains("windowState"): self.restoreState(self.settings.value("windowState"))
        
        theme = self.settings.value("theme", "dark")
        self.set_stylesheet(theme)

    def closeEvent(self, event):
        activity_logger.log("Application Closed")
        self.settings.setValue("window_size", self.size())
        self.settings.setValue("window_pos", self.pos())
        self.settings.setValue("windowState", self.saveState())
        self.settings.setValue("theme", "dark" if "#252526" in self.styleSheet() else "light")
        self.task_manager.cancel_all()
        event.accept()
