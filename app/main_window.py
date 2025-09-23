# app/main_window.py
# UPDATED: Bulletproof window flags + size caps reset so the main window can
#          minimize/maximize and be freely resized on Linux/Wayland/X11/Win/macOS.
#          Keeps your theme, icons, splitter behavior, and domains.

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QListWidget, QStackedWidget,
    QMessageBox, QToolButton, QSplitter, QListWidgetItem, QSizePolicy
)
from PySide6.QtGui import QIcon, QColor
from PySide6.QtCore import QSettings, QSize, QPoint, Qt
from app.advanced_features.redteam_assess import RedTeamAssessWidget
from app.config import AppConfig, qss_dark_theme, qss_light_theme
from app.core.task_manager import TaskManager
from app.core.app_logger import activity_logger
from app.assets.icon_manager import icon_manager

# Domain widgets
from app.widgets.network_ops_widget import NetworkOpsWidget
from app.advanced_features.cybersecurity_widget import CybersecurityWidget
from app.advanced_features.cloud_dashboard import CloudDashboardWidget
from app.advanced_features.security_testing import SecurityTestingWidget
from app.advanced_features.ai_assistant_widget import AIAssistantWidget
from app.widgets.settings_widget import SettingsWidget
from app.advanced_features.blue_team_widget import BlueTeamWidget


# Qt's "max size" sentinel
_QWIDGETSIZE_MAX = 16777215


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        activity_logger.log("Application Started")
        self.settings = QSettings(AppConfig.ORG_NAME, AppConfig.APP_NAME)
        self.setWindowTitle(f"{AppConfig.APP_NAME} v{AppConfig.APP_VERSION}")

        # ---- HARD-ENABLE NORMAL WINDOW BEHAVIOR ----
        # Make sure we are a real top-level window with system decorations.
        # Use setWindowFlag per-flag (safer than overwriting all flags).
        self.setWindowFlag(Qt.FramelessWindowHint, False)
        self.setWindowFlag(Qt.CustomizeWindowHint, False)
        self.setWindowFlag(Qt.Window, True)
        self.setWindowFlag(Qt.WindowSystemMenuHint, True)
        self.setWindowFlag(Qt.WindowCloseButtonHint, True)
        self.setWindowFlag(Qt.WindowMinimizeButtonHint, True)
        self.setWindowFlag(Qt.WindowMaximizeButtonHint, True)

        # Ensure geometry is not artificially capped
        self.setMinimumSize(QSize(640, 480))
        self.setMaximumSize(_QWIDGETSIZE_MAX, _QWIDGETSIZE_MAX)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.task_manager = TaskManager()

        # ---- CENTRAL WIDGET & LAYOUT ----
        central_widget = QWidget()
        central_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        central_widget.setMinimumSize(1, 1)
        central_widget.setMaximumSize(_QWIDGETSIZE_MAX, _QWIDGETSIZE_MAX)
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # ---- NAV + STACK IN SPLITTER ----
        self.nav_bar = QListWidget()
        self.nav_bar.setObjectName("NavBar")
        self.nav_bar.setFixedWidth(200)  # fixed width is fine; height expands
        self.nav_bar.setIconSize(QSize(24, 24))
        self.nav_bar.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)

        self.stack = QStackedWidget()
        self.stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.stack.setMinimumSize(1, 1)
        self.stack.setMaximumSize(_QWIDGETSIZE_MAX, _QWIDGETSIZE_MAX)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.nav_bar)
        self.splitter.addWidget(self.stack)
        self.splitter.setSizes([200, 1080])
        self.splitter.setHandleWidth(1)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setStretchFactor(0, 0)  # sidebar stays narrow
        self.splitter.setStretchFactor(1, 1)  # stack expands
        self.splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.splitter.setMinimumSize(1, 1)
        self.splitter.setMaximumSize(_QWIDGETSIZE_MAX, _QWIDGETSIZE_MAX)

        main_layout.addWidget(self.splitter)

        # ---- DOMAINS ----
        self.domains = [
    {"name": "Network Operations", "widget_class": NetworkOpsWidget, "icon_name": "network"},
    {"name": "Cybersecurity", "widget_class": CybersecurityWidget, "icon_name": "security"},
    {"name": "DevOps & Cloud", "widget_class": CloudDashboardWidget, "icon_name": "cloud"},
    {"name": "Red Team Operations", "widget_class": SecurityTestingWidget, "icon_name": "red_team"},
    {"name": "AI Assistant", "widget_class": AIAssistantWidget, "icon_name": "superpowers"},
    {"name": "Settings", "widget_class": SettingsWidget, "icon_name": "settings"},
    {"name": "🟦 Blue Team", "widget_class": BlueTeamWidget, "icon_name": "security"},
    # ✅ Use icon_name here instead of icon
    {
        "name": "Red Team (Assess)",
        "widget_class": RedTeamAssessWidget,
        "icon_name": "red_team",
        "tooltip": "Run real nuclei/naabu/amass/ZAP/OpenVAS/Shodan/Censys/Prowler assessments",
    },
]


        self._create_domains()
        self._create_menus()

        self.nav_bar.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav_bar.currentRowChanged.connect(self.log_domain_change)

        self.load_settings()
        self._force_resizable_sanity()  # final guard against any stray caps
        self.nav_bar.setCurrentRow(0)

    # ---- Helpers ----

    def _force_resizable_sanity(self):
        """Final guard to ensure nothing capped our window inadvertently."""
        self.setMaximumSize(_QWIDGETSIZE_MAX, _QWIDGETSIZE_MAX)
        if self.minimumWidth() < 400 or self.minimumHeight() < 300:
            self.setMinimumSize(640, 480)

    def log_domain_change(self, index):
        item = self.nav_bar.item(index)
        if not item:
            return
        domain_name = item.text().strip()
        activity_logger.log("Domain Viewed", f"Switched to '{domain_name}' domain.")

    def _create_domains(self):
        for domain in self.domains:
            widget = domain["widget_class"](self.settings, self.task_manager)
            widget.setObjectName("MainContentPanel")
            widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            widget.setMinimumSize(1, 1)
            widget.setMaximumSize(_QWIDGETSIZE_MAX, _QWIDGETSIZE_MAX)
            self.stack.addWidget(widget)
            item = QListWidgetItem(domain["name"])
            self.nav_bar.addItem(item)

        # Apply initial icons to nav items
        theme = self.settings.value("theme", "dark")
        icon_color = QColor("#1c1c1c") if theme == "light" else QColor("#e0e0e0")
        for i, domain in enumerate(self.domains):
            self.nav_bar.item(i).setIcon(icon_manager.get_icon(domain["icon_name"], icon_color))

    def _create_menus(self):
        menu_bar = self.menuBar()

        # Left corner: sidebar toggle
        self.sidebar_toggle_btn = QToolButton()
        self.sidebar_toggle_btn.setToolTip("Toggle Sidebar")
        self.sidebar_toggle_btn.clicked.connect(self.toggle_sidebar)
        menu_bar.setCornerWidget(self.sidebar_toggle_btn, Qt.Corner.TopLeftCorner)

        # Menus
        file_menu = menu_bar.addMenu("&File")
        file_menu.addAction("E&xit", self.close)
        help_menu = menu_bar.addMenu("&Help")
        help_menu.addAction("&About", self.show_about_dialog)

        # Right corner: theme toggle
        from PySide6.QtWidgets import QHBoxLayout  # local import to avoid cluttering header
        self.theme_button_container = QWidget()
        self.theme_button_container.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Minimum)
        theme_layout = QHBoxLayout(self.theme_button_container)
        theme_layout.setContentsMargins(0, 0, 10, 0)
        self.theme_toggle_button = QToolButton()
        self.theme_toggle_button.setToolTip("Toggle light/dark theme")
        theme_layout.addWidget(self.theme_toggle_button)
        menu_bar.setCornerWidget(self.theme_button_container)

        self.theme_toggle_button.clicked.connect(self.toggle_theme)

    def toggle_sidebar(self):
        sizes = self.splitter.sizes()
        left = sizes[0]
        right = sizes[1] if len(sizes) > 1 else 1
        self.splitter.setSizes([0, right] if left > 0 else [200, right])

    def toggle_theme(self):
        current_theme = self.settings.value("theme", "dark")
        self.set_stylesheet("light" if current_theme == "dark" else "dark")

    def set_stylesheet(self, theme: str):
        if theme == "light":
            self.setStyleSheet(qss_light_theme)
            icon_color = QColor("#1c1c1c")
        else:
            self.setStyleSheet(qss_dark_theme)
            icon_color = QColor("#e0e0e0")

        self.settings.setValue("theme", theme)
        self._update_icons_for_theme(icon_color, theme)

    def _update_icons_for_theme(self, color: QColor, theme: str):
        # Update nav icons
        for i, domain in enumerate(self.domains):
            self.nav_bar.item(i).setIcon(icon_manager.get_icon(domain["icon_name"], color))

        # Update corner widget icons
        self.theme_toggle_button.setIcon(
            icon_manager.get_icon("light_mode" if theme == "dark" else "dark_mode", color)
        )
        self.sidebar_toggle_btn.setIcon(icon_manager.get_icon("menu", color))

        # Let child widgets refresh their icons (if they implement update_icons)
        for i in range(self.stack.count()):
            widget = self.stack.widget(i)
            if hasattr(widget, "update_icons"):
                widget.update_icons(color)

    def show_about_dialog(self):
        QMessageBox.about(
            self,
            f"About {AppConfig.APP_NAME}",
            f"Version: {AppConfig.APP_VERSION}\nThe all-in-one command platform for technical operations.",
        )

    def load_settings(self):
        # Restore size/pos (but keep resizable, and guard bad values)
        size = self.settings.value("window_size", QSize(1280, 800))
        pos = self.settings.value("window_pos", QPoint(100, 100))
        if isinstance(size, QSize):
            self.resize(size)
        else:
            self.resize(QSize(1280, 800))
        if isinstance(pos, QPoint):
            self.move(pos)
        else:
            self.move(QPoint(100, 100))

        if self.settings.contains("windowState"):
            try:
                self.restoreState(self.settings.value("windowState"))
            except Exception:
                pass

        theme = self.settings.value("theme", "dark")
        self.set_stylesheet(theme)

    def closeEvent(self, event):
        activity_logger.log("Application Closed")
        self.settings.setValue("window_size", self.size())
        self.settings.setValue("window_pos", self.pos())
        self.settings.setValue("windowState", self.saveState())
        self.task_manager.cancel_all()
        event.accept()

