# app/config.py
# CORRECTED: Added a specific QSS rule to fix QComboBox dropdowns in the light theme.

import sys
from pathlib import Path
from typing import List

class AppConfig:
    PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
    APP_NAME: str = "NetOps Toolkit Pro"
    APP_VERSION: str = "5.3.0"
    ORG_NAME: str = "Gemini-Tools"
    VENV_DIR: Path = PROJECT_ROOT / ".venv-netops-toolkit"
    LOG_FILE: Path = PROJECT_ROOT / "netops_toolkit.log"
    ACTIVITY_LOG_FILE: Path = PROJECT_ROOT / "user_activity.log"
    APP_DIR = Path(__file__).resolve().parent
    ASSETS_DIR: Path = APP_DIR / "assets"
    
    DEPENDENCIES: List[str] = [
        "PySide6", "httpx[http2]", "dnspython", "cryptography", "rich",
        "qasync", "python-whois", "psutil", "pyserial", "scapy",
        "netmiko", "pysnmp", "pyyaml", "networkx", "mac-vendor-lookup",
        "asyncssh", "boto3", "openai", "google-generativeai", "ollama", "easysnmp",
        "natsort", "vulners", "python-wappalyzer", "python-nmap"
    ]

IS_FROZEN = getattr(sys, 'frozen', False)

qss_light_theme = """
    QMainWindow, QDialog { background-color: #DBDBDB; }
    QWidget#MainContentPanel { background-color: #DBDBDB; }
    QWidget {
        font-family: Segoe UI, sans-serif;
        font-size: 10pt;
        color: #1c1c1c;
    }
    QMenuBar { background-color: #d0d0d0; color: #1c1c1c; border-bottom: 1px solid #c0c0c0; }
    QMenuBar::item:selected { background-color: #c0c0c0; }
    QMenu { background-color: #ffffff; border: 1px solid #c0c0c0; }
    QMenu::item:selected { background-color: #0078d7; color: #ffffff; }
    QListWidget#NavBar { background-color: #d0d0d0; border: none; border-right: 1px solid #c0c0c0; }
    QListWidget#NavBar::item { padding: 12px 15px; color: #1c1c1c; }
    QListWidget#NavBar::item:selected, QListWidget#NavBar::item:hover { background-color: #c0c0c0; border-left: 3px solid #0078d7; font-weight: bold; }
    QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox { background-color: #ffffff; border: 1px solid #c0c0c0; padding: 6px; border-radius: 4px; }
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border: 1px solid #0078d7; }
    
    /* FIX: Added specific rule for ComboBox dropdown menus in light mode */
    QComboBox QAbstractItemView {
        background-color: #ffffff;
        color: #1c1c1c;
        selection-background-color: #0078d7;
        selection-color: #ffffff;
    }

    QPushButton { background-color: #e1e1e1; border: 1px solid #c0c0c0; padding: 8px 12px; border-radius: 4px; font-weight: bold; }
    QPushButton:hover { background-color: #d1d1d1; }
    QPushButton:pressed { background-color: #c1c1c1; }
    QTableWidget, QTreeWidget { background-color: #ffffff; border: 1px solid #c0c0c0; }
    QHeaderView::section { background-color: #e1e1e1; padding: 5px; border: none; border-bottom: 1px solid #c0c0c0; }
    QTabBar::tab { background-color: transparent; color: #444444; padding: 10px 15px; border: 1px solid transparent; border-bottom: 2px solid transparent; margin-right: 2px; }
    QTabBar::tab:hover { color: #000000; }
    QTabBar::tab:selected { background-color: #DBDBDB; color: #000000; border: 1px solid #c0c0c0; border-bottom: 2px solid #DBDBDB; border-top-left-radius: 6px; border-top-right-radius: 6px; font-weight: bold; }
    QTabWidget::pane { border: 1px solid #c0c0c0; border-radius: 2px; background-color: #DBDBDB; }
    QGroupBox { border: 1px solid #c0c0c0; margin-top: 1ex; border-radius: 4px; }
    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
    QSplitter::handle { background-color: #c0c0c0; }
    QToolButton { border: none; padding: 4px; }
"""

qss_dark_theme = """
    QMainWindow, QDialog { background-color: #252526; }
    QWidget#MainContentPanel { background-color: #252526; }
    QWidget {
        font-family: Consolas, monospace;
        font-size: 11pt;
        color: #e0e0e0;
    }
    QMenuBar { background-color: #2d2d2d; color: #e0e0e0; border-bottom: 1px solid #3c3c3c; }
    QMenuBar::item:selected { background-color: #3e3e3e; }
    QMenu { background-color: #2d2d2d; border: 1px solid #3c3c3c; }
    QMenu::item:selected { background-color: #0078d7; }
    QListWidget#NavBar { background-color: #2d2d2d; border: none; border-right: 1px solid #3c3c3c; }
    QListWidget#NavBar::item { padding: 12px 15px; color: #cccccc; }
    QListWidget#NavBar::item:selected, QListWidget#NavBar::item:hover { background-color: #3e3e3e; border-left: 3px solid #0078d7; font-weight: bold; }
    QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox { background-color: #1e1e1e; border: 1px solid #3c3c3c; padding: 6px; border-radius: 4px; color: #e0e0e0; }
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border: 1px solid #0078d7; }
    QPushButton { background-color: #3e3e3e; border: 1px solid #555555; padding: 8px 12px; border-radius: 4px; font-weight: bold; }
    QPushButton:hover { background-color: #4f4f4f; }
    QPushButton:pressed { background-color: #2d2d2d; }
    QTableWidget, QTreeWidget { background-color: #1e1e1e; border: 1px solid #3c3c3c; }
    QHeaderView::section { background-color: #2d2d2d; padding: 5px; border: none; border-bottom: 1px solid #3c3c3c; }
    QTabBar::tab { background-color: transparent; color: #aaaaaa; padding: 10px 15px; border: 1px solid transparent; border-bottom: 2px solid transparent; margin-right: 2px; }
    QTabBar::tab:hover { color: #ffffff; }
    QTabBar::tab:selected { background-color: #252526; color: #ffffff; border: 1px solid #3c3c3c; border-bottom: 2px solid #252526; border-top-left-radius: 6px; border-top-right-radius: 6px; font-weight: bold; }
    QTabWidget::pane { border: 1px solid #3c3c3c; border-radius: 2px; background-color: #252526; }
    QGroupBox { border: 1px solid #3c3c3c; margin-top: 1ex; border-radius: 4px; }
    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
    QSplitter::handle { background-color: #3c3c3c; }
    QToolButton { border: none; padding: 4px; }
"""
