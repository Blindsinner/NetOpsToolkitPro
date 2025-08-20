# -*- coding: utf-8 -*-
from PySide6.QtGui import QIcon
from PySide6.QtCore import QSize
from app.config import AppConfig

class IconManager:
    """A singleton class to manage and provide QIcon objects for the application."""
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(IconManager, cls).__new__(cls, *args, **kwargs)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.ICON_PATHS = {
            "network": "network.svg",
            "security": "security.svg",
            "cloud": "cloud.svg",
            "red_team": "red_team.svg",
            "superpowers": "superpowers.svg",
            "terminal": "terminal.svg",
            "scanner": "scanner.svg",
            "tools": "tools.svg",
        }
        self._cache = {}
        self._initialized = True

    def get_icon(self, name: str) -> QIcon:
        """Gets a QIcon for the given name, caching it."""
        if name in self._cache:
            return self._cache[name]

        filename = self.ICON_PATHS.get(name)
        if not filename:
            print(f"Warning: Icon '{name}' not found in IconManager.")
            return QIcon()

        # This path is correct, it looks for the folder named "app"
        path = AppConfig.PROJECT_ROOT / "app" / "assets" / "icons" / filename
        if not path.exists():
            print(f"Warning: Icon file not found at path: {path}")
            return QIcon()

        icon = QIcon(str(path))
        self._cache[name] = icon
        return icon

# Global instance
icon_manager = IconManager()