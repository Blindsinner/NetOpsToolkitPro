# app/assets/icon_manager.py
# FINAL VERSION: The ICON_PATHS dictionary is now complete with all required icons.

from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtCore import QSize, Qt
from app.config import AppConfig

class IconManager:
    """A singleton class to manage, cache, and re-color QIcon objects for the application."""
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(IconManager, cls).__new__(cls, *args, **kwargs)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        
        # FIX: Added 'dashboard', 'config', 'performance', 'automation', and 'topology'
        # to the list of recognized icon names.
        self.ICON_PATHS = {
            "network": "network.svg",
            "security": "security.svg",
            "cloud": "cloud.svg",
            "red_team": "red_team.svg",
            "superpowers": "superpowers.svg",
            "settings": "settings.svg",
            "terminal": "terminal.svg",
            "scanner": "scanner.svg",
            "tools": "tools.svg",
            "config": "config.svg",
            "performance": "performance.svg",
            "automation": "automation.svg",
            "topology": "topology.svg",
            "dashboard": "dashboard.svg",
            "menu": "menu.svg",
            "light_mode": "light_mode.svg",
            "dark_mode": "dark_mode.svg",
        }
        self._cache = {}
        self._initialized = True

    def get_icon(self, name: str, color: QColor) -> QIcon:
        """
        Gets a QIcon for the given name, re-colored with the specified color.
        Caches results for performance. For best results, SVGs should be monochrome.
        """
        cache_key = (name, color.name())
        if cache_key in self._cache:
            return self._cache[cache_key]

        filename = self.ICON_PATHS.get(name)
        if not filename:
            print(f"Warning: Icon '{name}' not defined in IconManager.")
            return QIcon()

        path = AppConfig.ASSETS_DIR / "icons" / filename
        if not path.exists():
            print(f"Warning: Icon file not found at path: {path}")
            return QIcon()

        pixmap = QPixmap(QSize(256, 256))
        pixmap.fill(Qt.GlobalColor.transparent)

        painter = QPainter(pixmap)
        renderer = QSvgRenderer(str(path))
        
        if renderer.isValid():
            renderer.render(painter)

        mask = pixmap.createMaskFromColor(QColor("black"), Qt.MaskMode.MaskOutColor)
        painter.setPen(color)
        painter.drawPixmap(pixmap.rect(), mask, mask.rect())
        painter.end()

        icon = QIcon(pixmap)
        self._cache[cache_key] = icon
        return icon

# Global instance
icon_manager = IconManager()
