
from __future__ import annotations

from PySide6.QtCore import Qt, QUrl, Slot
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QLabel, QMessageBox

# Try to import QtWebEngine lazily; if unavailable or fails (e.g., sandbox), we fall back to a QLabel.
try:
    from PySide6.QtWebEngineWidgets import QWebEngineView  # type: ignore
    WEBENGINE_AVAILABLE = True
except Exception:
    QWebEngineView = None  # type: ignore
    WEBENGINE_AVAILABLE = False

class BrowserAutomationWidget(QWidget):
    def __init__(self, settings, task_manager, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.task_manager = task_manager

        self.url_bar = QLineEdit(self)
        self.url_bar.setPlaceholderText("https://example.com")
        self.btn_go = QPushButton("Go", self)

        header = QHBoxLayout()
        header.addWidget(QLabel("URL:"))
        header.addWidget(self.url_bar)
        header.addWidget(self.btn_go)

        self.layout = QVBoxLayout(self)
        self.layout.addLayout(header)


        if WEBENGINE_AVAILABLE:
            try:
                self.view = QWebEngineView(self)
                self.layout.addWidget(self.view, stretch=1)
                self.btn_go.clicked.connect(self._go)
                # sensible default
                self.url_bar.setText("https://example.com")
                self._go()
            except Exception as e:
                # Fallback if WebEngine cannot initialize (e.g., sandbox error).
                self._install_placeholder(str(e))
        else:
            self._install_placeholder("QtWebEngine not available.")

    def _install_placeholder(self, reason: str):
        msg = QLabel(f"QtWebEngine is unavailable in this environment.\nReason: {reason}\n"
                     "You can still paste URLs above and press Go to open in your system browser.")
        msg.setWordWrap(True)
        self.layout.addWidget(msg, stretch=1)
        self.btn_go.clicked.connect(self._open_external)

    @Slot()
    def _go(self):
        url_txt = self.url_bar.text().strip()
        if not url_txt:
            return
        if not url_txt.startswith("http"):
            url_txt = "http://" + url_txt
        if WEBENGINE_AVAILABLE and hasattr(self, "view"):
            self.view.setUrl(QUrl(url_txt))
        else:
            self._open_external()

    @Slot()
    def _open_external(self):
        # Use OS default browser
        import webbrowser
        url_txt = self.url_bar.text().strip() or "https://example.com"
        if not url_txt.startswith("http"):
            url_txt = "http://" + url_txt
        webbrowser.open(url_txt)
