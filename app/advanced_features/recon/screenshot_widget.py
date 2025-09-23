# app/advanced_features/recon/screenshot_widget.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit, QPushButton, QFileDialog, QHBoxLayout
from app.widgets.base_widget import BaseToolWidget
from app.core.recon.screenshot_engine import ScreenshotEngine

class ScreenshotWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.engine = ScreenshotEngine(task_manager)
        self.engine.error.connect(self.show_error)
        self.engine.finished.connect(self._on_finished)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.urls_input = QTextEdit()
        self.urls_input.setPlaceholderText("Enter one URL per line")
        self.dir_btn = QPushButton("Choose Output Directory")
        self.dir_btn.clicked.connect(self._choose_dir)
        self.out_dir = QLineEdit()
        run = QPushButton("Screenshot")
        run.clicked.connect(self._run)
        form.addRow("URLs:", self.urls_input)
        form.addRow(self.dir_btn, self.out_dir)
        form.addRow(run)
        layout.addLayout(form)

        self.status = QTextEdit(readOnly=True)
        layout.addWidget(self.status)

        self.manifest = []

    def _choose_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if d:
            self.out_dir.setText(d)

    def _run(self):
        urls = [u.strip() for u in self.urls_input.toPlainText().splitlines() if u.strip()]
        if not urls:
            self.show_error("Enter at least one URL.")
            return
        out_dir = self.out_dir.text().strip()
        if not out_dir:
            self.show_error("Choose an output directory.")
            return
        self.status.clear()
        self.engine.run(urls, out_dir)

    def _on_finished(self, manifest):
        self.manifest = manifest
        self.status.append(f"Saved {len(manifest)} screenshots. Manifest written to folder.")

