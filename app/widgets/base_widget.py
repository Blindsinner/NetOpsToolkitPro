# -*- coding: utf-8 -*-
from PySide6.QtWidgets import QWidget, QMessageBox, QApplication, QTableWidget, QFileDialog
from PySide6.QtCore import QSettings

from app.core.task_manager import TaskManager
from app.core.network_tools import NetworkTools
from app.core.system_tools import SystemTools

class BaseToolWidget(QWidget):
    def __init__(self, settings: QSettings, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.task_manager = task_manager
        self.network_tools = NetworkTools()
        self.system_tools = SystemTools()

    def show_error(self, message: str):
        QMessageBox.critical(self, "Error", message)

    def show_info(self, message: str):
        QMessageBox.information(self, "Info", message)

    def copy_to_clipboard(self, text: str):
        QApplication.clipboard().setText(text)
        self.show_info("Copied to clipboard!")

    # --- NEW: Helper functions for exporting table data ---
    def _copy_table_data(self, table: QTableWidget):
        header = [table.horizontalHeaderItem(c).text() for c in range(table.columnCount())]
        lines = ["\t".join(header)]
        for r in range(table.rowCount()):
            row_data = [table.item(r, c).text() if table.item(r, c) else "" for c in range(table.columnCount())]
            lines.append("\t".join(row_data))
        self.copy_to_clipboard("\n".join(lines))

    def _export_table_to_csv(self, table: QTableWidget, default_filename: str = "export.csv"):
        path, _ = QFileDialog.getSaveFileName(self, "Export to CSV", default_filename, "CSV Files (*.csv)")
        if not path: return
        
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                header = [table.horizontalHeaderItem(c).text() for c in range(table.columnCount())]
                f.write(",".join(header) + "\n")
                for r in range(table.rowCount()):
                    row_data = [f'"{table.item(r, c).text()}"' if table.item(r, c) else "" for c in range(table.columnCount())]
                    f.write(",".join(row_data) + "\n")
            self.show_info(f"Data successfully exported to {path}")
        except Exception as e:
            self.show_error(f"Failed to export file: {e}")

    def load_state(self): pass
    def save_state(self): pass
    def closeEvent(self, event): super().closeEvent(event)