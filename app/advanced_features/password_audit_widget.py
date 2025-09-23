# app/advanced_features/password_audit_widget.py
from PySide6.QtWidgets import (
    QVBoxLayout, QFormLayout, QLineEdit, QPushButton, QComboBox,
    QGroupBox, QFileDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QHBoxLayout
)
from app.widgets.base_widget import BaseToolWidget
from app.core.password_auditor_engine import PasswordAuditorEngine

class PasswordAuditWidget(BaseToolWidget):
    """UI for the defensive Password Strength Auditor."""
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self.audit_thread = None

        layout = QVBoxLayout(self)
        
        input_group = QGroupBox("Audit Configuration")
        form = QFormLayout(input_group)
        
        self.hash_file_input = QLineEdit()
        self.wordlist_file_input = QLineEdit()
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(['md5', 'sha1', 'sha256', 'sha512'])
        
        hash_browse_btn = QPushButton("Browse...")
        wordlist_browse_btn = QPushButton("Browse...")
        
        hash_layout = QHBoxLayout()
        hash_layout.addWidget(self.hash_file_input)
        hash_layout.addWidget(hash_browse_btn)
        
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(self.wordlist_file_input)
        wordlist_layout.addWidget(wordlist_browse_btn)

        self.start_audit_btn = QPushButton("Start Audit")
        
        form.addRow("Hash File (user:hash format):", hash_layout)
        form.addRow("Wordlist File:", wordlist_layout)
        form.addRow("Hashing Algorithm:", self.algo_combo)
        form.addRow(self.start_audit_btn)
        
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)
        self.progress_bar = QProgressBar()
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Username", "Weak Password", "Hash Algorithm"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        results_layout.addWidget(self.progress_bar)
        results_layout.addWidget(self.results_table)

        layout.addWidget(input_group)
        layout.addWidget(results_group)

        # Connections
        hash_browse_btn.clicked.connect(lambda: self._browse_file(self.hash_file_input, "Select Hash File"))
        wordlist_browse_btn.clicked.connect(lambda: self._browse_file(self.wordlist_file_input, "Select Wordlist File"))
        self.start_audit_btn.clicked.connect(self.start_audit)

    def _browse_file(self, line_edit, title):
        path, _ = QFileDialog.getOpenFileName(self, title, "", "Text files (*.txt);;All files (*)")
        if path:
            line_edit.setText(path)

    def start_audit(self):
        hash_file = self.hash_file_input.text()
        wordlist_file = self.wordlist_file_input.text()
        algo = self.algo_combo.currentText()
        if not all([hash_file, wordlist_file, algo]):
            self.show_error("Please provide a hash file, wordlist, and algorithm.")
            return

        self.start_audit_btn.setEnabled(False)
        self.start_audit_btn.setText("Auditing...")
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)

        self.audit_thread = PasswordAuditorEngine(hash_file, wordlist_file, algo)
        self.audit_thread.progress_updated.connect(self.progress_bar.setValue)
        self.audit_thread.password_found.connect(self.add_found_password)
        self.audit_thread.audit_finished.connect(self.on_audit_finished)
        self.audit_thread.start()

    def add_found_password(self, user, password):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(user))
        self.results_table.setItem(row, 1, QTableWidgetItem(password))
        self.results_table.setItem(row, 2, QTableWidgetItem(self.algo_combo.currentText()))

    def on_audit_finished(self, message):
        self.show_info(message)
        self.start_audit_btn.setEnabled(True)
        self.start_audit_btn.setText("Start Audit")

    def shutdown(self):
        if self.audit_thread and self.audit_thread.isRunning():
            self.audit_thread.stop()
            self.audit_thread.wait()
