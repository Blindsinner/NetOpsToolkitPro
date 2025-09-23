# app/advanced_features/crypto_tools.py
# REFACTORED: The encryption tab is now split into sub-tabs for clarity.

import hashlib
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget, QFormLayout, QLineEdit,
    QComboBox, QPushButton, QTextEdit, QFileDialog, QMessageBox, QLabel,
    QHBoxLayout # FIX: Added the missing QHBoxLayout import
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
from app.widgets.base_widget import BaseToolWidget

SALT = b'netops-toolkit-pro-salt'

class CryptoToolsWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        
        self.layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        self.tabs.addTab(self._create_hashing_tab(), "Hashing")
        self.tabs.addTab(self._create_encryption_tab(), "Symmetric Encryption (Fernet)")

    def _create_hashing_tab(self):
        widget = QWidget()
        layout = QFormLayout(widget)
        self.hash_input = QTextEdit(); self.hash_input.setPlaceholderText("Enter text or drop a file here...")
        self.hash_input.setAcceptDrops(True); self.hash_input.dragEnterEvent = self.hash_drag_enter_event
        self.hash_input.dropEvent = self.hash_drop_event
        self.hash_algo_combo = QComboBox(); self.hash_algo_combo.addItems(sorted(hashlib.algorithms_guaranteed))
        self.hash_algo_combo.setCurrentText("sha256")
        self.hash_output = QLineEdit(); self.hash_output.setReadOnly(True); self.hash_output.setFont(QFont("Consolas", 10))
        calculate_button = QPushButton("Calculate Hash")
        calculate_button.clicked.connect(self.calculate_hash)
        layout.addRow(QLabel("Input Text or File:"), self.hash_input)
        layout.addRow(QLabel("Algorithm:"), self.hash_algo_combo)
        layout.addRow(calculate_button)
        layout.addRow(QLabel("Resulting Hash:"), self.hash_output)
        return widget

    def _create_encryption_tab(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        enc_tabs = QTabWidget()
        main_layout.addWidget(enc_tabs)
        
        enc_tabs.addTab(self._create_password_enc_tab(), "Password-Based")
        enc_tabs.addTab(self._create_raw_key_enc_tab(), "Raw Key-Based")

        return main_widget

    def _create_password_enc_tab(self):
        """Creates the UI for encryption using a master password."""
        widget = QWidget()
        layout = QFormLayout(widget)
        self.pass_enc_input = QTextEdit()
        self.pass_enc_password = QLineEdit()
        self.pass_enc_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_enc_output = QTextEdit()
        self.pass_enc_output.setReadOnly(True)
        
        encrypt_button = QPushButton("Encrypt")
        decrypt_button = QPushButton("Decrypt")
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(encrypt_button)
        button_layout.addWidget(decrypt_button)
        
        layout.addRow("Plaintext / Ciphertext:", self.pass_enc_input)
        layout.addRow("Master Password:", self.pass_enc_password)
        layout.addRow(button_layout)
        layout.addRow("Output:", self.pass_enc_output)
        
        encrypt_button.clicked.connect(self.perform_password_encrypt)
        decrypt_button.clicked.connect(self.perform_password_decrypt)
        return widget

    def _create_raw_key_enc_tab(self):
        """Creates the UI for encryption using a raw Fernet key."""
        widget = QWidget()
        layout = QFormLayout(widget)
        self.raw_enc_input = QTextEdit()
        self.raw_enc_key = QLineEdit()
        self.raw_enc_output = QTextEdit()
        self.raw_enc_output.setReadOnly(True)
        
        generate_key_button = QPushButton("Generate New Fernet Key")
        encrypt_button = QPushButton("Encrypt")
        decrypt_button = QPushButton("Decrypt")
        
        key_layout = QHBoxLayout()
        key_layout.addWidget(self.raw_enc_key)
        key_layout.addWidget(generate_key_button)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(encrypt_button)
        button_layout.addWidget(decrypt_button)
        
        layout.addRow("Plaintext / Ciphertext:", self.raw_enc_input)
        layout.addRow("Raw Fernet Key:", key_layout)
        layout.addRow(button_layout)
        layout.addRow("Output:", self.raw_enc_output)
        
        generate_key_button.clicked.connect(self.generate_fernet_key)
        encrypt_button.clicked.connect(self.perform_raw_key_encrypt)
        decrypt_button.clicked.connect(self.perform_raw_key_decrypt)
        return widget

    def perform_password_encrypt(self):
        fernet = self._get_fernet_from_password()
        if not fernet: return
        try:
            token = fernet.encrypt(self.pass_enc_input.toPlainText().encode('utf-8'))
            self.pass_enc_output.setText(token.decode('utf-8'))
        except Exception as e:
            self.pass_enc_output.setText(f"Encryption failed: {e}")

    def perform_password_decrypt(self):
        fernet = self._get_fernet_from_password()
        if not fernet: return
        try:
            decrypted_text = fernet.decrypt(self.pass_enc_input.toPlainText().encode('utf-8'))
            self.pass_enc_output.setText(decrypted_text.decode('utf-8'))
        except InvalidToken:
            self.pass_enc_output.setText("Decryption failed: Invalid password or corrupted data.")
        except Exception as e:
            self.pass_enc_output.setText(f"Decryption failed: {e}")

    def _get_fernet_from_password(self):
        password = self.pass_enc_password.text()
        if not password: self.show_error("A master password is required."); return None
        try:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, iterations=480000)
            key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
            return Fernet(key)
        except Exception as e: self.show_error(f"Could not derive key: {e}"); return None

    def generate_fernet_key(self):
        key = Fernet.generate_key()
        self.raw_enc_key.setText(key.decode('utf-8'))
        self.show_info("New raw Fernet key generated.")

    def perform_raw_key_encrypt(self):
        fernet = self._get_fernet_from_raw_key()
        if not fernet: return
        try:
            token = fernet.encrypt(self.raw_enc_input.toPlainText().encode('utf-8'))
            self.raw_enc_output.setText(token.decode('utf-8'))
        except Exception as e:
            self.raw_enc_output.setText(f"Encryption failed: {e}")

    def perform_raw_key_decrypt(self):
        fernet = self._get_fernet_from_raw_key()
        if not fernet: return
        try:
            decrypted_text = fernet.decrypt(self.raw_enc_input.toPlainText().encode('utf-8'))
            self.raw_enc_output.setText(decrypted_text.decode('utf-8'))
        except InvalidToken:
            self.raw_enc_output.setText("Decryption failed: Invalid key or corrupted data.")
        except Exception as e:
            self.raw_enc_output.setText(f"Decryption failed: {e}")

    def _get_fernet_from_raw_key(self):
        key = self.raw_enc_key.text().strip()
        if not key: self.show_error("A raw Fernet key is required."); return None
        try:
            return Fernet(key.encode('utf-8'))
        except Exception as e: self.show_error(f"Invalid Fernet key: {e}"); return None
        
    def hash_drag_enter_event(self, event):
        if event.mimeData().hasUrls(): event.acceptProposedAction()
    def hash_drop_event(self, event):
        if event.mimeData().urls(): self.load_file_for_hashing(event.mimeData().urls()[0].toLocalFile())
    def load_file_for_hashing(self, file_path):
        try:
            with open(file_path, 'rb') as f: self.hash_input.setText(f"FILE_LOADED::{file_path}")
        except Exception as e: self.show_error(f"Could not load file: {e}")
    def calculate_hash(self):
        algo = self.hash_algo_combo.currentText(); hasher = hashlib.new(algo)
        input_text = self.hash_input.toPlainText()
        if input_text.startswith("FILE_LOADED::"):
            file_path = input_text.split("::", 1)[1]
            try:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192): hasher.update(chunk)
            except Exception as e: self.hash_output.setText(f"Error reading file: {e}"); return
        else:
            hasher.update(input_text.encode('utf-8'))
        self.hash_output.setText(hasher.hexdigest())
