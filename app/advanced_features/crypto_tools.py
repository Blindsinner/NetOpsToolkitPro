# -*- coding: utf-8 -*-
import hashlib
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
# --- FIX: Import the same KDF implementation as the credentials manager ---
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QWidget, QFormLayout, QLineEdit,
    QComboBox, QPushButton, QTextEdit, QFileDialog, QMessageBox, QLabel
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

# --- FIX: Use the IDENTICAL salt from CredentialsManager ---
SALT = b'netops-toolkit-pro-salt'

class CryptoToolsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        
        self.setWindowTitle("Cryptography Tools")
        self.setMinimumSize(600, 400)
        self.resize(600, 400)

        self.layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        self.tabs.addTab(self._create_hashing_tab(), "Hashing")
        self.tabs.addTab(self._create_encryption_tab(), "Symmetric Encryption (Fernet)")

    def _create_hashing_tab(self):
        widget = QWidget()
        layout = QFormLayout(widget)

        self.hash_input = QTextEdit()
        self.hash_input.setPlaceholderText("Enter text or drop a file here...")
        self.hash_input.setAcceptDrops(True)
        self.hash_input.dragEnterEvent = self.hash_drag_enter_event
        self.hash_input.dropEvent = self.hash_drop_event
        
        self.hash_algo_combo = QComboBox()
        self.hash_algo_combo.addItems(sorted(hashlib.algorithms_guaranteed))
        self.hash_algo_combo.setCurrentText("sha256")
        
        self.hash_output = QLineEdit()
        self.hash_output.setReadOnly(True)
        self.hash_output.setFont(QFont("Consolas", 10))

        calculate_button = QPushButton("Calculate Hash")
        calculate_button.clicked.connect(self.calculate_hash)

        layout.addRow(QLabel("Input Text or File:"), self.hash_input)
        layout.addRow(QLabel("Algorithm:"), self.hash_algo_combo)
        layout.addRow(calculate_button)
        layout.addRow(QLabel("Resulting Hash:"), self.hash_output)
        
        return widget

    def hash_drag_enter_event(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def hash_drop_event(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.load_file_for_hashing(file_path)

    def load_file_for_hashing(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                self.hash_input.setText(f"FILE_LOADED::{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not load file: {e}")

    def calculate_hash(self):
        algo = self.hash_algo_combo.currentText()
        hasher = hashlib.new(algo)
        input_text = self.hash_input.toPlainText()
        if input_text.startswith("FILE_LOADED::"):
            file_path = input_text.split("::", 1)[1]
            try:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        hasher.update(chunk)
            except Exception as e:
                self.hash_output.setText(f"Error reading file: {e}")
                return
        else:
            data = input_text.encode('utf-8')
            hasher.update(data)
        self.hash_output.setText(hasher.hexdigest())

    def _create_encryption_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        form_layout = QFormLayout()
        self.enc_input = QTextEdit()
        self.enc_password = QLineEdit()
        self.enc_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.enc_output = QTextEdit()
        self.enc_output.setReadOnly(True)
        generate_key_button = QPushButton("Generate New Fernet Key")
        encrypt_button = QPushButton("Encrypt")
        decrypt_button = QPushButton("Decrypt")
        form_layout.addRow("Plaintext/Ciphertext:", self.enc_input)
        form_layout.addRow("Master Password:", self.enc_password)
        layout.addLayout(form_layout)
        layout.addWidget(generate_key_button)
        layout.addWidget(encrypt_button)
        layout.addWidget(decrypt_button)
        layout.addWidget(QLabel("Output:"))
        layout.addWidget(self.enc_output)
        generate_key_button.clicked.connect(self.generate_fernet_key)
        encrypt_button.clicked.connect(self.perform_encrypt)
        decrypt_button.clicked.connect(self.perform_decrypt)
        return widget

    def _derive_key_from_password(self, password: str) -> bytes:
        """Derives a Fernet-compatible key from a user-provided password."""
        # --- FIX: Use IDENTICAL parameters to CredentialsManager ---
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=480000,
        )
        key = kdf.derive(password.encode('utf-8'))
        return base64.urlsafe_b64encode(key)

    def get_fernet_key(self):
        password = self.enc_password.text()
        if not password:
            QMessageBox.warning(self, "Warning", "A master password is required.")
            return None
        try:
            derived_key = self._derive_key_from_password(password)
            return Fernet(derived_key)
        except Exception as e:
             QMessageBox.critical(self, "Error", f"Could not derive key from password. Error: {e}")
             return None

    def generate_fernet_key(self):
        key = Fernet.generate_key()
        self.enc_output.setText(f"Generated Raw Fernet Key:\n{key.decode('utf-8')}")
        QMessageBox.information(self, "Key Generated", "A raw Fernet key has been generated and placed in the output box. This is different from using a master password.")


    def perform_encrypt(self):
        fernet = self.get_fernet_key()
        if not fernet: return
        try:
            token = fernet.encrypt(self.enc_input.toPlainText().encode('utf-8'))
            self.enc_output.setText(token.decode('utf-8'))
        except Exception as e:
            self.enc_output.setText(f"Encryption failed: {e}")

    def perform_decrypt(self):
        fernet = self.get_fernet_key()
        if not fernet: return
        try:
            decrypted_text = fernet.decrypt(self.enc_input.toPlainText().encode('utf-8'))
            self.enc_output.setText(decrypted_text.decode('utf-8'))
        except InvalidToken:
            self.enc_output.setText("Decryption failed: Invalid password or corrupted data.")
        except Exception as e:
            self.enc_output.setText(f"Decryption failed: {e}")