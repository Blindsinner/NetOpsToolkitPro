# -*- coding: utf-8 -*-
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PySide6.QtWidgets import QInputDialog, QLineEdit

class CredentialsManager:
    """Handles secure encryption and decryption of credentials."""

    def __init__(self):
        # We will store the key in memory for the session
        self.session_key = None

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derives a cryptographic key from a password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000, # Recommended number of iterations
        )
        return base64.urlsafe_b64encode(kdf.derive(password))

    def get_master_password(self, parent=None):
        """Prompts the user for the master password and caches the derived key."""
        if self.session_key:
            return True # Key is already in memory

        password, ok = QInputDialog.getText(parent, "Master Password",
            "Please enter your master password to unlock credentials:",
            QLineEdit.EchoMode.Password)

        if ok and password:
            # We use a static, known salt. For ultra-high security, this could be stored elsewhere.
            salt = b'netops-toolkit-pro-salt'
            self.session_key = self._derive_key(password.encode(), salt)
            return True
        return False

    def encrypt_password(self, plain_text_password: str) -> str:
        """Encrypts a device password using the session key."""
        if not self.session_key:
            raise ValueError("Master password has not been set for this session.")
        
        f = Fernet(self.session_key)
        encrypted_pass = f.encrypt(plain_text_password.encode())
        return encrypted_pass.decode('utf-8')

    def decrypt_password(self, encrypted_password: str) -> str:
        """Decrypts a device password using the session key."""
        if not self.session_key:
            raise ValueError("Master password has not been set for this session.")
            
        try:
            f = Fernet(self.session_key)
            decrypted_pass = f.decrypt(encrypted_password.encode())
            return decrypted_pass.decode('utf-8')
        except InvalidToken:
            # This indicates the master password was wrong
            raise ValueError("Invalid master password or corrupted data.")
        except Exception:
            # Handles cases where the data might not be encrypted at all
            return encrypted_password