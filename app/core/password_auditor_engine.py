# app/core/password_auditor_engine.py
import hashlib
from PySide6.QtCore import QThread, Signal

class PasswordAuditorEngine(QThread):
    """
    Runs a password audit in a background thread by comparing hashes against
    a wordlist of common passwords.
    """
    # Signal to update progress (current_count, total_count)
    progress_updated = Signal(int, int)
    # Signal when a hash is successfully matched (user, password)
    password_found = Signal(str, str)
    # Signal when the audit is complete
    audit_finished = Signal(str)

    def __init__(self, hash_file, wordlist_file, algorithm, parent=None):
        super().__init__(parent)
        self.hash_file = hash_file
        self.wordlist_file = wordlist_file
        self.algorithm = algorithm
        self.is_running = True
        self.user_hashes = {}  # Store as {hash: user}

    def run(self):
        """The main worker method, executed in a separate thread."""
        try:
            # 1. Load hashes from the input file
            with open(self.hash_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if ':' in line:
                        user, h = line.strip().split(':', 1)
                        self.user_hashes[h.lower()] = user
            
            if not self.user_hashes:
                self.audit_finished.emit("Error: No valid 'user:hash' entries found in the hash file.")
                return

            # 2. Get total wordlist count for progress bar
            total_words = sum(1 for line in open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore'))
            self.progress_updated.emit(0, total_words)

            # 3. Iterate through wordlist and compare hashes
            processed_words = 0
            hasher = hashlib.new(self.algorithm)

            with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for password in f:
                    if not self.is_running:
                        break
                    
                    password = password.strip()
                    h = hasher.copy()
                    h.update(password.encode('utf-8'))
                    hex_digest = h.hexdigest().lower()

                    if hex_digest in self.user_hashes:
                        user = self.user_hashes[hex_digest]
                        self.password_found.emit(user, password)
                        # Remove the found hash to avoid re-checking
                        del self.user_hashes[hex_digest]
                    
                    processed_words += 1
                    if processed_words % 10000 == 0: # Update progress every 10k words
                        self.progress_updated.emit(processed_words, total_words)
            
            self.progress_updated.emit(total_words, total_words)
            self.audit_finished.emit("Audit complete.")
        except FileNotFoundError as e:
            self.audit_finished.emit(f"Error: File not found - {e.filename}")
        except Exception as e:
            self.audit_finished.emit(f"An unexpected error occurred: {e}")

    def stop(self):
        self.is_running = False
