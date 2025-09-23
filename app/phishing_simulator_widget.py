import mimetypes
import csv
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import List

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QTextEdit, QPushButton, QComboBox, QFileDialog,
    QMessageBox, QLabel, QCheckBox, QGroupBox, QSpinBox,
    QRadioButton, QButtonGroup
)


def validate_email(email: str) -> bool:
    return "@" in email and "." in email


def spoofed_address(name: str, addr: str) -> str:
    return f"{name} <{addr}>" if name else addr


def load_template(brand: str, subject: str) -> str:
    return f"""<html><body>
    <h2>{brand} - {subject}</h2>
    <p>This is a simulated phishing message for testing purposes only.</p>
    <p><a href="#">Click here to verify</a></p>
    </body></html>"""


class PhishingSimulator(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phishing Simulator")
        self.attachments: List[Path] = []

        layout = QVBoxLayout(self)

        # Envelope Settings
        env_group = QGroupBox("Email Envelope")
        env_form = QFormLayout(env_group)

        self.from_name = QLineEdit("IT Support")
        self.from_email = QLineEdit("it-support@example.com")

        # Recipient Mode Toggle
        self.recipient_mode_group = QButtonGroup(self)
        self.radio_manual = QRadioButton("Manual Entry")
        self.radio_csv = QRadioButton("CSV Upload")
        self.radio_manual.setChecked(True)
        self.recipient_mode_group.addButton(self.radio_manual)
        self.recipient_mode_group.addButton(self.radio_csv)

        mode_layout = QHBoxLayout()
        mode_layout.addWidget(self.radio_manual)
        mode_layout.addWidget(self.radio_csv)
        env_form.addRow("Recipient Mode:", mode_layout)

        # Manual Inputs
        self.to_manual = QLineEdit("")
        self.cc_manual = QLineEdit("")
        self.bcc_manual = QLineEdit("")

        # CSV input
        self.csv_path = QLineEdit("")
        self.csv_browse = QPushButton("Browse")
        csv_row = QHBoxLayout()
        csv_row.addWidget(self.csv_path)
        csv_row.addWidget(self.csv_browse)

        self.subject = QLineEdit("Security Alert")
        self.brand = QComboBox()
        self.brand.addItems(["Generic", "Microsoft 365", "Google Workspace", "Okta", "GitHub"])
        self.tracker_cb = QCheckBox("Include tracker pixel")

        env_form.addRow("From Name:", self.from_name)
        env_form.addRow("From Email:", self.from_email)
        env_form.addRow("To:", self.to_manual)
        env_form.addRow("CC (optional):", self.cc_manual)
        env_form.addRow("BCC (optional):", self.bcc_manual)
        env_form.addRow("CSV File:", csv_row)
        env_form.addRow("Subject:", self.subject)
        env_form.addRow("Brand:", self.brand)
        env_form.addRow(self.tracker_cb)

        # SMTP Settings
        smtp_group = QGroupBox("SMTP Settings")
        smtp_form = QFormLayout(smtp_group)

        self.smtp_host = QLineEdit("smtp.gmail.com")
        self.smtp_port = QSpinBox(); self.smtp_port.setRange(1, 65535); self.smtp_port.setValue(587)
        self.smtp_tls = QCheckBox("Use STARTTLS"); self.smtp_tls.setChecked(True)
        self.smtp_user = QLineEdit()
        self.smtp_pass = QLineEdit(); self.smtp_pass.setEchoMode(QLineEdit.Password)
        self.confirm_cb = QCheckBox("I confirm this will send real emails")

        smtp_form.addRow("SMTP Server:", self.smtp_host)
        smtp_form.addRow("Port:", self.smtp_port)
        smtp_form.addRow("", self.smtp_tls)
        smtp_form.addRow("SMTP Username:", self.smtp_user)
        smtp_form.addRow("SMTP Password:", self.smtp_pass)
        smtp_form.addRow(self.confirm_cb)

        # HTML Editor
        self.html_edit = QTextEdit()
        self.html_edit.setPlaceholderText("Write or paste HTML here...")

        # Attachment status
        self.attach_label = QLabel("Attachments: none")

        # Buttons
        btns = QHBoxLayout()
        self.btn_template = QPushButton("Generate Template")
        self.btn_attach = QPushButton("Add Attachment")
        self.btn_clear = QPushButton("Clear Attachments")
        self.btn_export_html = QPushButton("Export HTML")
        self.btn_export_eml = QPushButton("Export EML")
        self.btn_send = QPushButton("Send")

        for b in [self.btn_template, self.btn_attach, self.btn_clear,
                  self.btn_export_html, self.btn_export_eml, self.btn_send]:
            btns.addWidget(b)

        # Layout
        layout.addWidget(env_group)
        layout.addWidget(smtp_group)
        layout.addLayout(btns)
        layout.addWidget(self.attach_label)
        layout.addWidget(QLabel("HTML Body:"))
        layout.addWidget(self.html_edit)

        # Events
        self.csv_browse.clicked.connect(self.browse_csv)
        self.btn_template.clicked.connect(self.generate_template)
        self.btn_attach.clicked.connect(self.add_attachment)
        self.btn_clear.clicked.connect(self.clear_attachments)
        self.btn_export_html.clicked.connect(self.export_html)
        self.btn_export_eml.clicked.connect(self.export_eml)
        self.btn_send.clicked.connect(self.send_emails)
        self.radio_manual.toggled.connect(self.toggle_recipient_inputs)
        self.radio_csv.toggled.connect(self.toggle_recipient_inputs)

        self.toggle_recipient_inputs()

    def toggle_recipient_inputs(self):
        manual = self.radio_manual.isChecked()
        self.to_manual.setEnabled(manual)
        self.cc_manual.setEnabled(manual)
        self.bcc_manual.setEnabled(manual)
        self.csv_path.setEnabled(not manual)
        self.csv_browse.setEnabled(not manual)

    def browse_csv(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Choose CSV", "", "CSV Files (*.csv)")
        if fn:
            self.csv_path.setText(fn)

    def generate_template(self):
        html = load_template(self.brand.currentText(), self.subject.text())
        self.html_edit.setPlainText(html)

    def add_attachment(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Attachments", "", "All Files (*)")
        for f in files:
            path = Path(f)
            if path.exists():
                self.attachments.append(path)
        self.refresh_attachments()

    def clear_attachments(self):
        self.attachments.clear()
        self.refresh_attachments()

    def refresh_attachments(self):
        if not self.attachments:
            self.attach_label.setText("Attachments: none")
        else:
            names = ", ".join(p.name for p in self.attachments)
            self.attach_label.setText(f"Attachments: {names}")

    def export_html(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Export HTML", "lure.html", "HTML Files (*.html)")
        if fn:
            Path(fn).write_text(self.html_edit.toPlainText().strip(), encoding="utf-8")
            QMessageBox.information(self, "Saved", f"Saved HTML to:\n{fn}")

    def export_eml(self):
        msg = self.build_message({"email": "test@example.com"})
        fn, _ = QFileDialog.getSaveFileName(self, "Export EML", "lure.eml", "Email Files (*.eml)")
        if fn:
            Path(fn).write_bytes(msg.as_bytes())
            QMessageBox.information(self, "Saved", f"Saved EML to:\n{fn}")

    def get_recipients(self) -> List[dict]:
        recips = []
        if self.radio_manual.isChecked():
            for addr in self.to_manual.text().split(","):
                addr = addr.strip()
                if validate_email(addr):
                    recips.append({"email": addr})
        elif self.radio_csv.isChecked():
            csv_file = self.csv_path.text().strip()
            if csv_file and Path(csv_file).exists():
                with open(csv_file, newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if validate_email(row.get("email", "")):
                            recips.append(row)
        return recips

    def build_message(self, recipient: dict) -> EmailMessage:
        html = self.html_edit.toPlainText().strip() or load_template(self.brand.currentText(), self.subject.text())
        for key, val in recipient.items():
            html = html.replace(f"{{{key}}}", val)

        if self.tracker_cb.isChecked():
            html += '<img src="http://localhost/tracker.gif" width="1" height="1" style="display:none;"/>'

        msg = EmailMessage()
        msg["From"] = spoofed_address(self.from_name.text(), self.from_email.text())
        msg["To"] = recipient["email"]
        msg["Subject"] = self.subject.text()
        if self.cc_manual.text():
            msg["Cc"] = self.cc_manual.text()
        if self.bcc_manual.text():
            msg["Bcc"] = self.bcc_manual.text()

        msg.set_content("This is a multi-part message in MIME format.")
        msg.add_alternative(html, subtype="html")

        for p in self.attachments:
            ctype, _ = mimetypes.guess_type(str(p))
            maintype, subtype = (ctype or "application/octet-stream").split("/", 1)
            msg.add_attachment(p.read_bytes(), maintype=maintype, subtype=subtype, filename=p.name)

        return msg

    def send_emails(self):
        if not self.confirm_cb.isChecked():
            QMessageBox.warning(self, "Confirm Required", "Please confirm you want to send real emails.")
            return

        recipients = self.get_recipients()
        if not recipients:
            QMessageBox.warning(self, "No Recipients", "Please enter or load valid recipients.")
            return

        try:
            smtp = smtplib.SMTP(self.smtp_host.text(), self.smtp_port.value(), timeout=15)
            smtp.ehlo()
            if self.smtp_tls.isChecked():
                context = ssl.create_default_context()
                smtp.starttls(context=context)
                smtp.ehlo()
            if self.smtp_user.text() and self.smtp_pass.text():
                smtp.login(self.smtp_user.text(), self.smtp_pass.text())

            for r in recipients:
                try:
                    msg = self.build_message(r)
                    smtp.send_message(msg)
                except Exception as e:
                    print(f"Failed to send to {r['email']}: {e}")
            smtp.quit()
            QMessageBox.information(self, "Success", f"Sent to {len(recipients)} recipient(s).")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    window = PhishingSimulator()
    window.resize(950, 780)
    window.show()
    sys.exit(app.exec())

