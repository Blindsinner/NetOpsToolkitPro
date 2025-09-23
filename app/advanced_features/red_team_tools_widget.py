from __future__ import annotations
import csv, mimetypes, socket, ssl, smtplib, ipaddress
from email.message import EmailMessage
from pathlib import Path
from typing import List


from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QGroupBox, QFormLayout,
QLineEdit, QTextEdit, QPushButton, QSpinBox, QCheckBox, QLabel,
QFileDialog, QMessageBox, QComboBox, QRadioButton, QButtonGroup,
QScrollArea, QSizePolicy, QStackedWidget
)


import dns.resolver
from app.core.phex.email_utils import load_template, spoofed_address, validate_email


class BaseToolWidget(QWidget):
    def __init__(self, settings=None, task_manager=None):
        super().__init__()


class _PhishingComposer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.attachments: List[Path] = []
        self.recipients: List[dict] = []

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        scroll.setWidget(container)

        root = QVBoxLayout(container)

        # Envelope Section
        env_box = QGroupBox("Envelope & Content")
        env_form = QFormLayout(env_box)
        self.from_name = QLineEdit("Natalia HR")
        self.from_addr = QLineEdit("faysaliteng@yandex.com")
        self.reply_to = QLineEdit()
        self.errors_to = QLineEdit()
        self.subject = QLineEdit("Urgent Policy Update")
        self.campaign = QLineEdit("HR-Notice")

        self.radio_manual = QRadioButton("Manual Input")
        self.radio_csv = QRadioButton("From CSV")
        self.radio_csv.setChecked(True)
        self.rec_mode_group = QButtonGroup()
        self.rec_mode_group.addButton(self.radio_manual)
        self.rec_mode_group.addButton(self.radio_csv)
        mode_row = QHBoxLayout()
        mode_row.addWidget(self.radio_manual)
        mode_row.addWidget(self.radio_csv)

        self.to_manual = QLineEdit()
        self.cc_manual = QLineEdit()
        self.bcc_manual = QLineEdit()

        self.to_csv = QLineEdit("recipients.csv")
        self.btn_browse_csv = QPushButton("Browse")
        csv_row = QHBoxLayout()
        csv_row.addWidget(self.to_csv)
        csv_row.addWidget(self.btn_browse_csv)

        self.brand = QComboBox()
        self.brand.addItems(["Generic", "Microsoft 365", "Google Workspace", "Okta", "GitHub"])

        self.priority_box = QComboBox()
        self.priority_box.addItems(["Normal", "Low", "High"])

        self.xmailer_box = QComboBox()
        self.xmailer_box.addItems(["- none -", "Microsoft Outlook", "Thunderbird", "Apple Mail", "Roundcube", "Gmail Web"])

        self.delivery_receipt = QLineEdit()
        self.read_receipt = QLineEdit()
        self.extra_header = QLineEdit()

        self.tracker = QCheckBox("Include tracker pixel")

        env_form.addRow("From (Name):", self.from_name)
        env_form.addRow("From (Email):", self.from_addr)
        env_form.addRow("Reply-To:", self.reply_to)
        env_form.addRow("Errors-To:", self.errors_to)
        env_form.addRow("Subject:", self.subject)
        env_form.addRow("Campaign:", self.campaign)
        env_form.addRow("Recipient Mode:", mode_row)
        env_form.addRow("To:", self.to_manual)
        env_form.addRow("CC:", self.cc_manual)
        env_form.addRow("BCC:", self.bcc_manual)
        env_form.addRow("CSV File:", csv_row)
        env_form.addRow("Template Theme:", self.brand)
        env_form.addRow("Priority:", self.priority_box)
        env_form.addRow("X-Mailer:", self.xmailer_box)
        env_form.addRow("Confirm Delivery:", self.delivery_receipt)
        env_form.addRow("Confirm Reading:", self.read_receipt)
        env_form.addRow("Add Header (X-Extra):", self.extra_header)
        env_form.addRow(self.tracker)

        # SMTP Settings
        smtp_box = QGroupBox("SMTP Settings")
        smtp_form = QFormLayout(smtp_box)
        self.smtp_host = QLineEdit("smtp.hostinger.com")
        self.smtp_port = QSpinBox(); self.smtp_port.setRange(1, 65535); self.smtp_port.setValue(465)
        self.smtp_tls = QCheckBox("Use STARTTLS")
        self.smtp_user = QLineEdit("support@bdpolishacademy.com")
        self.smtp_pass = QLineEdit("Ff01817018512@")
        self.smtp_pass.setEchoMode(QLineEdit.Password)
        self.confirm_send = QCheckBox("I understand this will send real emails")

        smtp_form.addRow("SMTP Server:", self.smtp_host)
        smtp_form.addRow("Port:", self.smtp_port)
        smtp_form.addRow("", self.smtp_tls)
        smtp_form.addRow("Username:", self.smtp_user)
        smtp_form.addRow("Password:", self.smtp_pass)
        smtp_form.addRow(self.confirm_send)

        # Buttons
        btns = QHBoxLayout()
        self.btn_template = QPushButton("Generate Template")
        self.btn_export_eml = QPushButton("Export .eml")
        self.btn_export_html = QPushButton("Export .html")
        self.btn_attach = QPushButton("Add Attachment")
        self.btn_clear_attach = QPushButton("Clear Attachments")
        self.btn_send = QPushButton("Send")
        for b in [self.btn_template, self.btn_export_eml, self.btn_export_html,
                  self.btn_attach, self.btn_clear_attach, self.btn_send]:
            b.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            btns.addWidget(b)

        self.attach_label = QLabel("Attachments: none")

        # HTML Editor
        self.html_code = QTextEdit()
        self.html_code.setMinimumHeight(400)
        self.html_preview = QTextEdit()
        self.html_preview.setReadOnly(True)
        self.html_preview.setMinimumHeight(400)

        self.editor_stack = QStackedWidget()
        self.editor_stack.addWidget(self.html_code)
        self.editor_stack.addWidget(self.html_preview)

        self.btn_html_mode = QPushButton("HTML Mode")
        self.btn_preview_mode = QPushButton("Preview Mode")
        mode_toggle_layout = QHBoxLayout()
        mode_toggle_layout.addWidget(self.btn_html_mode)
        mode_toggle_layout.addWidget(self.btn_preview_mode)
        mode_toggle_layout.addStretch()

        root.addWidget(env_box)
        root.addWidget(smtp_box)
        root.addLayout(btns)
        root.addWidget(self.attach_label)
        root.addWidget(QLabel("HTML Body:"))
        root.addLayout(mode_toggle_layout)
        root.addWidget(self.editor_stack)

        layout = QVBoxLayout(self)
        layout.addWidget(scroll)
        self.setLayout(layout)

        self.btn_browse_csv.clicked.connect(self._browse_csv)
        self.radio_manual.toggled.connect(self._toggle_mode)
        self.btn_template.clicked.connect(self._on_template)
        self.btn_export_eml.clicked.connect(self._on_export_eml)
        self.btn_export_html.clicked.connect(self._on_export_html)
        self.btn_attach.clicked.connect(self._on_add_attachment)
        self.btn_clear_attach.clicked.connect(self._on_clear_attachments)
        self.btn_send.clicked.connect(self._on_send)
        self.btn_html_mode.clicked.connect(self._show_html_editor)
        self.btn_preview_mode.clicked.connect(self._show_preview)
        self._toggle_mode()

    def _toggle_mode(self):
        manual = self.radio_manual.isChecked()
        self.to_manual.setEnabled(manual)
        self.cc_manual.setEnabled(manual)
        self.bcc_manual.setEnabled(manual)
        self.to_csv.setEnabled(not manual)
        self.btn_browse_csv.setEnabled(not manual)

    def _show_html_editor(self):
        self.editor_stack.setCurrentWidget(self.html_code)

    def _show_preview(self):
        html = self.html_code.toPlainText()
        self.html_preview.setHtml(html)
        self.editor_stack.setCurrentWidget(self.html_preview)

    def _browse_csv(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Select CSV", "", "CSV Files (*.csv)")
        if fn:
            self.to_csv.setText(fn)

    def _on_template(self):
        html = load_template(self.brand.currentText(), self.subject.text())
        self.html_code.setPlainText(html)
        self._show_preview()

    def _on_export_html(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save HTML", "phish.html", "HTML Files (*.html)")
        if fn:
            Path(fn).write_text(self.html_code.toPlainText(), encoding="utf-8")

    def _on_export_eml(self):
        try:
            dummy = {"email": "test@example.com"}
            msg = self.build_message(dummy)
            fn, _ = QFileDialog.getSaveFileName(self, "Save EML", "test.eml", "Email Files (*.eml)")
            if fn:
                Path(fn).write_bytes(msg.as_bytes())
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _on_add_attachment(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Attachments", "", "All Files (*)")
        for f in files:
            p = Path(f)
            if p.exists():
                self.attachments.append(p)
        self._refresh_attachments()

    def _on_clear_attachments(self):
        self.attachments.clear()
        self._refresh_attachments()

    def _refresh_attachments(self):
        if not self.attachments:
            self.attach_label.setText("Attachments: none")
        else:
            names = ", ".join(p.name for p in self.attachments)
            self.attach_label.setText(f"Attachments: {names}")

    def _on_send(self):
        if not self.confirm_send.isChecked():
            QMessageBox.warning(self, "Confirm Required", "Check the confirmation box to proceed.")
            return

        self.recipients.clear()
        if self.radio_manual.isChecked():
            for email in self.to_manual.text().split(","):
                if validate_email(email.strip()):
                    self.recipients.append({"email": email.strip()})
        else:
            path = Path(self.to_csv.text())
            if not path.exists():
                QMessageBox.warning(self, "CSV Missing", "CSV file does not exist.")
                return
            with open(path, newline='', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    if validate_email(row.get("email", "")):
                        self.recipients.append(row)

        if not self.recipients:
            QMessageBox.warning(self, "No Recipients", "No valid recipients found.")
            return

        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.smtp_host.text(), self.smtp_port.value(), context=context, timeout=10) as server:
                server.ehlo()
                if self.smtp_user.text():
                    server.login(self.smtp_user.text(), self.smtp_pass.text())
                for r in self.recipients:
                    msg = self.build_message(r)
                    server.send_message(msg)
        except Exception as e:
            QMessageBox.critical(self, "Send Failed", str(e))
            return

        QMessageBox.information(self, "Done", f"Sent to {len(self.recipients)} recipient(s).")

    def build_message(self, r: dict) -> EmailMessage:
        html = self.html_code.toPlainText()
        for key, val in r.items():
            html = html.replace(f"{{{key}}}", val)
        if self.tracker.isChecked():
            html += f'<img src="http://localhost/tracker.gif?id={r.get("email")}" width="1" height="1" style="display:none;">'

        msg = EmailMessage()
        msg["From"] = spoofed_address(self.from_name.text(), self.from_addr.text())
        msg["To"] = r["email"]
        msg["Subject"] = self.subject.text()

        if self.cc_manual.text(): msg["Cc"] = self.cc_manual.text()
        if self.bcc_manual.text(): msg["Bcc"] = self.bcc_manual.text()
        if self.reply_to.text(): msg["Reply-To"] = self.reply_to.text()
        if self.errors_to.text(): msg["Errors-To"] = self.errors_to.text()
        if self.delivery_receipt.text(): msg["Return-Receipt-To"] = self.delivery_receipt.text()
        if self.read_receipt.text(): msg["Disposition-Notification-To"] = self.read_receipt.text()
        if self.extra_header.text(): msg["X-Extra"] = self.extra_header.text()

        priority = self.priority_box.currentText()
        if priority == "High":
            msg["X-Priority"] = "1"
            msg["Importance"] = "High"
        elif priority == "Low":
            msg["X-Priority"] = "5"
            msg["Importance"] = "Low"

        xmailer = self.xmailer_box.currentText()
        if xmailer != "- none -":
            msg["X-Mailer"] = xmailer

        msg.set_content("This is a multipart HTML email.")
        msg.add_alternative(html, subtype="html")

        for file in self.attachments:
            ctype, _ = mimetypes.guess_type(str(file))
            maintype, subtype = (ctype or "application/octet-stream").split("/", 1)
            msg.add_attachment(file.read_bytes(), maintype=maintype, subtype=subtype, filename=file.name)

        return msg
class _SMTPDiagnostics(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        mx_box = QGroupBox("MX Lookup")
        mx_form = QFormLayout(mx_box)
        self.mx_domain = QLineEdit("example.com")
        self.btn_mx = QPushButton("Resolve MX")
        self.mx_out = QTextEdit(); self.mx_out.setReadOnly(True)
        mx_form.addRow("Domain:", self.mx_domain)
        mx_form.addRow(self.btn_mx)
        mx_form.addRow(self.mx_out)

        hs_box = QGroupBox("SMTP Handshake")
        hs_form = QFormLayout(hs_box)
        self.hs_host = QLineEdit("127.0.0.1")
        self.hs_port = QSpinBox(); self.hs_port.setRange(1, 65535); self.hs_port.setValue(1025)
        self.hs_tls = QCheckBox("Use STARTTLS")
        self.hs_user = QLineEdit()
        self.hs_pass = QLineEdit(); self.hs_pass.setEchoMode(QLineEdit.Password)
        self.btn_test = QPushButton("Test Handshake")
        self.hs_out = QTextEdit(); self.hs_out.setReadOnly(True)
        hs_form.addRow("Server:", self.hs_host)
        hs_form.addRow("Port:", self.hs_port)
        hs_form.addRow("", self.hs_tls)
        hs_form.addRow("Username:", self.hs_user)
        hs_form.addRow("Password:", self.hs_pass)
        hs_form.addRow(self.btn_test)
        hs_form.addRow(self.hs_out)

        layout.addWidget(mx_box)
        layout.addWidget(hs_box)

        self.btn_mx.clicked.connect(self._do_mx)
        self.btn_test.clicked.connect(self._do_handshake)

    def _do_mx(self):
        domain = self.mx_domain.text().strip()
        try:
            answers = dns.resolver.resolve(domain, "MX")
            results = "\n".join(f"{r.preference}\t{r.exchange}" for r in answers)
            self.mx_out.setText(results)
        except Exception as e:
            self.mx_out.setText(f"Failed to resolve MX: {e}")

    def _do_handshake(self):
        try:
            with smtplib.SMTP(self.hs_host.text(), self.hs_port.value(), timeout=10) as s:
                s.ehlo()
                if self.hs_tls.isChecked():
                    s.starttls()
                    s.ehlo()
                out = ["EHLO OK"]
                if self.hs_user.text() and self.hs_pass.text():
                    try:
                        s.login(self.hs_user.text(), self.hs_pass.text())
                        out.append("Login successful")
                    except Exception as e:
                        out.append(f"Login failed: {e}")
                out.append("\n".join(f"- {k}" for k in s.esmtp_features))
                self.hs_out.setText("\n".join(out))
        except Exception as e:
            self.hs_out.setText(f"Handshake failed: {e}")

class RedTeamToolsWidget(BaseToolWidget):
    def __init__(self, settings=None, task_manager=None):
        super().__init__(settings, task_manager)
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.addTab(_PhishingComposer(self), "🎭 Phishing Composer")
        self.tabs.addTab(_SMTPDiagnostics(self), "✉️ SMTP Diagnostics")
        layout.addWidget(self.tabs)
        self.setLayout(layout)


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    win = RedTeamToolsWidget()
    win.resize(1400, 900)
    win.setWindowTitle("Red Team Toolkit")
    win.show()
    sys.exit(app.exec())

