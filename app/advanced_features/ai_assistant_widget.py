# app/advanced_features/ai_assistant_widget.py
# REFACTORED: The main dialog is now an embeddable QWidget.

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QTextEdit, # QDialog changed to QWidget
    QLineEdit, QGroupBox, QFormLayout, QMessageBox, QLabel,
    QDoubleSpinBox, QSpinBox, QComboBox, QDialog
)
from PySide6.QtCore import Qt
from app.widgets.base_widget import BaseToolWidget
from app.core.ai_assistant import AIAssistant

# NOTE: The AIConfigDialog is correctly a QDialog as it's a pop-up for settings.
# No changes are needed for this class.
class AIConfigDialog(QDialog):
    """A dialog for configuring the AI Assistant settings."""
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("AI Assistant Configuration")
        self.setMinimumWidth(600)
        
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["Google Gemini", "OpenAI", "Ollama", "Custom"])
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.base_url_input = QLineEdit()
        self.model_input = QLineEdit()
        self.temp_spinbox = QDoubleSpinBox()
        self.temp_spinbox.setRange(0.0, 2.0); self.temp_spinbox.setSingleStep(0.1)
        self.tokens_spinbox = QSpinBox()
        self.tokens_spinbox.setRange(100, 16384); self.tokens_spinbox.setSingleStep(128)
        self.system_prompt_input = QTextEdit()
        
        self.custom_headers_label = QLabel("Custom Headers (JSON):")
        self.custom_headers_input = QTextEdit()
        self.custom_body_label = QLabel("Custom Body (JSON Template):")
        self.custom_body_input = QTextEdit()
        
        form.addRow("AI Provider:", self.provider_combo)
        form.addRow("API Key / Token:", self.api_key_input)
        form.addRow("Base URL / Host:", self.base_url_input)
        form.addRow("Model Name:", self.model_input)
        form.addRow("Temperature:", self.temp_spinbox)
        form.addRow("Max Tokens:", self.tokens_spinbox)
        form.addRow("System Prompt:", self.system_prompt_input)
        form.addRow(self.custom_headers_label, self.custom_headers_input)
        form.addRow(self.custom_body_label, self.custom_body_input)
        
        self.save_btn = QPushButton("Save Configuration")
        layout.addLayout(form)
        layout.addWidget(self.save_btn)
        
        self.provider_combo.currentTextChanged.connect(self.on_provider_change)
        self.load_settings()
        self.save_btn.clicked.connect(self.save_and_accept)

    def on_provider_change(self, provider):
        is_custom = provider == "Custom"
        self.custom_headers_label.setVisible(is_custom)
        self.custom_headers_input.setVisible(is_custom)
        self.custom_body_label.setVisible(is_custom)
        self.custom_body_input.setVisible(is_custom)
        
        self.api_key_input.setText(self.settings.value(f"ai/{provider}/api_key", ""))
        
        if provider == "Google Gemini":
            self.base_url_input.setText("N/A"); self.base_url_input.setEnabled(False)
            self.model_input.setText(self.settings.value(f"ai/{provider}/model", "gemini-1.5-flash"))
        elif provider == "OpenAI":
            self.base_url_input.setText(self.settings.value(f"ai/{provider}/base_url", "https://api.openai.com/v1")); self.base_url_input.setEnabled(True)
            self.model_input.setText(self.settings.value(f"ai/{provider}/model", "gpt-4o"))
        elif provider == "Ollama":
            self.base_url_input.setText(self.settings.value(f"ai/{provider}/base_url", "http://localhost:11434")); self.base_url_input.setEnabled(True)
            self.model_input.setText(self.settings.value(f"ai/{provider}/model", "llama3"))
        elif provider == "Custom":
             self.base_url_input.setEnabled(True)
             self.base_url_input.setText(self.settings.value(f"ai/{provider}/base_url", "http://localhost:1234/v1/chat/completions"))


    def load_settings(self):
        provider = self.settings.value("ai/provider", "Google Gemini")
        self.provider_combo.setCurrentText(provider)
        self.on_provider_change(provider)
        
        self.temp_spinbox.setValue(float(self.settings.value(f"ai/{provider}/temperature", 0.7)))
        self.tokens_spinbox.setValue(int(self.settings.value(f"ai/{provider}/max_tokens", 2048)))
        self.system_prompt_input.setText(self.settings.value(f"ai/{provider}/system_prompt", 
            "You are an expert-level assistant for Network, Cybersecurity, and DevOps engineers."))
        self.custom_headers_input.setText(self.settings.value("ai/Custom/custom_headers", '{"Authorization": "Bearer <KEY>"}'))
        self.custom_body_input.setText(self.settings.value("ai/Custom/custom_body", '{"model": "custom-model", "messages": [{"role": "user", "content": "{prompt}\\n\\n{context}"}]}'))
            
    def save_and_accept(self):
        provider = self.provider_combo.currentText()
        self.settings.setValue("ai/provider", provider)
        self.settings.setValue(f"ai/{provider}/api_key", self.api_key_input.text().strip())
        self.settings.setValue(f"ai/{provider}/base_url", self.base_url_input.text().strip())
        self.settings.setValue(f"ai/{provider}/model", self.model_input.text().strip())
        self.settings.setValue(f"ai/{provider}/temperature", self.temp_spinbox.value())
        self.settings.setValue(f"ai/{provider}/max_tokens", self.tokens_spinbox.value())
        self.settings.setValue(f"ai/{provider}/system_prompt", self.system_prompt_input.toPlainText().strip())
        if provider == "Custom":
            self.settings.setValue("ai/Custom/custom_headers", self.custom_headers_input.toPlainText())
            self.settings.setValue("ai/Custom/custom_body", self.custom_body_input.toPlainText())
        self.accept()

class AIAssistantWidget(BaseToolWidget): # REFACTORED: Class name and inheritance
    def __init__(self, settings, task_manager): # REFACTORED: Consistent constructor
        super().__init__(settings, task_manager)
        self.assistant = None
        
        # REFACTORED: Window setup removed.
        
        main_layout = QVBoxLayout(self)
        context_group = QGroupBox("Context (Paste logs, configs, or data here)")
        context_layout = QVBoxLayout(context_group)
        self.context_input = QTextEdit()
        context_layout.addWidget(self.context_input)
        main_layout.addWidget(context_group, stretch=2)

        prompt_group = QGroupBox("Prompt (What should the AI do?)")
        prompt_layout = QFormLayout(prompt_group)
        self.prompt_input = QLineEdit("Explain this in simple terms.")
        self.submit_btn = QPushButton("Ask Assistant")
        prompt_layout.addRow(self.prompt_input)
        prompt_layout.addRow(self.submit_btn)
        main_layout.addWidget(prompt_group)

        response_group = QGroupBox("AI Response")
        response_layout = QVBoxLayout(response_group)
        self.response_output = QTextEdit()
        self.response_output.setReadOnly(True)
        self.response_output.setMarkdown("")
        response_layout.addWidget(self.response_output)
        main_layout.addWidget(response_group, stretch=3)

        self.config_btn = QPushButton("Configure Assistant...")
        main_layout.addWidget(self.config_btn, alignment=Qt.AlignmentFlag.AlignRight)
        
        self.submit_btn.clicked.connect(self.run_analysis)
        self.config_btn.clicked.connect(self.open_config)

    def open_config(self):
        dialog = AIConfigDialog(self.settings, self)
        dialog.exec()

    def run_analysis(self):
        provider = self.settings.value("ai/provider", "Google Gemini")
        api_key = self.settings.value(f"ai/{provider}/api_key")
        if not api_key and provider not in ["Ollama"]:
            self.show_error(f"Please configure the AI Assistant with your {provider} API key first.")
            return

        settings = {s.split('/')[-1]: self.settings.value(s) for s in self.settings.allKeys() if s.startswith(f"ai/{provider}")}
        settings["provider"] = provider
        
        self.assistant = AIAssistant(settings)
        
        prompt = self.prompt_input.text().strip()
        context = self.context_input.toPlainText().strip()
        if not prompt or not context:
            self.show_error("Please provide both a context and a prompt.")
            return

        self.submit_btn.setEnabled(False)
        self.response_output.setText("")
        self.task_manager.create_task(
            self.get_and_stream_response(settings, prompt, context)
        )

    async def get_and_stream_response(self, settings, prompt, context):
        full_response = ""
        async for chunk in self.assistant.get_analysis_stream(settings, prompt, context):
            full_response += chunk
            self.response_output.setMarkdown(full_response)
            self.response_output.verticalScrollBar().setValue(self.response_output.verticalScrollBar().maximum())
        self.submit_btn.setEnabled(True)
