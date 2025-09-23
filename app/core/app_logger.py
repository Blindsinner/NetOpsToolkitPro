# -*- coding: utf-8 -*-
import logging
from app.config import AppConfig

class AppLogger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AppLogger, cls).__new__(cls)
            # Set up the logger
            cls._instance.logger = logging.getLogger('UserActivity')
            cls._instance.logger.setLevel(logging.INFO)
            handler = logging.FileHandler(AppConfig.ACTIVITY_LOG_FILE)
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            handler.setFormatter(formatter)
            cls._instance.logger.addHandler(handler)
            # Prevent logs from propagating to the root logger
            cls._instance.logger.propagate = False
        return cls._instance

    def log(self, action: str, details: str = ""):
        """Logs a user action."""
        message = f"ACTION: {action}"
        if details:
            message += f" | DETAILS: {details}"
        self.logger.info(message)

# Global instance for easy access
activity_logger = AppLogger()