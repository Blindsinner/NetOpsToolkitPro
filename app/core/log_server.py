# -*- coding: utf-8 -*-
import socketserver
import re
import datetime
from PySide6.QtCore import QObject, Signal, QThread

# Syslog facilities and severities for parsing
FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "logaudit", "logalert", "cron", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]
SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Handles incoming syslog messages and emits them via a Qt signal."""
    def handle(self):
        data = self.request[0].strip()
        try:
            message = data.decode('utf-8')
            parsed = self.parse_syslog(message)
            parsed["host"] = self.client_address[0]
            self.server.message_signal.emit(parsed)
        except (UnicodeDecodeError, IndexError):
            # Ignore messages that can't be parsed
            pass

    def parse_syslog(self, message: str) -> dict:
        """Parses a standard RFC 3164 syslog message."""
        # Example: <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
        match = re.match(r'<(\d+)>([\s\S]*)', message)
        if not match:
            return {"facility": "unknown", "severity": "unknown", "message": message}

        priority = int(match.group(1))
        facility = priority >> 3
        severity = priority & 0x07
        
        return {
            "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "facility": FACILITIES[facility] if facility < len(FACILITIES) else "unknown",
            "severity": SEVERITIES[severity] if severity < len(SEVERITIES) else "unknown",
            "message": match.group(2).strip()
        }

class LogServerThread(QThread):
    """A dedicated QThread to run the blocking syslog server."""
    message_received = Signal(dict)
    server_started = Signal(str, int)
    server_stopped = Signal(str)

    def __init__(self, host, port, parent=None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.server = None

    def run(self):
        try:
            # Pass the Qt signal to the handler class
            SyslogUDPHandler.server = self
            self.server = socketserver.UDPServer((self.host, self.port), SyslogUDPHandler)
            self.server_started.emit(self.host, self.port)
            self.server.serve_forever()
        except Exception as e:
            self.server_stopped.emit(str(e))

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.server_stopped.emit("Server stopped by user.")