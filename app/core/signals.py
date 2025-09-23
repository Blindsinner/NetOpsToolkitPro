# app/core/signals.py
from PySide6.QtCore import QObject, Signal

class SignalManager(QObject):
    """A central hub for application-wide signals to enable inter-tool communication."""
    
    # Signal to request a network scan on a specific target
    # Emits a dictionary with 'target' and optional 'scan_type'
    request_network_scan = Signal(dict)
    
    # Signal to request a threat intelligence lookup on an IP
    # Emits the IP address string
    request_threat_intel = Signal(str)
    
    # Signal to request a WHOIS/GeoIP lookup on a target
    # Emits the target string (IP or domain)
    request_lookup = Signal(str)

# Global instance for easy access throughout the application
signal_manager = SignalManager()
