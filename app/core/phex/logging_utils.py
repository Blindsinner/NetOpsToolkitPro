from pathlib import Path
from datetime import datetime

LOG_FILE = Path("logs/phishing.log")
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

def log_send(from_addr: str, to_addr: str, subject: str, campaign: str = "default"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    LOG_FILE.write_text(
        f"{timestamp} | Campaign: {campaign} | From: {from_addr} | To: {to_addr} | Subject: {subject}\n",
        encoding="utf-8",
        append=True
    )
