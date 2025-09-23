# email_utils.py
import re
from email.utils import formataddr
from pathlib import Path

def validate_email(email: str) -> bool:
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

def spoofed_address(name: str, email: str) -> str:
    return formataddr((name, email))

def load_template(brand: str, subject: str) -> str:
    base_path = Path(__file__).parent / "templates"
    brand_file = brand.lower().replace(" ", "_") + ".html"
    file_path = base_path / brand_file

    if not file_path.exists():
        return f"<html><body><h3>{brand}</h3><p>Template not found.</p></body></html>"

    try:
        content = file_path.read_text(encoding="utf-8")
        return content.replace("{title}", subject or "Security Notice")
    except Exception as e:
        return f"<html><body><h3>Template Error</h3><p>{e}</p></body></html>"
