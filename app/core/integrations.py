# app/core/integrations.py
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import Optional, Dict
from PySide6.QtCore import QSettings


BINARIES = [
    "naabu", "httpx", "nuclei", "amass", "katana", "prowler"
]

@dataclass
class ZapConfig:
    base_url: str
    api_key: str

@dataclass
class GreenboneConfig:
    host: str
    user: str
    password: str
    port: int

@dataclass
class CloudConfig:
    aws_profile: str

@dataclass
class ExternalApis:
    shodan_key: str
    censys_id: str
    censys_secret: str
    securitytrails_key: str

def get_settings() -> QSettings:
    from app.config import AppConfig
    return QSettings(AppConfig.ORG_NAME, AppConfig.APP_NAME)

def get_zap_config() -> ZapConfig:
    s = get_settings()
    return ZapConfig(
        base_url=s.value("redteam/zap_base_url", "http://127.0.0.1:8090"),
        api_key=s.value("redteam/zap_api_key", ""),
    )

def get_greenbone_config() -> GreenboneConfig:
    s = get_settings()
    host = s.value("redteam/greenbone_host", "127.0.0.1")
    user = s.value("redteam/greenbone_user", "")
    passwd = s.value("redteam/greenbone_pass", "")
    port = int(s.value("redteam/greenbone_port", 9390))
    return GreenboneConfig(host=host, user=user, password=passwd, port=port)

def get_cloud_config() -> CloudConfig:
    s = get_settings()
    return CloudConfig(aws_profile=s.value("redteam/aws_profile", ""))

def get_external_apis() -> ExternalApis:
    s = get_settings()
    return ExternalApis(
        shodan_key=s.value("redteam/shodan_api_key", ""),
        censys_id=s.value("redteam/censys_api_id", ""),
        censys_secret=s.value("redteam/censys_api_secret", ""),
        securitytrails_key=s.value("redteam/securitytrails_api_key", ""),
    )

def set_values(values: Dict[str, str]) -> None:
    """Bulk set and save QSettings keys."""
    s = get_settings()
    for k, v in values.items():
        s.setValue(k, v)

def which_status() -> Dict[str, bool]:
    return {b: shutil.which(b) is not None for b in BINARIES}

def ensure_amass_config_from_settings() -> Optional[str]:
    """
    Build a minimal amass config file from stored APIs (if any).
    Returns path to generated config (under ~/.config/NetOps/amass.ini) or None if nothing to write.
    """
    apis = get_external_apis()
    needs = any([apis.shodan_key, apis.censys_id and apis.censys_secret, apis.securitytrails_key])
    if not needs:
        return None

    from pathlib import Path
    conf_dir = Path.home() / ".config" / "NetOpsToolkitPro"
    conf_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = conf_dir / "amass.ini"

    lines = ["# Auto-generated from NetOps Settings\n"]
    if apis.shodan_key:
        lines.append("[shodan]\napikey = {}\n".format(apis.shodan_key))
    if apis.censys_id and apis.censys_secret:
        lines.append("[censys]\nid = {}\nsecret = {}\n".format(apis.censys_id, apis.censys_secret))
    if apis.securitytrails_key:
        lines.append("[securitytrails]\napikey = {}\n".format(apis.securitytrails_key))

    cfg_path.write_text("\n".join(lines), encoding="utf-8")
    return str(cfg_path)

