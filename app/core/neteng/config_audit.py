# app/core/neteng/config_audit.py
from __future__ import annotations
from typing import Dict, Any, Iterable
import re

CHECKS = [
    ("Telnet enabled", re.compile(r"transport input\s+telnet\b", re.I)),
    ("No SSH on vty", re.compile(r"transport input\s+(?!.*ssh).*$", re.I|re.M)),
    ("Weak SNMP community", re.compile(r"snmp-server\s+community\s+(public|private)\b", re.I)),
    ("Enable password (not secret)", re.compile(r"^\s*enable password\b", re.I|re.M)),
    ("No password encryption", re.compile(r"^\s*no service password-encryption\b", re.I|re.M)),
]

def audit_config(text: str) -> Dict[str, Any]:
    findings = []
    for name, regex in CHECKS:
        if regex.search(text):
            findings.append(name)

    # basic positives
    positives = []
    if re.search(r"^\s*enable secret\b", text, re.I|re.M):
        positives.append("Has 'enable secret'")
    if re.search(r"ip ssh version\s*2\b", text, re.I):
        positives.append("SSH v2 configured")

    return {
        "findings": findings,
        "positives": positives,
        "score": max(0, 100 - 15*len(findings))  # toy score
    }

def format_report(result: Dict[str, Any]) -> str:
    out = []
    out.append(f"Security score (toy): {result['score']}/100")
    out.append("")
    out.append("Findings:")
    if result["findings"]:
        for f in result["findings"]:
            out.append(f"  - {f}")
    else:
        out.append("  (none)")
    out.append("")
    out.append("Good signs:")
    if result["positives"]:
        for p in result["positives"]:
            out.append(f"  - {p}")
    else:
        out.append("  (none)")
    return "\n".join(out)
