# app/core/blueteam/log_analyzer.py
from __future__ import annotations
import re
from collections import Counter
from typing import Dict, Any, Iterable

SEV_RE = re.compile(r"\b(DEBUG|INFO|NOTICE|WARN|WARNING|ERR|ERROR|CRIT|ALERT|EMERG)\b", re.I)
IP_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s", re.M)  # syslog-ish

KEYWORDS = ( "failed", "denied", "refused", "invalid", "timeout", "auth", "drop", "malware", "attack" )

def analyze_log(lines: Iterable[str], max_lines: int = 500_000) -> Dict[str, Any]:
    sev = Counter()
    ips = Counter()
    hosts = Counter()
    alerts = []
    total = 0

    for i, raw in enumerate(lines):
        if i >= max_lines:
            break
        line = raw.rstrip("\n")
        total += 1

        # severity
        m = SEV_RE.search(line)
        if m:
            sev[m.group(1).upper()] += 1

        # IPs
        for ip in IP_RE.findall(line):
            ips[ip] += 1

        # host (syslog-ish)
        m2 = HOST_RE.match(line)
        if m2:
            hosts[m2.group(1)] += 1

        low = line.lower()
        if any(k in low for k in KEYWORDS):
            alerts.append(line)

    return {
        "total_lines": total,
        "severity_counts": dict(sev),
        "top_ips": ips.most_common(20),
        "top_hosts": hosts.most_common(20),
        "alerts_sample": alerts[:200],
        "truncated": len(alerts) > 200,
    }

def format_report(stats: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"Total lines: {stats['total_lines']}")
    lines.append("")
    lines.append("Severity counts:")
    if stats["severity_counts"]:
        for k, v in sorted(stats["severity_counts"].items()):
            lines.append(f"  - {k}: {v}")
    else:
        lines.append("  (none detected)")
    lines.append("")

    lines.append("Top IPs:")
    if stats["top_ips"]:
        for ip, c in stats["top_ips"]:
            lines.append(f"  - {ip}: {c}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("Top Hosts:")
    if stats["top_hosts"]:
        for h, c in stats["top_hosts"]:
            lines.append(f"  - {h}: {c}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("Alert-like lines (sample):")
    if stats["alerts_sample"]:
        for a in stats["alerts_sample"]:
            lines.append("  " + a)
        if stats.get("truncated"):
            lines.append("  ... (truncated)")
    else:
        lines.append("  (none)")

    return "\n".join(lines)
