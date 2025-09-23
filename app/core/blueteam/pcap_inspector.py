# app/core/blueteam/pcap_inspector.py
# Provides summarize_pcap() and format_report() expected by BlueTeamWidget.

from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Any, List

from scapy.all import rdpcap, TCP, UDP, ICMP, IP  # type: ignore

def summarize_pcap(path: str, limit: int = -1) -> Dict[str, Any]:
    pkts = rdpcap(path, count=limit)  # -1 reads all
    total = len(pkts)

    proto_counter = Counter()
    talker_counter = Counter()
    syn_by_src = defaultdict(int)

    for p in pkts:
        # protocol classification
        if TCP in p:
            proto_counter["TCP"] += 1
            # simple SYN heuristic
            try:
                flags = int(p[TCP].flags)
                if flags & 0x02:  # SYN
                    src = p[IP].src if IP in p else "?"
                    syn_by_src[src] += 1
            except Exception:
                pass
        elif UDP in p:
            proto_counter["UDP"] += 1
        elif ICMP in p:
            proto_counter["ICMP"] += 1
        else:
            name = p.lastlayer().name
            proto_counter[name] += 1

        # talkers
        if IP in p:
            talker_counter[(p[IP].src, p[IP].dst)] += 1

    top_talkers = [
        {"src": s, "dst": d, "count": c}
        for (s, d), c in talker_counter.most_common(15)
    ]

    alerts: List[str] = []
    for src, syns in sorted(syn_by_src.items(), key=lambda x: x[1], reverse=True)[:5]:
        if syns > 500:
            alerts.append(f"High SYN volume from {src}: {syns} SYN packets (possible SYN flood).")

    return {
        "file": path,
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "total_packets": total,
        "protocol_breakdown": dict(proto_counter),
        "top_talkers": top_talkers,
        "alerts": alerts,
    }

def format_report(summary: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"PCAP: {summary.get('file')}")
    lines.append(f"Analyzed: {summary.get('captured_at')}")
    lines.append(f"Total Packets: {summary.get('total_packets')}")
    lines.append("\nProtocol Breakdown:")
    for k, v in summary.get("protocol_breakdown", {}).items():
        lines.append(f"  - {k}: {v}")

    lines.append("\nTop Talkers:")
    for t in summary.get("top_talkers", []):
        lines.append(f"  - {t['src']} → {t['dst']}  ({t['count']} packets)")

    alerts = summary.get("alerts", [])
    if alerts:
        lines.append("\nAlerts:")
        for a in alerts:
            lines.append(f"  - {a}")

    return "\n".join(lines)
