# app/core/redteam/nmap_wrapper.py
from __future__ import annotations
from typing import Dict, Any, Iterable, List, Tuple
import nmap

class NmapWrapper:
    """
    Thin, controlled wrapper around python-nmap.
    Enforces an explicit allowlist to avoid accidental scans.
    """

    def __init__(self, allowlist: Iterable[str] | None = None) -> None:
        self.nm = nmap.PortScanner()
        self.set_allowlist(allowlist or [])

    def set_allowlist(self, items: Iterable[str]) -> None:
        self.allowlist = {i.strip() for i in items if i and i.strip()}

    def is_allowed(self, target: str) -> bool:
        return target.strip() in self.allowlist

    def scan_tcp(
        self,
        target: str,
        ports: str = "1-1024",
        arguments: str = "-sS -T4 -Pn",
    ) -> Dict[str, Any]:
        """
        Perform a TCP scan against an allowlisted target only.
        Returns the python-nmap structured dict.
        """
        if not self.is_allowed(target):
            raise PermissionError(
                f"Target '{target}' is not in the allowlist. "
                "Add it explicitly before scanning."
            )
        # python-nmap expects 'hosts' kwarg
        result = self.nm.scan(hosts=target, ports=ports, arguments=arguments)
        return result

    @staticmethod
    def summarize(result: Dict[str, Any]) -> str:
        """
        Produce a short, human-readable summary.
        """
        out: List[str] = []
        for host, hdata in result.get("scan", {}).items():
            out.append(f"Host: {host} ({hdata.get('status', {}).get('state','unknown')})")
            tcp = hdata.get("tcp", {})
            if tcp:
                ports: List[Tuple[int, Dict[str, Any]]] = sorted(tcp.items(), key=lambda x: x[0])
                for pnum, pdata in ports:
                    state = pdata.get("state", "?")
                    name = pdata.get("name", "?")
                    product = pdata.get("product") or ""
                    version = pdata.get("version") or ""
                    banner = (product + " " + version).strip()
                    out.append(f"  {pnum:>5}/tcp  {state:<7}  {name}  {banner}")
            else:
                out.append("  (no TCP results)")
        return "\n".join(out) if out else "No results."
