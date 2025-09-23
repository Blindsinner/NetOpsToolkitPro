# app/core/recon/asn_engine.py
import asyncio
import socket
from typing import List, Dict, Optional, Tuple, Set
from PySide6.QtCore import QObject, Signal
import httpx
import tldextract


class ASNEngine(QObject):
    progress = Signal(str)
    error = Signal(str)
    finished = Signal(list)  # list[dict]

    def __init__(self, task_manager, timeout: float = 10.0, max_concurrency: int = 5):
        super().__init__()
        self.task_manager = task_manager
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self, asn_or_domain: str):
        self._cancel = False
        self.task_manager.create_task(self._run(asn_or_domain.strip()))

    async def _run(self, asn_or_domain: str):
        try:
            results = await self._resolve(asn_or_domain)
            if not self._cancel:
                self.finished.emit(results)
        except Exception as e:
            self.error.emit(f"ASNEngine failed: {e!r}")

    async def _resolve(self, query: str) -> List[Dict]:
        # parse input into ASNs (ints)
        asns: Set[int] = set()
        ips: Set[str] = set()
        q = query.upper().strip()
        if q.startswith("AS") and q[2:].isdigit():
            asns.add(int(q[2:]))
        elif q.isdigit():
            asns.add(int(q))
        else:
            hostname = query.strip()
            ext = tldextract.extract(hostname)
            if ext.domain and ext.suffix and not ext.subdomain:
                hostname = f"{ext.domain}.{ext.suffix}"
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
                for _, _, _, _, sockaddr in infos:
                    ips.add(sockaddr[0])
            except socket.gaierror:
                self.progress.emit(f"DNS resolution failed for {hostname}")
            for ip in ips:
                asn = await self._asn_from_ip_bgpview(ip)
                if asn:
                    asns.add(asn)

        rows: List[Dict] = []
        for asn in sorted(asns):
            if self._cancel:
                break
            meta, prefixes = await self._asn_details_bgpview(asn)
            for p in prefixes:
                rows.append({
                    "asn": asn,
                    "organization": meta.get("name") if meta else None,
                    "country": meta.get("country_code") if meta else None,
                    "cidr": p.get("prefix"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "source": "bgpview",
                })

        # dedupe by (asn, cidr)
        dedup = {}
        for r in rows:
            dedup[(r["asn"], r["cidr"])] = r
        return list(dedup.values())

    async def _asn_from_ip_bgpview(self, ip: str) -> Optional[int]:
        url = f"https://api.bgpview.io/ip/{ip}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    if data.get("prefixes"):
                        origins = data["prefixes"][0].get("asn", {})
                        asn = origins.get("asn")
                        if isinstance(asn, int):
                            self.progress.emit(f"IP {ip} belongs to AS{asn}")
                            return asn
                elif resp.status_code == 429:
                    self.progress.emit("bgpview.io rate-limited; retrying may help.")
            except Exception as e:
                self.progress.emit(f"bgpview.io error for {ip}: {e}")
        return None

    async def _asn_details_bgpview(self, asn: int) -> Tuple[Dict, List[Dict]]:
        meta = {}
        prefixes: List[Dict] = []
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                meta_resp = await client.get(f"https://api.bgpview.io/asn/{asn}")
                if meta_resp.status_code == 200:
                    meta = meta_resp.json().get("data", {})
            except Exception as e:
                self.progress.emit(f"Failed to fetch ASN meta for AS{asn}: {e}")
            try:
                pre_resp = await client.get(f"https://api.bgpview.io/asn/{asn}/prefixes")
                if pre_resp.status_code == 200:
                    data = pre_resp.json().get("data", {})
                    prefixes = data.get("ipv4_prefixes", []) + data.get("ipv6_prefixes", [])
                elif pre_resp.status_code == 429:
                    self.progress.emit("Rate-limited fetching prefixes; partial results shown.")
            except Exception as e:
                self.progress.emit(f"Failed to fetch prefixes for AS{asn}: {e}")
        return meta, prefixes

