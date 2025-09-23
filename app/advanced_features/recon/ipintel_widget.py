# app/advanced_features/recon/ipintel_widget.py
# Lightweight IP intelligence widget. No new deps beyond your existing stack.
# Uses stdlib (socket) + httpx (already installed) for RDAP/GeoIP/ASN lookups.

import asyncio
import ipaddress
import socket
from typing import List, Tuple

import httpx
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QFormLayout,
    QLineEdit, QPushButton, QTextEdit, QLabel
)

from app.widgets.base_widget import BaseToolWidget


RDAP_ENDPOINT = "https://rdap.org/ip/{ip}"
GEOIP_ENDPOINT = "https://ipapi.co/{ip}/json/"
BGPVIEW_IP_ENDPOINT = "https://api.bgpview.io/ip/{ip}"
BGPVIEW_ASN_ENDPOINT = "https://api.bgpview.io/asn/{asn}"


class IPIntelWidget(BaseToolWidget):
    """
    IP & Host intelligence:
      • Resolve hostname → IPs and reverse PTR
      • RDAP summary (registrant, handle, ranges)
      • GeoIP (country, city, ASN if provided)
      • ASN details via BGPView (org, prefixes)
    All network I/O is async and scheduled via the existing task manager.
    """

    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)
        self._build_ui()

    # ---------------- UI ----------------
    def _build_ui(self):
        root = QVBoxLayout(self)

        # Target
        tgt_box = QGroupBox("Target")
        tgt_form = QFormLayout(tgt_box)
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("IPv4/IPv6 or hostname (e.g., 1.1.1.1 or example.com)")

        btn_row = QHBoxLayout()
        self.btn_resolve = QPushButton("Resolve / PTR")
        self.btn_rdap = QPushButton("RDAP")
        self.btn_geo = QPushButton("GeoIP")
        self.btn_asn = QPushButton("ASN Info")
        btn_row.addWidget(self.btn_resolve)
        btn_row.addWidget(self.btn_rdap)
        btn_row.addWidget(self.btn_geo)
        btn_row.addWidget(self.btn_asn)

        tgt_form.addRow("Input:", self.input_edit)
        tgt_form.addRow(btn_row)

        # Output
        self.out = QTextEdit()
        self.out.setReadOnly(True)

        note = QLabel(
            "Use only on targets you’re authorized to analyze. "
            "Public APIs may rate-limit; results are best-effort."
        )
        note.setWordWrap(True)

        root.addWidget(tgt_box)
        root.addWidget(self.out)
        root.addWidget(note)

        # Signals
        self.btn_resolve.clicked.connect(self._on_resolve)
        self.btn_rdap.clicked.connect(self._on_rdap)
        self.btn_geo.clicked.connect(self._on_geo)
        self.btn_asn.clicked.connect(self._on_asn)

    # ------------- Helpers -------------
    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except Exception:
            return False

    @staticmethod
    def _fmt_kv(title: str, kv: List[Tuple[str, str]]) -> str:
        lines = [f"== {title} =="]
        for k, v in kv:
            if v is None or v == "":
                continue
            lines.append(f"{k}: {v}")
        return "\n".join(lines)

    def _append_section(self, text: str):
        if text:
            self.out.append(text + "\n")

    # ------------- Actions -------------
    def _on_resolve(self):
        target = (self.input_edit.text() or "").strip()
        if not target:
            self.show_error("Enter an IP address or hostname.")
            return

        async def task():
            self._append_section(f"=== Resolve / PTR for: {target} ===")
            try:
                if self._is_ip(target):
                    # Reverse lookup (PTR)
                    try:
                        host, _, _ = await asyncio.to_thread(socket.gethostbyaddr, target)
                        self._append_section(self._fmt_kv("Reverse (PTR)", [("Hostname", host)]))
                    except Exception as e:
                        self._append_section(f"[PTR] No reverse found or error: {e}")
                else:
                    # Forward resolve (A/AAAA)
                    infos = await asyncio.to_thread(socket.getaddrinfo, target, None)
                    addrs = sorted({it[4][0] for it in infos})
                    if addrs:
                        self._append_section(self._fmt_kv("Forward (A/AAAA)", [("Addresses", ", ".join(addrs))]))
                    else:
                        self._append_section("[Resolve] No addresses found.")
            except Exception as e:
                self._append_section(f"[ERROR] Resolve failed: {e}")

        self.task_manager.create_task(task())

    def _on_rdap(self):
        target = (self.input_edit.text() or "").strip()
        if not target:
            self.show_error("Enter an IP address or hostname.")
            return

        async def task():
            try:
                ip = target
                if not self._is_ip(ip):
                    # resolve first ip
                    infos = await asyncio.to_thread(socket.getaddrinfo, ip, None, proto=socket.IPPROTO_TCP)
                    ip = infos[0][4][0] if infos else ip

                url = RDAP_ENDPOINT.format(ip=ip)
                async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                    r = await client.get(url)
                    if r.status_code >= 400:
                        self._append_section(f"[RDAP] HTTP {r.status_code}: {r.text[:400]}")
                        return
                    data = r.json()
                # Summarize some fields
                handle = data.get("handle") or data.get("name")
                start_addr = data.get("startAddress")
                end_addr = data.get("endAddress")
                country = (data.get("country") or "").upper()
                ent = ""
                try:
                    ents = data.get("entities") or []
                    if ents and isinstance(ents, list):
                        first = ents[0]
                        vcard = (first.get("vcardArray") or [None, []])[1]
                        org = ""
                        for row in vcard:
                            if row and len(row) >= 4 and row[0] == "fn":
                                org = row[3]
                                break
                        ent = org
                except Exception:
                    pass

                block = self._fmt_kv("RDAP Summary", [
                    ("Handle/Name", handle or "-"),
                    ("Range", f"{start_addr} - {end_addr}"),
                    ("Country", country or "-"),
                    ("Org", ent or "-"),
                ])
                self._append_section(block)
            except Exception as e:
                self._append_section(f"[ERROR] RDAP failed: {e}")

        self.task_manager.create_task(task())

    def _on_geo(self):
        target = (self.input_edit.text() or "").strip()
        if not target:
            self.show_error("Enter an IP address or hostname.")
            return

        async def task():
            try:
                ip = target
                if not self._is_ip(ip):
                    infos = await asyncio.to_thread(socket.getaddrinfo, ip, None, proto=socket.IPPROTO_TCP)
                    ip = infos[0][4][0] if infos else ip

                url = GEOIP_ENDPOINT.format(ip=ip)
                async with httpx.AsyncClient(timeout=20.0) as client:
                    r = await client.get(url)
                    if r.status_code >= 400:
                        self._append_section(f"[GeoIP] HTTP {r.status_code}: {r.text[:400]}")
                        return
                    j = r.json()

                block = self._fmt_kv("GeoIP", [
                    ("IP", j.get("ip") or ip),
                    ("Country", j.get("country_name")),
                    ("Region", j.get("region")),
                    ("City", j.get("city")),
                    ("Org", j.get("org")),
                    ("ASN", j.get("asn")),
                    ("Latitude", str(j.get("latitude") or j.get("lat") or "")),
                    ("Longitude", str(j.get("longitude") or j.get("lon") or "")),
                    ("Timezone", j.get("timezone")),
                ])
                self._append_section(block)
            except Exception as e:
                self._append_section(f"[ERROR] GeoIP failed: {e}")

        self.task_manager.create_task(task())

    def _on_asn(self):
        target = (self.input_edit.text() or "").strip()
        if not target:
            self.show_error("Enter an IP address or hostname.")
            return

        async def task():
            try:
                ip = target
                if not self._is_ip(ip):
                    infos = await asyncio.to_thread(socket.getaddrinfo, ip, None, proto=socket.IPPROTO_TCP)
                    ip = infos[0][4][0] if infos else ip

                # First: IP → ASN
                async with httpx.AsyncClient(timeout=20.0) as client:
                    r = await client.get(BGPVIEW_IP_ENDPOINT.format(ip=ip))
                    if r.status_code >= 400:
                        self._append_section(f"[ASN] HTTP {r.status_code}: {r.text[:400]}")
                        return
                    j = r.json()
                asn_list = (j.get("data") or {}).get("prefixes") or []
                if not asn_list:
                    self._append_section("[ASN] No prefixes/ASN found for IP.")
                    return
                # Pick the first ASN seen
                asn = None
                holder = None
                for p in asn_list:
                    asn = (p.get("asn") or {}).get("asn")
                    holder = (p.get("asn") or {}).get("name")
                    if asn:
                        break

                if not asn:
                    self._append_section("[ASN] No ASN in response.")
                    return

                # Now fetch ASN details
                async with httpx.AsyncClient(timeout=20.0) as client:
                    r2 = await client.get(BGPVIEW_ASN_ENDPOINT.format(asn=asn))
                    if r2.status_code >= 400:
                        self._append_section(f"[ASN] Details HTTP {r2.status_code}: {r2.text[:400]}")
                        return
                    a = r2.json().get("data") or {}

                name = a.get("name")
                desc = a.get("description_short") or a.get("description")
                country = a.get("country_code")
                prefixes_v4 = len(a.get("ipv4_prefixes") or [])
                prefixes_v6 = len(a.get("ipv6_prefixes") or [])

                block = self._fmt_kv("ASN", [
                    ("ASN", f"AS{asn}"),
                    ("Holder", holder or name or "-"),
                    ("Country", (country or "").upper()),
                    ("Prefixes v4", str(prefixes_v4)),
                    ("Prefixes v6", str(prefixes_v6)),
                    ("Description", desc or "-"),
                ])
                self._append_section(block)
            except Exception as e:
                self._append_section(f"[ERROR] ASN lookup failed: {e}")

        self.task_manager.create_task(task())

