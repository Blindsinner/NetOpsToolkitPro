# app/core/topology_discoverer.py
# ENRICHED DISCOVERY:
# - Keeps your Linux ARP + Cisco CDP path.
# - Adds robust fact collection: hostname, technology/OS, IP, mask, MAC, vendor, username.
# - Returns a ready-to-draw NetworkX graph (nodes already carry 'details').

import asyncio
import re
import networkx as nx
from typing import Dict, Tuple, Any

from app.core.device_connector import DeviceConnector
from app.core.credentials_manager import CredentialsManager

try:
    from mac_vendor_lookup import MacLookup
except Exception:  # optional dependency fallback
    MacLookup = None


class TopologyDiscoverer:
    """
    Discovers network topology by crawling devices and enriching each node
    with facts like IP, subnet mask, hostname, technology/OS, MAC, vendor,
    and (where possible) the logged-in username.
    """

    def __init__(self, connector: DeviceConnector, cred_manager: CredentialsManager, logger):
        self.connector = connector
        self.cred_manager = cred_manager
        self.logger = logger
        self.mac_lookup = MacLookup() if MacLookup else None
        self.DISCOVERY_COMMANDS = {
            "cisco_ios": "show cdp neighbors detail",
            "cisco_nxos": "show cdp neighbors detail",
            "cisco_asa": "show cdp neighbors detail",
            "linux": "arp -n",
        }
        self.graph = nx.Graph()

    # ---------------------------
    # Helpers
    # ---------------------------
    async def _run(self, device_info: dict, command: str) -> Tuple[bool, str]:
        return await self.connector.run_command(device_info, command)

    @staticmethod
    def _first_group(pattern: re.Pattern, text: str, default: str = "N/A") -> str:
        m = pattern.search(text or "")
        return m.group(1).strip() if m else default

    async def _lookup_vendor(self, mac: str) -> str:
        mac = (mac or "").upper()
        if not mac or not self.mac_lookup:
            return "Unknown"
        try:
            # aio_lookup only exists on newer mac_vendor_lookup; fall back to sync if needed.
            if hasattr(self.mac_lookup, "aio_lookup"):
                return await self.mac_lookup.aio_lookup(mac)
            return self.mac_lookup.lookup(mac)
        except Exception:
            return "Unknown"

    # ---------------------------
    # Fact collectors
    # ---------------------------
    async def _collect_linux_facts(self, dev: dict) -> Dict[str, str]:
        facts = {
            "hostname": "N/A",
            "technology": "Linux",
            "ip": "N/A",
            "subnet_mask": "N/A",
            "mac": "N/A",
            "username": "N/A",
            "vendor": "Unknown",
        }

        ok, out = await self._run(dev, "hostnamectl 2>/dev/null || hostname")
        if ok and out.strip():
            hn = self._first_group(re.compile(r"Static hostname:\s*(.+)"), out, default="").strip()
            if not hn:
                hn = out.strip().splitlines()[0].strip()
            facts["hostname"] = hn

        ok, out = await self._run(dev, "uname -srm")
        if ok and out.strip():
            facts["technology"] = out.strip()

        # Route decision to get primary interface + source IP
        ok, out = await self._run(dev, "ip route get 1.1.1.1 | sed -n '1p'")
        primary_if = ""
        if ok and out:
            ip_m = re.search(r"\bsrc\s+([0-9.]+)", out)
            if_m = re.search(r"\bdev\s+(\S+)", out)
            if ip_m:
                facts["ip"] = ip_m.group(1)
            if if_m:
                primary_if = if_m.group(1)

        if primary_if:
            ok, out = await self._run(dev, f"ip -o -4 addr show dev {primary_if}")
            if ok and out:
                m = re.search(r"inet\s+([0-9.]+)/(\d+)", out)
                if m:
                    prefix = int(m.group(2))
                    mask_bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                    mask = ".".join(str((mask_bits >> (8 * i)) & 0xFF) for i in [3, 2, 1, 0])
                    facts["subnet_mask"] = mask

            ok, out = await self._run(dev, f"ip -o link show {primary_if}")
            if ok and out:
                mm = re.search(r"\blink/(?:ether|loopback)\s+([0-9a-f:]{17})", out, re.I)
                if mm:
                    mac = mm.group(1).upper()
                    facts["mac"] = mac
                    facts["vendor"] = await self._lookup_vendor(mac)

        ok, out = await self._run(dev, "who | awk '{print $1}' | head -n1")
        if ok and out.strip():
            facts["username"] = out.strip().splitlines()[0].strip()

        return facts

    async def _collect_cisco_facts(self, dev: dict) -> Dict[str, str]:
        facts = {
            "hostname": "N/A",
            "technology": "Cisco",
            "ip": "N/A",
            "subnet_mask": "N/A",
            "mac": "N/A",
            "username": "N/A",
            "vendor": "Cisco",
        }

        ok, out = await self._run(dev, "show running-config | include ^hostname")
        if ok and out:
            hn = self._first_group(re.compile(r"^hostname\s+(.+)$", re.M), out, default="N/A")
            facts["hostname"] = hn

        ok, out = await self._run(dev, "show version")
        if ok and out:
            for line in out.splitlines():
                if line.strip():
                    facts["technology"] = line.strip()
                    break

        chosen_if = ""
        ok, out = await self._run(dev, "show ip interface brief")
        if ok and out:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 6:
                    if_name, ip_addr = parts[0], parts[1]
                    status, proto = parts[-2].lower(), parts[-1].lower()
                    if ip_addr.lower() != "unassigned" and status == "up" and proto == "up":
                        chosen_if = if_name
                        facts["ip"] = ip_addr
                        break

        if chosen_if:
            ok, out = await self._run(dev, f"show ip interface {chosen_if}")
            if ok and out:
                m = re.search(r"Internet address is\s+([0-9.]+)/(\d+)", out)
                if m:
                    prefix = int(m.group(2))
                    mask_bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                    mask = ".".join(str((mask_bits >> (8 * i)) & 0xFF) for i in [3, 2, 1, 0])
                    facts["subnet_mask"] = mask

            ok, out = await self._run(dev, f"show interface {chosen_if}")
            if ok and out:
                mac_m = re.search(r"address is\s+([0-9a-f\.]+)", out, re.I)
                if mac_m:
                    raw = mac_m.group(1).lower().replace(".", "")
                    mac = ":".join([raw[i:i + 2] for i in range(0, len(raw), 2)]).upper()
                    facts["mac"] = mac
                    facts["vendor"] = await self._lookup_vendor(mac) or "Cisco"

        return facts

    async def _collect_device_facts(self, device_info: dict) -> Dict[str, str]:
        dtype = (device_info.get("device_type") or "").lower()
        if dtype in {"cisco_ios", "cisco_nxos", "cisco_asa"}:
            return await self._collect_cisco_facts(device_info)
        if dtype == "linux":
            return await self._collect_linux_facts(device_info)
        return {
            "hostname": device_info.get("host", "N/A"),
            "technology": dtype or "unknown",
            "ip": "N/A",
            "subnet_mask": "N/A",
            "mac": "N/A",
            "username": "N/A",
            "vendor": "Unknown",
        }

    # ---------------------------
    # Neighbor parsing
    # ---------------------------
    async def _parse_output(self, output: str, device_type: str, host: str):
        """Parse CDP (Cisco) or ARP (Linux) neighbors and add edges."""
        if device_type in ["cisco_ios", "cisco_nxos", "cisco_asa"]:
            # Split into neighbor blocks and parse each
            blocks = re.split(r"-{5,}|\n(?=Device ID:)", output or "")
            for block in blocks:
                device_id_match = re.search(r"Device ID:\s*(.+)", block)
                ip_address_match = re.search(r"IP (?:address|Address):\s*([0-9.]+)", block, re.I)
                platform_match = re.search(r"Platform:\s*(.+?)(?:,|$)", block)
                if device_id_match and ip_address_match:
                    neighbor_id = device_id_match.group(1).strip()
                    neighbor_ip = ip_address_match.group(1).strip()
                    vendor = "Cisco"
                    if platform_match:
                        vendor = platform_match.group(1).strip()
                    if host != neighbor_id:
                        self.graph.add_edge(host, neighbor_id)
                        self.graph.nodes[neighbor_id]["ip"] = neighbor_ip
                        self.graph.nodes[neighbor_id]["vendor"] = vendor

        elif device_type == "linux":
            lines = (output or "").strip().splitlines()
            if not lines:
                return
            arp_pattern = re.compile(
                r"^(?P<ip>[0-9.]+)\s+\S+\s+(?P<mac>([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))"
            )
            for line in lines[1:]:  # skip header
                m = arp_pattern.search(line)
                if not m:
                    continue
                neighbor_ip = m.group("ip")
                neighbor_mac = m.group("mac").upper()
                vendor = await self._lookup_vendor(neighbor_mac)
                neighbor_id = f"{neighbor_ip}\n({vendor})"
                if host != neighbor_ip:
                    self.graph.add_edge(host, neighbor_id)
                    self.graph.nodes[neighbor_id]["ip"] = neighbor_ip
                    self.graph.nodes[neighbor_id]["mac"] = neighbor_mac
                    self.graph.nodes[neighbor_id]["vendor"] = vendor

    # ---------------------------
    # Public API
    # ---------------------------
    async def crawl_device(self, device_info: dict):
        """Connect, collect facts, parse neighbors, and stamp node attributes."""
        host = device_info.get("host")
        device_type = (device_info.get("device_type") or "").lower()
        self.graph.add_node(host)  # ensure presence
        self.logger(f"CRAWLING: {host} ({device_type or 'unknown'})...")

        # Decrypt password if necessary
        decrypted = device_info.copy()
        try:
            encrypted_pass = device_info.get("password", "")
            if encrypted_pass:
                decrypted["password"] = self.cred_manager.decrypt_password(encrypted_pass)
        except ValueError as e:
            self.logger(f"ERROR: Could not decrypt password for {host}. {e}")
            return

        # Collect node facts
        facts = await self._collect_device_facts(decrypted)
        node_details = {
            "subnet_mask": facts.get("subnet_mask", "N/A"),
            "hostname": facts.get("hostname", "N/A"),
            "technology": facts.get("technology", "N/A"),
            "username": facts.get("username", "N/A"),
        }
        self.graph.nodes[host].update({
            "ip": facts.get("ip", "N/A"),
            "mac": facts.get("mac", "N/A"),
            "vendor": facts.get("vendor", "Unknown"),
            "details": node_details,
            "device_type": device_type or "Host",
        })

        # Neighbors via discovery command
        command = self.DISCOVERY_COMMANDS.get(device_type)
        if not command:
            self.logger(f"INFO: No discovery command for device type '{device_type}'. Skipping neighbor parse for {host}.")
            return

        success, output = await self._run(decrypted, command)
        if success:
            await self._parse_output(output or "", device_type, host)
        else:
            self.logger(f"ERROR: Failed to fetch neighbor data from {host}. Output:\n{output}")

    async def discover_from_seeds(self, seed_devices: list) -> tuple[nx.Graph, str]:
        """Start the discovery walk from configured seed devices."""
        self.graph.clear()
        if not self.cred_manager.get_master_password():
            self.logger("ERROR: Master password not provided. Aborting discovery.")
            return self.graph, "Master password not provided."

        tasks = [asyncio.create_task(self.crawl_device(d)) for d in seed_devices]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger("--- Discovery Finished ---")
        return self.graph, "Discovery finished."

