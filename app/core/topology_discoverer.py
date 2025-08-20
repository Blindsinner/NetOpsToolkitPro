# -*- coding: utf-8 -*-
import asyncio
import re
import networkx as nx
from app.core.device_connector import DeviceConnector
from app.core.credentials_manager import CredentialsManager
from mac_vendor_lookup import MacLookup

class TopologyDiscoverer:
    """Discovers network topology by crawling devices."""

    def __init__(self, connector: DeviceConnector, cred_manager: CredentialsManager, logger):
        self.connector = connector
        self.cred_manager = cred_manager
        self.logger = logger
        self.mac_lookup = MacLookup()
        self.DISCOVERY_COMMANDS = {
            "cisco_ios": "show cdp neighbors detail",
            "cisco_nxos": "show cdp neighbors detail",
            "cisco_asa": "show cdp neighbors detail",
            "linux": "arp -n"
        }
        self.graph = nx.Graph()

    # --- FIX: Converted this to an async method to allow for async MAC lookups ---
    async def _parse_output(self, output: str, device_type: str, host: str):
        """Parses command output to find neighbors."""
        if device_type in ["cisco_ios", "cisco_nxos", "cisco_asa"]:
            device_id_match = re.search(r"Device ID: (.+)", output)
            ip_address_match = re.search(r"IP address: (.+)", output)
            platform_match = re.search(r"Platform: (.+?),", output)
            if device_id_match and ip_address_match and platform_match:
                neighbor_id = device_id_match.group(1).strip()
                neighbor_ip = ip_address_match.group(1).strip()
                self.graph.add_edge(host, neighbor_id)
                self.graph.nodes[neighbor_id]['ip'] = neighbor_ip
        
        elif device_type == "linux":
            lines = output.strip().split('\n')
            arp_pattern = re.compile(r"^(?P<ip>[\d\.]+)\s+\w+\s+(?P<mac>([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))")
            for line in lines[1:]: # Skip header
                match = arp_pattern.search(line)
                if match:
                    neighbor_ip = match.group('ip')
                    neighbor_mac = match.group('mac').upper()
                    
                    try:
                        # --- FIX: Await the async version of the lookup ---
                        vendor = await self.mac_lookup.async_lookup.lookup(neighbor_mac)
                    except KeyError:
                        vendor = "Unknown"
                        
                    neighbor_id = f"{neighbor_ip}\n({vendor})"
                    
                    if host != neighbor_ip: # Avoid self-loops
                        self.graph.add_edge(host, neighbor_id)
                        self.graph.nodes[neighbor_id]['ip'] = neighbor_ip


    async def crawl_device(self, device_info: dict):
        """Connects to a single device and finds its neighbors."""
        host = device_info.get("host")
        device_type = device_info.get("device_type")
        self.graph.add_node(host) # Add the node even if crawling fails
        self.logger(f"CRAWLING: {host}...")

        decrypted_device_info = device_info.copy()
        try:
            encrypted_pass = device_info.get("password", "")
            if encrypted_pass:
                decrypted_device_info["password"] = self.cred_manager.decrypt_password(encrypted_pass)
        except ValueError as e:
            self.logger(f"ERROR: Could not decrypt password for {host}. {e}")
            return

        command = self.DISCOVERY_COMMANDS.get(device_type)
        if not command:
            self.logger(f"INFO: No discovery command for device type '{device_type}'. Skipping {host}.")
            return

        success, output = await self.connector.run_command(decrypted_device_info, command)
        if success:
            # --- FIX: Await the new async _parse_output method ---
            await self._parse_output(output, device_type, host)
        else:
            self.logger(f"ERROR: Failed to fetch data from {host}. Output:\n{output}")

    async def discover_from_seeds(self, seed_devices: list) -> (nx.Graph, str):
        """Starts the discovery process from a list of seed devices."""
        self.graph.clear()
        if not self.cred_manager.get_master_password():
            self.logger("ERROR: Master password not provided. Aborting discovery.")
            return self.graph, "Master password not provided."

        tasks = []
        for device_info in seed_devices:
            task = asyncio.create_task(self.crawl_device(device_info))
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        self.logger("--- Discovery Finished ---")
        return self.graph, "Discovery finished."