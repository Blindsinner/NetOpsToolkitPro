# app/core/nac_engine.py
import asyncio
import socket
import logging
from typing import Dict, AsyncGenerator
# FIX: Import the correct class for asynchronous operations
from mac_vendor_lookup import AsyncMacLookup, VendorNotFoundError

from app.core.network_tools import NetworkTools

class NacEngine:
    def __init__(self):
        self.network_tools = NetworkTools()
        # FIX: Instantiate the asynchronous version of the client
        self.mac_lookup = AsyncMacLookup()
        self._db_updated = False

    async def initialize_vendor_db(self):
        """Asynchronously updates the vendor database if it hasn't been already."""
        if self._db_updated:
            return
        try:
            # FIX: Properly await the asynchronous update method
            await self.mac_lookup.update_vendors()
            self._db_updated = True
            logging.info("MAC vendor database updated successfully.")
        except Exception as e:
            logging.error(f"Could not update MAC vendor database: {e}")

    async def discover_devices(self, target_range: str, interface: str) -> AsyncGenerator[Dict, None]:
        """Discovers devices on the network using an ARP scan."""
        # Ensure the vendor DB is ready before scanning
        await self.initialize_vendor_db()

        results = await self.network_tools.run_arp_scan(target_range, interface)
        for device in results:
            try:
                # FIX: Use the correct async method, which is 'lookup'
                vendor = await self.mac_lookup.lookup(device['mac'])
            except VendorNotFoundError:
                vendor = "Unknown"
            except Exception as e:
                logging.error(f"MAC vendor lookup failed for {device['mac']}: {e}")
                vendor = "Lookup Failed"

            device['vendor'] = vendor
            
            # Attempt to resolve hostname
            try:
                hostname, _, _ = await asyncio.get_running_loop().run_in_executor(
                    None, socket.gethostbyaddr, device['ip']
                )
                device['hostname'] = hostname
            except socket.herror:
                device['hostname'] = "N/A"

            yield device