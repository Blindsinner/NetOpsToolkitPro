# -*- coding: utf-8 -*-
import asyncio
from typing import Dict, AsyncGenerator
from mac_vendor_lookup import MacLookup, VendorNotFoundError

from app.core.network_tools import NetworkTools

class NacEngine:
    def __init__(self):
        self.network_tools = NetworkTools()
        # The MacLookup class can be initialized directly
        self.mac_lookup = MacLookup()

    async def discover_devices(self, target_range: str, interface: str) -> AsyncGenerator[Dict, None]:
        """Discovers devices on the network using an ARP scan."""
        results = await self.network_tools.run_arp_scan(target_range, interface)
        for device in results:
            try:
                # --- THIS IS THE FIX ---
                # We now directly await the asynchronous method from the library,
                # which avoids starting a second event loop.
                vendor = await self.mac_lookup.aio_lookup(device['mac'])
            except VendorNotFoundError:
                vendor = "Unknown"
            except Exception: # Catch any other potential errors from the lookup
                vendor = "Lookup Failed"

            device['vendor'] = vendor
            yield device