# -*- coding: utf-8 -*-
import asyncio
import logging
from typing import Dict, Any, List
# FIX: Replaced the entire module with one based on the easysnmp library,
# which is more stable and avoids the persistent import errors from pysnmp.
import easysnmp

class PerformanceMonitor:
    """Handles network device SNMP queries for performance metrics using easysnmp."""

    OIDS = {
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "ifDescr": "1.3.6.1.2.1.2.2.1.2",
        "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
        "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
        "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
        "ifInUcastPkts": "1.3.6.1.2.1.2.2.1.11",
        "ifOutUcastPkts": "1.3.6.1.2.1.2.2.1.17",
        "hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2",
    }
    
    def _create_session(self, device_info: Dict[str, Any]) -> easysnmp.Session:
        """Creates an easysnmp session from device info."""
        return easysnmp.Session(
            hostname=device_info.get("host"),
            community=device_info.get("snmp_community", "public"),
            version=int(device_info.get("snmp_version", 2)),
            timeout=5,
            retries=2
        )

    async def _run_sync_in_executor(self, func, *args, **kwargs):
        """Runs a synchronous (blocking) function in a separate thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    async def test_snmp(self, device_info: Dict[str, Any]) -> (bool, str):
        logging.info(f"Testing SNMP on {device_info.get('host')}...")
        try:
            session = self._create_session(device_info)
            response = await self._run_sync_in_executor(session.get, self.OIDS["sysName"])
            sys_name = response.value
            return True, f"Success! System Name: {sys_name}"
        except Exception as e:
            logging.error(f"SNMP test failed for {device_info.get('host')}: {e}")
            return False, str(e)

    async def get_basic_stats(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        stats = {"status": "Failed", "error": "An unknown error occurred."}
        try:
            session = self._create_session(device_info)
            oids_to_get = [
                self.OIDS["sysName"],
                self.OIDS["sysUpTime"],
                self.OIDS["sysDescr"],
            ]
            responses = await self._run_sync_in_executor(session.get, oids_to_get)

            stats["sysName"] = responses[0].value
            stats["sysUpTime"] = responses[1].value
            stats["sysDescr"] = responses[2].value
            
            # Walk for CPU
            cpu_responses = await self._run_sync_in_executor(session.walk, self.OIDS["hrProcessorLoad"])
            cpu_loads = [int(item.value) for item in cpu_responses]
            
            if cpu_loads:
                avg_cpu = sum(cpu_loads) / len(cpu_loads)
                stats["cpu_load"] = f"{avg_cpu:.2f}%"
            else:
                stats["cpu_load"] = "N/A"

            stats["status"] = "Success"
            stats.pop("error", None)
        except Exception as e:
            stats["error"] = str(e)
        return stats

    async def get_interfaces(self, device_info: Dict[str, Any]) -> (bool, List[Dict[str, Any]]):
        interfaces = []
        try:
            session = self._create_session(device_info)
            if_responses = await self._run_sync_in_executor(session.walk, self.OIDS["ifDescr"])
            
            for item in if_responses:
                if_index = item.oid.split('.')[-1]
                interfaces.append({"index": if_index, "description": item.value})

            return True, interfaces
        except Exception as e:
            logging.error(f"Failed to get interfaces from {device_info.get('host')}: {e}")
            return False, []

    async def get_interface_stats(self, device_info: Dict[str, Any], if_index: str) -> (bool, Dict[str, Any]):
        try:
            session = self._create_session(device_info)
            oids_to_get = [
                f"{self.OIDS['ifInOctets']}.{if_index}",
                f"{self.OIDS['ifOutOctets']}.{if_index}",
                f"{self.OIDS['ifInUcastPkts']}.{if_index}",
                f"{self.OIDS['ifOutUcastPkts']}.{if_index}",
                f"{self.OIDS['ifOperStatus']}.{if_index}",
            ]
            responses = await self._run_sync_in_executor(session.get, oids_to_get)
            
            status_map = {"1": "Up", "2": "Down"}
            stats = {
                "in_octets": int(responses[0].value),
                "out_octets": int(responses[1].value),
                "in_pkts": int(responses[2].value),
                "out_pkts": int(responses[3].value),
                "status": status_map.get(responses[4].value, "Unknown"),
            }
            return True, stats
        except Exception as e:
            logging.error(f"Failed to get stats for index {if_index} on {device_info.get('host')}: {e}")
            return False, {"error": str(e)}

