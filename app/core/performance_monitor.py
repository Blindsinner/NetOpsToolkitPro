# -*- coding: utf-8 -*-
import asyncio
import logging
from typing import Dict, Any, List
from pysnmp.hlapi.asyncio import *

class PerformanceMonitor:
    """Handles network device SNMP queries for performance metrics using pysnmp."""

    OIDS = {
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "ifDescr": "1.3.6.1.2.1.2.2.1.2",
        "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
        "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
        "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
        "hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2",
    }
    
    async def _snmp_request(self, command_generator, device_info: Dict[str, Any]):
        """Helper function to perform an asynchronous SNMP request."""
        snmp_engine = SnmpEngine()
        auth_data = CommunityData(device_info.get("snmp_community", "public"), mpModel=int(device_info.get("snmp_version", 1))-1)
        transport_target = UdpTransportTarget((device_info.get("host"), 161), timeout=5, retries=2)
        context_data = ContextData()

        error_indication, error_status, error_index, var_binds = await command_generator(
            snmp_engine, auth_data, transport_target, context_data
        )

        if error_indication:
            raise Exception(error_indication)
        elif error_status:
            raise Exception(f'{error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1][0] or "?"}')
        
        return var_binds

    async def test_snmp(self, device_info: Dict[str, Any]) -> (bool, str):
        logging.info(f"Testing SNMP on {device_info.get('host')}...")
        try:
            cmd_gen = getCmd(ObjectType(ObjectIdentity(self.OIDS["sysName"])))
            var_binds = await self._snmp_request(cmd_gen, device_info)
            sys_name = str(var_binds[0][1])
            return True, f"Success! System Name: {sys_name}"
        except Exception as e:
            logging.error(f"SNMP test failed for {device_info.get('host')}: {e}")
            return False, str(e)

    async def get_basic_stats(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        stats = {"status": "Failed", "error": "An unknown error occurred."}
        try:
            oids = [self.OIDS["sysName"], self.OIDS["sysUpTime"], self.OIDS["sysDescr"]]
            cmd_gen = getCmd(*(ObjectType(ObjectIdentity(oid)) for oid in oids))
            var_binds = await self._snmp_request(cmd_gen, device_info)

            stats["sysName"] = str(var_binds[0][1])
            stats["sysUpTime"] = str(var_binds[1][1])
            stats["sysDescr"] = str(var_binds[2][1])
            
            # Walk for CPU
            walk_gen = nextCmd(ObjectType(ObjectIdentity(self.OIDS["hrProcessorLoad"])))
            cpu_var_binds = await self._snmp_request(walk_gen, device_info)
            cpu_loads = [int(var_bind[1]) for var_bind in cpu_var_binds]
            
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
            walk_gen = nextCmd(ObjectType(ObjectIdentity(self.OIDS["ifDescr"])))
            var_binds = await self._snmp_request(walk_gen, device_info)
            for var_bind in var_binds:
                if_index = var_bind[0].getOid()._value[len(ObjectIdentity(self.OIDS["ifDescr"]).getOid()):]
                interfaces.append({ "index": str(if_index[0]), "description": str(var_bind[1])})
            return True, interfaces
        except Exception as e:
            logging.error(f"Failed to get interfaces from {device_info.get('host')}: {e}")
            return False, []

    async def get_interface_stats(self, device_info: Dict[str, Any], if_index: str) -> (bool, Dict[str, Any]):
        try:
            oids = [
                f"{self.OIDS['ifInOctets']}.{if_index}",
                f"{self.OIDS['ifOutOctets']}.{if_index}",
                f"{self.OIDS['ifOperStatus']}.{if_index}",
            ]
            cmd_gen = getCmd(*(ObjectType(ObjectIdentity(oid)) for oid in oids))
            var_binds = await self._snmp_request(cmd_gen, device_info)
            
            status_map = {"1": "Up", "2": "Down"}
            stats = {
                "in_octets": int(var_binds[0][1]),
                "out_octets": int(var_binds[1][1]),
                "status": status_map.get(str(var_binds[2][1]), "Unknown"),
            }
            return True, stats
        except Exception as e:
            logging.error(f"Failed to get stats for index {if_index} on {device_info.get('host')}: {e}")
            return False, {"error": str(e)}