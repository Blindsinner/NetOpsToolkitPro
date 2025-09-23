# app/core/system_tools.py
import ipaddress
import logging
import platform
from typing import Any, Dict, List, Optional
import psutil
import socket
import subprocess
import re

class SystemTools:
    def get_local_network_info(self) -> Dict[str, Any]:
        return psutil.net_if_addrs()

    def get_usable_interfaces(self) -> List[str]:
        """
        Gets a list of active, non-loopback interfaces suitable for capture/scanning.
        This is a more robust filter to avoid virtual/pseudo-interfaces.
        """
        usable_interfaces = []
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            for name, snic_addrs in addrs.items():
                if name in stats and stats[name].isup and not 'lo' in name.lower():
                    has_mac = any(snic_addr.family == psutil.AF_LINK for snic_addr in snic_addrs)
                    if has_mac:
                        usable_interfaces.append(name)
        except Exception as e:
            logging.error(f"Could not get usable interfaces: {e}")
        return usable_interfaces

    def get_default_lan_info(self) -> Optional[Dict[str, str]]:
        """
        Gets detailed information about the default LAN interface, including gateway,
        using platform-native commands for reliability.
        """
        try:
            if platform.system() == "Windows":
                # Use 'route print' to find the default route
                result = subprocess.run(["route", "print", "-4"], capture_output=True, text=True, check=True)
                match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d\.]+)\s+([\d\.]+)", result.stdout, re.MULTILINE)
                if not match: return None
                gateway, interface_ip = match.groups()
            else: # Linux / macOS
                # Use 'ip route' to find the default route
                result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, check=True)
                match = re.search(r"default via ([\d\.]+) dev (\S+)", result.stdout)
                if not match: return None
                gateway, interface_name = match.groups()
                interface_ip = None

            addrs = psutil.net_if_addrs()
            for iface_name, iface_addrs in addrs.items():
                for addr in iface_addrs:
                    if addr.family == 2: # AF_INET
                        # For Windows, find the interface that has the IP we found
                        if platform.system() == "Windows" and addr.address == interface_ip:
                            network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                            return {"adapter": iface_name, "ip": addr.address, "subnet_mask": addr.netmask, "gateway": gateway, "cidr": str(network.with_prefixlen)}
                        # For Linux/macOS, find the IP on the named interface
                        elif platform.system() != "Windows" and iface_name == interface_name:
                             network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                             return {"adapter": iface_name, "ip": addr.address, "subnet_mask": addr.netmask, "gateway": gateway, "cidr": str(network.with_prefixlen)}
            return None # Fallback if no match is found
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError, TypeError) as e:
            logging.warning(f"Could not auto-detect LAN info: {e}")
            return None


    def get_adapter_commands(self, adapter: str, action: str, value: Optional[str] = None) -> str:
        cmds = {
            "windows": {
                "disable": f'netsh interface set interface "{adapter}" admin=disable',
                "enable": f'netsh interface set interface "{adapter}" admin=enable',
                "mtu": f'netsh interface ipv4 set subinterface "{adapter}" mtu={value} store=persistent',
                "flush_dns": 'ipconfig /flushdns', "reset_tcp": 'netsh int ip reset',
            },
            "linux": {
                "disable": f'sudo ip link set "{adapter}" down', "enable": f'sudo ip link set "{adapter}" up',
                "mtu": f'sudo ip link set dev "{adapter}" mtu {value}',
                "flush_dns": 'sudo systemd-resolve --flush-caches || sudo /etc/init.d/nscd restart',
                "reset_tcp": '# Restart networking: sudo systemctl restart networking',
            },
            "darwin": {
                "disable": f'sudo ifconfig "{adapter}" down', "enable": f'sudo ifconfig "{adapter}" up',
                "mtu": f'sudo ifconfig "{adapter}" mtu {value}',
                "flush_dns": 'sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder',
                "reset_tcp": '# No direct equivalent.',
            },
        }
        return cmds.get(platform.system().lower(), {}).get(action, f"Action '{action}' not supported on this OS")

    def list_serial_ports(self) -> List[Dict[str, str]]:
        from serial.tools import list_ports
        return [{"device": p.device, "description": p.description} for p in list_ports.comports()]