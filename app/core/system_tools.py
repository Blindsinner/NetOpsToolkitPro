# -*- coding: utf-8 -*-
import ipaddress
import logging
import platform
from typing import Any, Dict, List, Optional
import psutil

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
                # Check if interface is up and not a loopback
                if name in stats and stats[name].isup and not 'lo' in name.lower():
                    # Check for a MAC address, a strong indicator of a physical-like interface
                    has_mac = any(snic_addr.family == psutil.AF_LINK for snic_addr in snic_addrs)
                    if has_mac:
                        usable_interfaces.append(name)
        except Exception as e:
            logging.error(f"Could not get usable interfaces: {e}")
        return usable_interfaces

    def get_default_lan_info(self) -> Optional[Dict[str, str]]:
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            candidate = None
            for iface, iface_addrs in addrs.items():
                if iface not in stats or not stats[iface].isup: continue
                for addr in iface_addrs:
                    if addr.family == 2:  # AF_INET (IPv4)
                        try:
                            ip_obj = ipaddress.ip_address(addr.address)
                            if ip_obj.is_private and not ip_obj.is_loopback:
                                network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                                candidate = {"adapter": iface, "cidr": str(network.with_prefixlen)}
                                if str(network.network_address).startswith(("192.168", "10.")):
                                    return candidate
                        except (ValueError, TypeError): continue
            return candidate
        except Exception as e:
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