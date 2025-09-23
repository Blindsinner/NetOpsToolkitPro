# -*- coding: utf-8 -*-
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

@dataclass
class IPInfoResult:
    input_str: str
    timestamp: str = field(default_factory=time.ctime)
    errors: list[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

class IPUtils:
    def get_ip_info(self, ip_str: str, subnet_str: Optional[str] = None) -> IPInfoResult:
        full_input = ip_str
        if subnet_str and "/" not in ip_str:
            full_input = f"{ip_str}/{subnet_str}"
        try:
            if "/" in full_input:
                network = ipaddress.ip_network(full_input, strict=False)
                addr = ipaddress.ip_address(full_input.split('/')[0])
            else:
                addr = ipaddress.ip_address(full_input)
                network = ipaddress.ip_network(f"{addr}/32", strict=False)

            if isinstance(network, ipaddress.IPv4Network):
                return self._get_ipv4_details(addr, network, full_input)
            else:
                return IPInfoResult(input_str=full_input, errors=["IPv6 details not implemented yet."])
        except ValueError as e:
            return IPInfoResult(input_str=full_input, errors=[str(e)])

    def _get_ipv4_details(self, addr: Any, network: Any, original_input: str) -> IPInfoResult:
        first_octet = int(str(addr).split('.')[0])
        ip_class = (
            "A" if 1 <= first_octet <= 126 else "B" if 128 <= first_octet <= 191 else
            "C" if 192 <= first_octet <= 223 else "D" if 224 <= first_octet <= 239 else "E"
        )
        details = {
            "IP Address": str(addr), "Subnet Mask": str(network.netmask), "CIDR Notation": f"/{network.prefixlen}",
            "Network Address": str(network.network_address), "Broadcast Address": str(network.broadcast_address),
            "Address Class": f"{'Private' if addr.is_private else 'Public'} {ip_class}",
            "Total Hosts": network.num_addresses, "Usable Hosts": max(0, network.num_addresses - 2),
            "Usable Host Range": f"{network.network_address + 1} - {network.broadcast_address - 1}" if network.prefixlen < 31 else "N/A",
            "Wildcard Mask": str(network.hostmask),
            "Binary IP": '.'.join([bin(int(x))[2:].zfill(8) for x in str(addr).split('.')]),
            "Binary Subnet": '.'.join([bin(int(x))[2:].zfill(8) for x in str(network.netmask).split('.')]),
            "Integer ID": int(addr), "Hex ID": hex(int(addr)), "in-addr.arpa": addr.reverse_pointer,
            "IPv4-Mapped IPv6": f"::ffff:{addr}",
            "6to4 Prefix": f"2002:{int(str(addr).split('.')[0]):02x}{int(str(addr).split('.')[1]):02x}:{int(str(addr).split('.')[2]):02x}{int(str(addr).split('.')[3]):02x}::/48",
        }
        return IPInfoResult(input_str=original_input, details=details)