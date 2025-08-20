# -*- coding: utf-8 -*-
import asyncio
import logging
from typing import List, Callable, AsyncGenerator
from scapy.all import send, IP, TCP, UDP
from netmiko import NetmikoAuthenticationException

class SecurityTester:
    """A collection of tools for proactive security testing."""

    async def _run_in_executor(self, func, *args, **kwargs):
        """Runs a blocking Scapy function in a separate thread."""
        return await asyncio.get_running_loop().run_in_executor(None, lambda: func(*args, **kwargs))

    async def perform_port_knock(self, target_ip: str, ports: List[int], protocol: str, delay: float) -> AsyncGenerator[str, None]:
        if not ports:
            yield "ERROR: Port sequence cannot be empty."
            return

        yield f"Starting knock sequence on {target_ip} with {protocol}..."
        
        for i, port in enumerate(ports):
            yield f"  [{i+1}/{len(ports)}] Knocking on port {port}..."
            try:
                if protocol == "TCP":
                    packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
                elif protocol == "UDP":
                    packet = IP(dst=target_ip) / UDP(dport=port)
                else:
                    yield f"ERROR: Unsupported protocol '{protocol}'."
                    return
                
                await self._run_in_executor(send, packet, verbose=0)
                if i < len(ports) - 1:
                    await asyncio.sleep(delay)
            except Exception as e:
                error_msg = f"ERROR: Failed to send packet to port {port}: {e}"
                yield error_msg
                logging.error(error_msg)
                return
        
        yield "--- Knock sequence complete ---"

    async def audit_password(self, device_info, username, password) -> (str, bool):
        """
        Attempts a single login to a device.
        Returns the result and a boolean indicating success.
        """
        from app.core.device_connector import DeviceConnector
        connector = DeviceConnector()
        
        test_device_info = device_info.copy()
        test_device_info['username'] = username
        test_device_info['password'] = password
        
        try:
            success, message = await connector.test_connection(test_device_info)
            if success:
                return f"SUCCESS: Valid credentials found! User: '{username}', Pass: '{password}'", True
            else:
                if "Authentication failed" in message:
                    return f"FAILURE: Invalid credentials for user '{username}'.", False
                else:
                    return f"ERROR: Connection failed. {message}", False
        except Exception as e:
            return f"ERROR: An unexpected error occurred: {e}", False