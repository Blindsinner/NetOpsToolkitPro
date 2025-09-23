# -*- coding: utf-8 -*-
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple

from netmiko import (
    ConnectHandler,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

class DeviceConnector:
    """
    Handles network device connections and operations using Netmiko.

    Backward-compatible notes:
    - Some parts of the app instantiate DeviceConnector(connection_info).
      We now support an optional default device profile via __init__.
    - Every public method also accepts a per-call device_info which, when
      provided, overrides the defaults set at construction.
    """

    # Map user-facing names to Netmiko device_type
    DEVICE_TYPES = {
        "Cisco IOS (SSH)": "cisco_ios",
        "Cisco ASA (SSH)": "cisco_asa",
        "Arista EOS (SSH)": "arista_eos",
        "Juniper Junos (SSH)": "juniper_junos",
        "Linux (SSH)": "linux",
    }

    # Commands to fetch running configuration for different device types
    BACKUP_COMMANDS = {
        "cisco_ios": "show running-config",
        "cisco_asa": "show running-config",
        "arista_eos": "show running-config",
        "juniper_junos": "show configuration",
        # For Linux there is no "running-config"—return some basic system info
        "linux": "cat /etc/os-release; echo '---'; uname -a",
    }

    # Neighbor discovery examples (extend as you like)
    DISCOVERY_COMMANDS = {
        "cisco_ios": "show cdp neighbors detail",
        "juniper_junos": "show lldp neighbors detail",
        "arista_eos": "show lldp neighbors detail",
        # "linux": could use lldpcli if present
    }

    def __init__(self, connection_info: Optional[Dict[str, Any]] = None) -> None:
        """
        Optional default connection info for backward compatibility with code
        that does DeviceConnector(conn_info).
        """
        self._default_info: Dict[str, Any] = connection_info or {}

    # --------------------------- helpers ---------------------------

    def _map_device_type(self, dt: Optional[str]) -> Optional[str]:
        if not dt:
            return None
        # If a friendly name was passed, map it; otherwise assume it's already a Netmiko type
        return self.DEVICE_TYPES.get(dt, dt)

    def _merged_info(self, supplied: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        base = dict(self._default_info)  # copy
        if supplied:
            base.update(supplied)
        # Normalize device_type
        base["device_type"] = self._map_device_type(base.get("device_type"))
        return base

    def _get_connection_dict(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare kwargs for Netmiko ConnectHandler."""
        # Accept both 'host' and 'ip' keys
        host = device_info.get("host") or device_info.get("ip")
        return {
            "device_type": device_info.get("device_type"),
            "host": host,
            "username": device_info.get("username"),
            "password": device_info.get("password"),
            "port": device_info.get("port", 22),
            "secret": device_info.get("secret", ""),  # enable/privilege for some drivers
            "conn_timeout": device_info.get("conn_timeout", 10),
            "fast_cli": device_info.get("fast_cli", True),
        }

    async def _run_in_executor(self, func, *args, **kwargs):
        """Run a blocking function in a separate thread to keep the UI responsive."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    # --------------------------- operations ---------------------------

    async def test_connection(self, device_info: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        info = self._merged_info(device_info)
        conn = self._get_connection_dict(info)
        logging.info(f"Testing connection to {conn.get('host')} ({conn.get('device_type')})...")
        try:
            ssh = await self._run_in_executor(ConnectHandler, **conn)
            prompt = await self._run_in_executor(ssh.find_prompt)
            await self._run_in_executor(ssh.disconnect)
            return True, f"Success. Prompt: {prompt}"
        except NetmikoTimeoutException:
            msg = f"Connection timed out to {conn.get('host')}"
            logging.error(msg)
            return False, msg
        except NetmikoAuthenticationException:
            msg = f"Authentication failed for {conn.get('host')}"
            logging.error(msg)
            return False, msg
        except Exception as e:
            msg = f"Unexpected error: {e}"
            logging.error(msg, exc_info=True)
            return False, msg

    async def run_command(
        self,
        device_info: Optional[Dict[str, Any]],
        command: str,
        read_timeout: Optional[int] = 60,
    ) -> Tuple[bool, str]:
        info = self._merged_info(device_info)
        conn = self._get_connection_dict(info)
        logging.info(f"Running command on {conn.get('host')}: {command}")
        try:
            ssh = await self._run_in_executor(ConnectHandler, **conn)
            output = await self._run_in_executor(
                ssh.send_command,
                command,
                read_timeout=read_timeout,
            )
            await self._run_in_executor(ssh.disconnect)
            return True, output
        except Exception as e:
            msg = f"Failed to run command on {conn.get('host')}: {e}"
            logging.error(msg, exc_info=True)
            return False, msg

    async def fetch_backup(self, device_info: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        info = self._merged_info(device_info)
        device_type = info.get("device_type")
        command = self.BACKUP_COMMANDS.get(device_type)
        if not command:
            return False, f"No backup command defined for device type '{device_type}'"
        return await self.run_command(info, command, read_timeout=120)

    async def send_config(
        self,
        device_info: Optional[Dict[str, Any]],
        commands: List[str],
        read_timeout: Optional[int] = 120,
    ) -> Tuple[bool, str]:
        """
        Send configuration commands. Uses send_config_set for network OSes.
        For 'linux', falls back to line-by-line command execution (no config mode).
        """
        info = self._merged_info(device_info)
        conn = self._get_connection_dict(info)
        dtype = conn.get("device_type")
        logging.info(f"Sending config to {conn.get('host')} ({dtype}): {commands}")

        try:
            ssh = await self._run_in_executor(ConnectHandler, **conn)

            if dtype == "linux":
                # No "config mode" concept on generic Linux in Netmiko.
                # Execute commands one-by-one (best-effort).
                output_all = []
                for cmd in commands:
                    # send_command_timing avoids prompt pattern assumptions
                    out = await self._run_in_executor(ssh.send_command_timing, cmd)
                    output_all.append(f"$ {cmd}\n{out}")
                output = "\n".join(output_all)
            else:
                # Network OS: use proper config mode handling
                output = await self._run_in_executor(
                    ssh.send_config_set,
                    commands,
                    read_timeout=read_timeout,
                )
                # Some platforms support save_config; guard it.
                try:
                    _ = await self._run_in_executor(ssh.save_config)
                except Exception:
                    pass

            await self._run_in_executor(ssh.disconnect)
            logging.info(f"Configuration sent successfully to {conn.get('host')}.")
            return True, output

        except Exception as e:
            msg = f"Failed to send config to {conn.get('host')}: {e}"
            logging.error(msg, exc_info=True)
            return False, msg

