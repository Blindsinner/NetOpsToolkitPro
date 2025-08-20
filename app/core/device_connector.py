# -*- coding: utf-8 -*-
import asyncio
import logging
from typing import Dict, Any, List
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

class DeviceConnector:
    """Handles network device connections and operations using Netmiko."""

    # Simple mapping of user-friendly names to netmiko device types
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
        "linux": "cat /etc/os-release && uname -a", # Example command for Linux
    }
    
    # Commands for neighbor discovery
    DISCOVERY_COMMANDS = {
        "cisco_ios": "show cdp neighbors detail",
        # Add other device types and their LLDP/CDP commands here
        # e.g., "juniper_junos": "show lldp neighbors",
    }

    async def _run_in_executor(self, func, *args, **kwargs):
        """Runs a blocking function in a separate thread."""
        return await asyncio.get_running_loop().run_in_executor(None, lambda: func(*args, **kwargs))

    def _get_connection_dict(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Prepares the dictionary for Netmiko's ConnectHandler."""
        return {
            "device_type": device_info.get("device_type"),
            "host": device_info.get("host"),
            "username": device_info.get("username"),
            "password": device_info.get("password"),
            "port": device_info.get("port", 22),
            "secret": device_info.get("secret", ""),  # For enable mode
            "conn_timeout": 10,
        }

    async def test_connection(self, device_info: Dict[str, Any]) -> (bool, str):
        """Tests SSH connectivity and authentication to a device."""
        conn_dict = self._get_connection_dict(device_info)
        logging.info(f"Testing connection to {conn_dict.get('host')}...")
        try:
            ssh = await self._run_in_executor(ConnectHandler, **conn_dict)
            prompt = await self._run_in_executor(ssh.find_prompt)
            await self._run_in_executor(ssh.disconnect)
            logging.info(f"Connection successful to {conn_dict.get('host')}. Prompt: {prompt}")
            return True, f"Success! Prompt: {prompt}"
        except NetmikoTimeoutException:
            msg = f"Connection timed out to {conn_dict.get('host')}"
            logging.error(msg)
            return False, msg
        except NetmikoAuthenticationException:
            msg = f"Authentication failed for {conn_dict.get('host')}"
            logging.error(msg)
            return False, msg
        except Exception as e:
            msg = f"An unexpected error occurred: {e}"
            logging.error(msg, exc_info=True)
            return False, str(e)

    async def run_command(self, device_info: Dict[str, Any], command: str) -> (bool, str):
        """Connects to a device and runs a single read-only command."""
        conn_dict = self._get_connection_dict(device_info)
        logging.info(f"Running command on {conn_dict.get('host')}: {command}")
        try:
            ssh = await self._run_in_executor(ConnectHandler, **conn_dict)
            output = await self._run_in_executor(ssh.send_command, command, read_timeout=60)
            await self._run_in_executor(ssh.disconnect)
            return True, output
        except Exception as e:
            msg = f"Failed to run command on {conn_dict.get('host')}: {e}"
            logging.error(msg, exc_info=True)
            return False, msg

    async def fetch_backup(self, device_info: Dict[str, Any]) -> (bool, str):
        """Connects to a device and retrieves its running configuration."""
        conn_dict = self._get_connection_dict(device_info)
        device_type = conn_dict.get("device_type")
        command = self.BACKUP_COMMANDS.get(device_type)

        if not command:
            return False, f"Backup command not defined for device type '{device_type}'"
        
        # Use the generic run_command method
        return await self.run_command(device_info, command)

    async def send_config(self, device_info: Dict[str, Any], commands: List[str]) -> (bool, str):
        """Connects to a device and sends a list of configuration commands."""
        conn_dict = self._get_connection_dict(device_info)
        logging.info(f"Sending config to {conn_dict.get('host')}: {commands}")
        try:
            ssh = await self._run_in_executor(ConnectHandler, **conn_dict)
            output = await self._run_in_executor(ssh.send_config_set, commands)
            await self._run_in_executor(ssh.save_config)
            await self._run_in_executor(ssh.disconnect)
            logging.info(f"Successfully sent config to {conn_dict.get('host')}.")
            return True, output
        except Exception as e:
            msg = f"Failed to send config to {conn_dict.get('host')}: {e}"
            logging.error(msg, exc_info=True)
            return False, msg