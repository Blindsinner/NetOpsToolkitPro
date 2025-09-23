# app/core/health_engine.py
import asyncio
import platform
import json
from PySide6.QtCore import QObject, Signal
from app.config import AppConfig
from app.core.performance_monitor import PerformanceMonitor
from app.core.credentials_manager import CredentialsManager

DEVICES_FILE = AppConfig.PROJECT_ROOT / "device_configs" / "devices.json"

class HealthEngine(QObject):
    """
    Performs concurrent health checks (ping, SNMP) on a list of devices
    and emits signals with the results for real-time UI updates.
    """
    # Signal emits a dictionary with a single device's health status
    device_health_updated = Signal(dict)
    # Signal emits when all checks are complete
    all_checks_finished = Signal(str)

    def __init__(self, task_manager):
        super().__init__()
        self.task_manager = task_manager
        self.devices = self._load_devices()
        self.perf_monitor = PerformanceMonitor()
        self.cred_manager = CredentialsManager()
        self.is_running = False

    def _load_devices(self):
        if not DEVICES_FILE.exists():
            return []
        try:
            with open(DEVICES_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []

    def run_all_checks(self, parent_widget=None):
        """Starts the asynchronous process of checking all devices."""
        if self.is_running:
            print("Health checks are already running.")
            return
            
        self.devices = self._load_devices()
        if not self.devices:
            self.all_checks_finished.emit("No devices in inventory to check.")
            return

        # Get master password once for the entire run
        if not self.cred_manager.get_master_password(parent_widget):
            self.all_checks_finished.emit("Master password not provided. Checks aborted.")
            return

        self.is_running = True
        self.task_manager.create_task(self._run_all_checks_async())

    async def _run_all_checks_async(self):
        """The async coroutine that runs all checks concurrently."""
        tasks = [self._check_device(device) for device in self.devices]
        await asyncio.gather(*tasks)
        self.is_running = False
        self.all_checks_finished.emit("All health checks complete.")

    async def _check_device(self, device_info):
        """Performs all health checks for a single device."""
        host = device_info.get("host")
        if not host:
            return

        # Perform Ping check
        status, rtt = await self._check_ping(host)
        
        # Prepare result dictionary
        result = {
            "host": host,
            "status": status,
            "rtt": rtt,
            "cpu_load": "N/A"
        }

        # If ping was successful, try an SNMP check
        if status == "Up" and device_info.get("device_type") != "linux":
            decrypted_device = device_info.copy()
            encrypted_pass = device_info.get("password", "")
            if encrypted_pass:
                try:
                    decrypted_device["password"] = self.cred_manager.decrypt_password(encrypted_pass)
                except ValueError:
                    # Could not decrypt, so SNMP will likely fail, but we proceed
                    pass

            # Assume default SNMP settings for a quick check
            snmp_info = {
                "host": host,
                "snmp_community": "public",
                "snmp_version": 2
            }
            snmp_stats = await self.perf_monitor.get_basic_stats(snmp_info)
            if snmp_stats.get("status") == "Success":
                result["cpu_load"] = snmp_stats.get("cpu_load", "N/A")

        # Emit the result for this single device
        self.device_health_updated.emit(result)

    async def _check_ping(self, host: str) -> (str, str):
        """
        Performs a single ping to check reachability and get RTT.
        Returns (status, rtt_string).
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', host]
        
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        if proc.returncode == 0:
            output = stdout.decode('utf-8', 'ignore')
            # Try to parse RTT
            for line in output.splitlines():
                if 'time=' in line:
                    try:
                        rtt = line.split('time=')[1].split(' ')[0]
                        return "Up", rtt + " ms"
                    except IndexError:
                        continue
            return "Up", "N/A"
        else:
            return "Down", "N/A"
