# app/core/assess/greenbone_engine.py
from __future__ import annotations
import asyncio, shutil
from typing import Optional, Tuple, List

class GreenboneEngine:
    """
    Minimal GMP XML over gvm-cli (OpenVAS/Greenbone).
    Requires: gvm-cli, GVM running (gvm-start), and valid credentials.
    """

    def __init__(self, host="127.0.0.1", port=9390, username="", password=""):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password

    def available(self) -> bool:
        return shutil.which("gvm-cli") is not None

    async def _xml(self, xml: str) -> str:
        if not self.available():
            return "ERROR: gvm-cli not in PATH."
        cmd = [
            "gvm-cli", "tls",
            f"--hostname={self.host}",
            f"--port={self.port}",
            f"--username={self.username}",
            f"--password={self.password}",
            "--xml", xml
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            return f"ERROR: {err.decode(errors='ignore')}"
        return out.decode(errors="ignore")

    async def get_version(self) -> str:
        return await self._xml("<get_version/>")

    async def get_configs(self) -> str:
        return await self._xml("<get_configs/>")

    async def get_targets(self) -> str:
        return await self._xml("<get_targets/>")

    async def get_tasks(self) -> str:
        return await self._xml("<get_tasks/>")

    async def create_target(self, name: str, hosts: str) -> str:
        xml = f"<create_target><name>{name}</name><hosts>{hosts}</hosts></create_target>"
        return await self._xml(xml)

    async def create_task(self, name: str, config_id: str, target_id: str) -> str:
        xml = f'<create_task><name>{name}</name><config id="{config_id}"/><target id="{target_id}"/></create_task>'
        return await self._xml(xml)

    async def start_task(self, task_id: str) -> str:
        xml = f'<start_task task_id="{task_id}"/>'
        return await self._xml(xml)

