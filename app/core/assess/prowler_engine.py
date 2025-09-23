# app/core/assess/prowler_engine.py
from __future__ import annotations
import asyncio, shutil, contextlib
from typing import AsyncIterator, Optional

class ProwlerEngine:
    """Streams Prowler AWS findings (JSON-ASFF lines)."""

    def __init__(self):
        self._proc: Optional[asyncio.subprocess.Process] = None

    def available(self) -> bool:
        return shutil.which("prowler") is not None

    async def run(self, profile: str = "default", region: str = "us-east-1", services: Optional[str] = None) -> AsyncIterator[str]:
        if not self.available():
            yield "ERROR: prowler not installed."
            return

        cmd = ["prowler", "-p", profile, "-f", region, "-M", "json-asff"]
        if services:
            cmd += ["-S", services]  # comma-separated services list

        self._proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        assert self._proc.stdout
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line: break
                yield line.decode(errors="ignore").rstrip("\n")
        finally:
            await self.stop()

    async def stop(self):
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._proc.wait(), timeout=3)
        self._proc = None

