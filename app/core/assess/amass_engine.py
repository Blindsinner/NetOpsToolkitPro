# app/core/assess/amass_engine.py
from __future__ import annotations
import asyncio, shutil, contextlib
from typing import AsyncIterator, Optional

class AmassEngine:
    """Async wrapper for amass passive enumeration."""

    def __init__(self):
        self._proc: Optional[asyncio.subprocess.Process] = None

    def available(self) -> bool:
        return shutil.which("amass") is not None

    async def enum_passive(self, domain: str) -> AsyncIterator[str]:
        if not self.available():
            yield "ERROR: amass is not installed or not in PATH."
            return

        cmd = ["amass", "enum", "-passive", "-d", domain]
        self._proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        assert self._proc.stdout
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line: break
                yield line.decode(errors="ignore").strip()
        finally:
            await self.stop()

    async def stop(self):
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._proc.wait(), timeout=3)
        self._proc = None

