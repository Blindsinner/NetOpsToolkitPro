# app/core/assess/naabu_engine.py
from __future__ import annotations
import asyncio, shutil, contextlib
from typing import AsyncIterator, Optional

class NaabuEngine:
    """Async wrapper for naabu port scanner."""

    def __init__(self):
        self._proc: Optional[asyncio.subprocess.Process] = None

    def available(self) -> bool:
        return shutil.which("naabu") is not None

    async def run(self, target: str, ports: str = "top-1000", rate: int = 2000) -> AsyncIterator[str]:
        if not self.available():
            yield "ERROR: naabu is not installed or not in PATH."
            return

        cmd = ["naabu", "-host", target, "-rate", str(rate)]
        if ports and ports != "top-1000": cmd += ["-p", ports]

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

