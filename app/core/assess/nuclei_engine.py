# app/core/assess/nuclei_engine.py
from __future__ import annotations
import asyncio, shutil, contextlib, tempfile, os
from typing import AsyncIterator, Iterable, Optional

class NucleiEngine:
    """Async wrapper around nuclei binary with streaming output."""

    def __init__(self, task_manager=None):
        self._proc: Optional[asyncio.subprocess.Process] = None
        self.task_manager = task_manager

    def available(self) -> bool:
        return shutil.which("nuclei") is not None

    async def run(
        self,
        target: Optional[str] = None,
        targets_list: Optional[Iterable[str]] = None,
        templates: Optional[Iterable[str]] = None,
        severity: Optional[str] = None,
        rate_limit: Optional[int] = None,
        timeout: Optional[int] = None,
        jsonl: bool = True
    ) -> AsyncIterator[str]:
        if not self.available():
            yield "ERROR: nuclei is not installed or not in PATH."
            return

        cmd = ["nuclei", "-silent"]
        temp_path = None
        if jsonl:
            cmd += ["-jsonl"]
        if target:
            cmd += ["-u", target]
        if targets_list:
            # write to temp file for -l
            fd, temp_path = tempfile.mkstemp(prefix="nuclei_targets_", text=True)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for t in targets_list:
                    f.write(f"{t}\n")
            cmd += ["-l", temp_path]
        if templates:
            for t in templates: cmd += ["-t", t]
        if severity:
            cmd += ["-severity", severity]
        if rate_limit:
            cmd += ["-rl", str(rate_limit)]
        if timeout:
            cmd += ["-timeout", str(timeout)]

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
            if temp_path:
                with contextlib.suppress(Exception): os.remove(temp_path)

    async def stop(self):
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._proc.wait(), timeout=3)
        self._proc = None

