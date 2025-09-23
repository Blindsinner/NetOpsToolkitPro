# app/core/recon/wayback_engine.py
from __future__ import annotations

import asyncio
import threading
from typing import Any, Dict, List, Optional, Tuple
import httpx


class WaybackEngine:
    """
    Wayback Machine client with BOTH async APIs and SAFE sync wrappers.

    - Async APIs (suffix *_async) are normal coroutines you can await.
    - Sync wrappers (no suffix) run the coroutine on a dedicated background
      event loop thread and return concrete values (not asyncio.Tasks).
    - No shared AsyncClient to avoid cross-loop issues; each call creates one.
    """
    _AVAIL_URL = "https://archive.org/wayback/available"
    _CDX_URL = "https://web.archive.org/cdx/search/cdx"

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout
        # background loop for sync wrappers
        self._bg_loop: Optional[asyncio.AbstractEventLoop] = None
        self._bg_thread: Optional[threading.Thread] = None
        self._bg_ready = threading.Event()
        self._ensure_bg_loop_started()

    # --------------------------
    # Background loop machinery
    # --------------------------
    def _ensure_bg_loop_started(self) -> None:
        if self._bg_thread and self._bg_thread.is_alive():
            return

        def _runner():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._bg_loop = loop
            self._bg_ready.set()
            try:
                loop.run_forever()
            finally:
                # cancel pending and close
                pending = asyncio.all_tasks(loop=loop)
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.close()

        self._bg_thread = threading.Thread(target=_runner, name="WaybackEngineLoop", daemon=True)
        self._bg_thread.start()
        self._bg_ready.wait()

    def _run_sync(self, coro, timeout: Optional[float] = None):
        """Run a coroutine on the background loop and return its result (no Task)."""
        if self._bg_loop is None or not self._bg_loop.is_running():
            self._ensure_bg_loop_started()
        fut = asyncio.run_coroutine_threadsafe(coro, self._bg_loop)
        return fut.result(timeout=timeout or (self.timeout + 10.0))

    # --------------------------
    # Async API (await these)
    # --------------------------
    async def availability_async(self, url: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout, http2=True) as client:
            r = await client.get(self._AVAIL_URL, params={"url": url})
            r.raise_for_status()
            return r.json()

    async def latest_snapshot_url_async(self, domain: str, path: str = "/") -> Optional[str]:
        url = f"https://{domain.rstrip('/')}{path}"
        data = await self.availability_async(url)
        closest = data.get("archived_snapshots", {}).get("closest")
        if closest and closest.get("available"):
            return closest.get("url")
        return None

    async def cdx_search_async(
        self,
        domain: str,
        limit: int = 200,
        status_filter: Optional[str] = "statuscode:200",
        fields: Tuple[str, ...] = ("timestamp", "original", "statuscode", "mimetype"),
        collapse: Optional[str] = "digest",
    ) -> List[Dict[str, str]]:
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": ",".join(fields),
            "limit": str(limit),
        }
        if status_filter:
            params["filter"] = status_filter
        if collapse:
            params["collapse"] = collapse

        async with httpx.AsyncClient(timeout=self.timeout, http2=True) as client:
            r = await client.get(self._CDX_URL, params=params)
            r.raise_for_status()
            rows = r.json() or []

        results: List[Dict[str, str]] = []
        for row in rows:
            if isinstance(row, list) and len(row) == len(fields):
                results.append({fname: val for fname, val in zip(fields, row)})
        return results

    # --------------------------
    # Sync wrappers (UI can call these)
    # --------------------------
    def availability(self, url: str) -> Dict[str, Any]:
        return self._run_sync(self.availability_async(url))

    def latest_snapshot_url(self, domain: str, path: str = "/") -> Optional[str]:
        return self._run_sync(self.latest_snapshot_url_async(domain, path))

    def cdx_search(
        self,
        domain: str,
        limit: int = 200,
        status_filter: Optional[str] = "statuscode:200",
        fields: Tuple[str, ...] = ("timestamp", "original", "statuscode", "mimetype"),
        collapse: Optional[str] = "digest",
    ) -> List[Dict[str, str]]:
        return self._run_sync(self.cdx_search_async(domain, limit, status_filter, fields, collapse))

    # --------------------------
    # Cleanup (optional)
    # --------------------------
    def close(self) -> None:
        """Stop the background loop thread (optional; daemon thread ends on exit)."""
        if self._bg_loop and self._bg_loop.is_running():
            self._bg_loop.call_soon_threadsafe(self._bg_loop.stop)
        self._bg_loop = None
        self._bg_thread = None

