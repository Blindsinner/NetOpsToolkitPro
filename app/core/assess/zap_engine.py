# app/core/assess/zap_engine.py
from __future__ import annotations
import asyncio, httpx, shutil, contextlib, os
from typing import AsyncIterator, Optional

class ZapEngine:
    """
    Controls a running ZAP daemon via JSON API.
    Start ZAP yourself (recommended):
      /usr/share/zaproxy/zap.sh -daemon -port 8090 -config api.key=YOURKEY
    """

    def __init__(self, host="127.0.0.1", port=8090, api_key: str = ""):
        self.host = host
        self.port = int(port)
        self.api_key = api_key
        self._client = httpx.AsyncClient(timeout=30.0)
        self._proc: Optional[asyncio.subprocess.Process] = None

    def base(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def _get(self, path: str, params: dict):
        p = params.copy()
        if self.api_key: p["apikey"] = self.api_key
        r = await self._client.get(self.base() + path, params=p)
        r.raise_for_status()
        return r.json()

    async def is_ready(self) -> bool:
        try:
            js = await self._get("/JSON/core/view/version/", {})
            return "version" in js
        except Exception:
            return False

    async def spider(self, url: str) -> AsyncIterator[str]:
        # start spider
        js = await self._get("/JSON/spider/action/scan/", {"url": url})
        scan_id = js.get("scan")
        if scan_id is None: yield "ERROR: could not start spider."; return

        while True:
            st = await self._get("/JSON/spider/view/status/", {"scanId": scan_id})
            pct = st.get("status")
            yield f"Spider progress: {pct}%"
            if pct == "100": break
            await asyncio.sleep(1.2)

    async def active_scan(self, url: str) -> AsyncIterator[str]:
        js = await self._get("/JSON/ascan/action/scan/", {"url": url, "recurse": "true"})
        sid = js.get("scan")
        if sid is None: yield "ERROR: could not start active scan."; return

        while True:
            st = await self._get("/JSON/ascan/view/status/", {"scanId": sid})
            pct = st.get("status")
            yield f"Active scan progress: {pct}%"
            if pct == "100": break
            await asyncio.sleep(1.5)

        # fetch alerts
        al = await self._get("/JSON/alert/view/alerts/", {"start": "0", "count": "9999"})
        for a in al.get("alerts", []):
            risk = a.get("risk", "?")
            name = a.get("name", "Issue")
            url = a.get("url", "")
            yield f"[{risk}] {name} @ {url}"

    async def close(self):
        with contextlib.suppress(Exception):
            await self._client.aclose()

