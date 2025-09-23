# app/core/assess/shodan_engine.py
from __future__ import annotations
import httpx
from typing import AsyncIterator, Optional, Dict, Any

class ShodanEngine:
    """Shodan REST API helper."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client = httpx.AsyncClient(timeout=25.0)

    def available(self) -> bool:
        return bool(self.api_key)

    async def host(self, ip: str) -> AsyncIterator[str]:
        if not self.available():
            yield "ERROR: Shodan API key not configured."
            return
        url = f"https://api.shodan.io/shodan/host/{ip}"
        r = await self._client.get(url, params={"key": self.api_key})
        if r.status_code != 200:
            yield f"ERROR: {r.status_code} - {r.text}"
            return
        data = r.json()
        yield f"IP: {data.get('ip_str')}  Org: {data.get('org')}  OS: {data.get('os')}"
        for item in data.get("data", []):
            port = item.get("port")
            product = item.get("product")
            cpe = ",".join(item.get("cpe", [])) if isinstance(item.get("cpe"), list) else item.get("cpe")
            vulns = list(item.get("vulns", {}).keys()) if isinstance(item.get("vulns"), dict) else []
            yield f" - {port}/tcp {product or ''}  CPE:{cpe or ''}  CVEs:{','.join(vulns)}"

    async def search(self, query: str) -> AsyncIterator[str]:
        if not self.available():
            yield "ERROR: Shodan API key not configured."
            return
        url = "https://api.shodan.io/shodan/host/search"
        r = await self._client.get(url, params={"key": self.api_key, "query": query})
        if r.status_code != 200:
            yield f"ERROR: {r.status_code} - {r.text}"
            return
        js = r.json()
        total = js.get("total", 0)
        yield f"Total results: {total}"
        for m in js.get("matches", []):
            ip = m.get("ip_str"); port = m.get("port")
            org = m.get("org"); product = m.get("product")
            yield f"{ip}:{port}  {product or ''} ({org or ''})"

    async def close(self):
        await self._client.aclose()

