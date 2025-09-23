# app/core/assess/censys_engine.py
from __future__ import annotations
import httpx, base64
from typing import AsyncIterator

class CensysEngine:
    """Censys v2 API."""

    def __init__(self, api_id: str, api_secret: str):
        self.api_id = api_id
        self.api_secret = api_secret
        self._client = httpx.AsyncClient(timeout=25.0)

    def available(self) -> bool:
        return bool(self.api_id and self.api_secret)

    def _auth(self):
        token = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    async def search_hosts(self, query: str) -> AsyncIterator[str]:
        if not self.available():
            yield "ERROR: Censys API creds not configured."
            return
        r = await self._client.post(
            "https://search.censys.io/api/v2/hosts/search",
            headers=self._auth(),
            json={"q": query, "per_page": 25},
        )
        if r.status_code != 200:
            yield f"ERROR: {r.status_code} - {r.text}"; return
        js = r.json()
        yield f"Total: {js.get('result',{}).get('total',0)}"
        for h in js.get("result", {}).get("hits", []):
            ip = h.get("ip"); asn = h.get("autonomous_system",{}).get("asn")
            services = [str(s.get("port")) for s in h.get("services",[])]
            yield f"{ip}  ASN:{asn}  Ports:{','.join(services)}"

    async def host(self, ip: str) -> AsyncIterator[str]:
        if not self.available():
            yield "ERROR: Censys API creds not configured."
            return
        r = await self._client.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            headers=self._auth(),
        )
        if r.status_code != 200:
            yield f"ERROR: {r.status_code} - {r.text}"; return
        js = r.json().get("result", {})
        yield f"IP: {js.get('ip')}  Location: {js.get('location',{}).get('country','')}"
        for s in js.get("services", []):
            yield f" - {s.get('port')}/{s.get('transport')}  {s.get('service_name')}  tls:{bool(s.get('tls'))}"

    async def close(self):
        await self._client.aclose()

