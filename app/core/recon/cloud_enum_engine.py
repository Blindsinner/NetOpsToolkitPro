# app/core/recon/cloud_enum_engine.py
import asyncio, re
from typing import List, Dict, Tuple
from PySide6.QtCore import QObject, Signal
import httpx
import tldextract

class CloudEnumEngine(QObject):
    progress = Signal(str)
    error = Signal(str)
    finished = Signal(list)  # list of dict

    def __init__(self, task_manager, timeout: float = 10.0, max_concurrency: int = 10):
        super().__init__()
        self.task_manager = task_manager
        self.timeout = timeout
        self._cancel = False
        self.semaphore = asyncio.Semaphore(max_concurrency)

    def cancel(self):
        self._cancel = True

    def run(self, brand_or_domain: str):
        self._cancel = False
        self.task_manager.create_task(self._run(brand_or_domain))

    def _candidates(self, brand_or_domain: str) -> List[str]:
        b = brand_or_domain.strip().lower()
        ext = tldextract.extract(b)
        parts = [ext.domain, ext.suffix, ext.subdomain]
        words = [p for p in [ext.domain, ext.subdomain, b.replace('.', '-'), b.replace('.', ''), b] if p]
        # simple variants
        variants = set(words)
        for w in list(variants):
            variants.add(w + "-static")
            variants.add("static-" + w)
            variants.add(w + "-assets")
            variants.add("assets-" + w)
            variants.add(w + "-media")
            variants.add(w + "cdn")
        return sorted(variants)

    async def _check_s3(self, client: httpx.AsyncClient, bucket: str) -> Tuple[str, str]:
        # virtual-hosted-style
        url = f"https://{bucket}.s3.amazonaws.com/"
        r = await client.get(url, timeout=self.timeout)
        status = "unknown"
        if r.status_code == 200 and "<ListBucketResult" in r.text:
            status = "listable"
        elif r.status_code in (200, 403):
            status = "exists"
        elif r.status_code == 404:
            status = "not_found"
        return ("aws", status)

    async def _check_gcs(self, client: httpx.AsyncClient, bucket: str) -> Tuple[str, str]:
        url = f"https://storage.googleapis.com/{bucket}/"
        r = await client.get(url, timeout=self.timeout)
        if r.status_code == 200 and "<ListBucketResult" in r.text or "Bucket" in r.text:
            status = "listable"
        elif r.status_code in (200, 403):
            status = "exists"
        elif r.status_code == 404:
            status = "not_found"
        else:
            status = "unknown"
        return ("gcp", status)

    async def _check_azure(self, client: httpx.AsyncClient, bucket: str) -> Tuple[str, str]:
        url = f"https://{bucket}.blob.core.windows.net/?restype=container&comp=list"
        r = await client.get(url, timeout=self.timeout)
        if r.status_code == 200 and "<EnumerationResults" in r.text:
            status = "listable"
        elif r.status_code in (200, 403):
            status = "exists"
        elif r.status_code == 404:
            status = "not_found"
        else:
            status = "unknown"
        return ("azure", status)

    async def _probe(self, client, bucket: str):
        providers = []
        try:
            providers.append(await self._check_s3(client, bucket))
        except Exception:
            pass
        try:
            providers.append(await self._check_gcs(client, bucket))
        except Exception:
            pass
        try:
            providers.append(await self._check_azure(client, bucket))
        except Exception:
            pass
        return providers

    async def _run(self, brand_or_domain: str):
        try:
            cands = self._candidates(brand_or_domain)
            results = []
            async with httpx.AsyncClient(follow_redirects=True, timeout=self.timeout) as client:
                for name in cands:
                    if self._cancel: break
                    providers = await self._probe(client, name)
                    for provider, status in providers:
                        if status in ("exists","listable"):
                            results.append({"provider": provider, "bucket": name, "acl": status, "evidence": ""})
                            self.progress.emit(f"{provider}://{name} -> {status}")
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(f"CloudEnumEngine failed: {e!r}")

