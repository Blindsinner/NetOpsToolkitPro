# app/core/js_recon_engine.py
import asyncio
import httpx
import re
from typing import AsyncGenerator
from urllib.parse import urljoin
from PySide6.QtCore import QObject, Signal

class JSReconEngine(QObject):
    """A specialized engine to find and analyze JavaScript files for secrets."""
    
    js_file_found = Signal(str)
    secret_found = Signal(dict)
    progress_updated = Signal(str)
    scan_finished = Signal(str)

    def __init__(self, task_manager):
        super().__init__()
        self.task_manager = task_manager
        self._is_running = False
        
        self.secret_patterns = {
            "API Key": re.compile(r'["\'](api_key|apikey|access_token|secret_key|accesstoken|secretkey)["\']\s*[:=]\s*["\']([a-zA-Z0-9\-_]{20,})["\']'),
            "Authorization Token": re.compile(r'["\'](Authorization)["\']\s*:\s*["\'](Bearer\s+[a-zA-Z0-9\._\-]+)["\']'),
            "URL Endpoint": re.compile(r'["\'](/api/v[0-9]+/[a-zA-Z0-9/_-]+)["\']'),
            "Sensitive File": re.compile(r'(\.env|\.htpasswd|config\.json|settings\.py)'),
        }

    def start_scan(self, base_url: str):
        if self._is_running: return
        self._is_running = True
        self.task_manager.create_task(self._run_scan(base_url))

    def stop_scan(self):
        self._is_running = False

    async def _run_scan(self, base_url: str):
        js_urls = set()
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            try:
                self.progress_updated.emit(f"Fetching root page: {base_url}")
                response = await client.get(base_url, timeout=20)
                
                src_pattern = re.compile(r'<script.*?src=["\'](.*?)["\']')
                for match in src_pattern.finditer(response.text):
                    if not self._is_running: break
                    js_path = match.group(1)
                    full_js_url = urljoin(base_url, js_path)
                    if full_js_url not in js_urls:
                        js_urls.add(full_js_url)
                        self.js_file_found.emit(full_js_url)

                if not self._is_running:
                    self.scan_finished.emit("Scan stopped by user.")
                    return

                tasks = [self._analyze_single_js(client, url) for url in js_urls]
                await asyncio.gather(*tasks)

            except httpx.RequestError as e:
                self.scan_finished.emit(f"Error fetching base URL: {e}")
                self._is_running = False
                return
        
        self.scan_finished.emit("JS file scan complete.")
        self._is_running = False
        
    async def _analyze_single_js(self, client: httpx.AsyncClient, js_url: str):
        if not self._is_running: return
        try:
            self.progress_updated.emit(f"Analyzing: {js_url.split('/')[-1]}")
            response = await client.get(js_url, timeout=20)
            content = response.text
            
            for secret_type, pattern in self.secret_patterns.items():
                for match in pattern.finditer(content):
                    found_secret = match.group(0)
                    if len(found_secret) > 200:
                        found_secret = found_secret[:200] + "..."
                    self.secret_found.emit({
                        "js_file": js_url,
                        "type": secret_type,
                        "match": found_secret
                    })
        except httpx.RequestError:
            pass
