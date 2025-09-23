# app/core/recon_engine.py
import asyncio
import httpx
import dns.resolver
import dns.exception
from typing import AsyncGenerator
from PySide6.QtCore import QObject, Signal

class ReconEngine(QObject):
    """A high-speed, asynchronous engine for web reconnaissance tasks."""
    
    path_found = Signal(dict)
    progress_updated = Signal(str)
    scan_finished = Signal(str)

    def __init__(self, task_manager, wordlist_path: str = None):
        super().__init__()
        self.task_manager = task_manager
        self.subdomain_wordlist = []
        self._is_bruteforce_running = False
        self._is_subdomain_running = False # Flag for subdomain scan

        if wordlist_path:
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.subdomain_wordlist = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"Warning: Subdomain wordlist not found at {wordlist_path}")

    def stop_subdomain_scan(self):
        """Stops the currently running subdomain scan."""
        self._is_subdomain_running = False

    async def find_subdomains(self, domain: str) -> AsyncGenerator[dict, None]:
        """
        Finds subdomains using multiple methods and yields results as they are found.
        """
        self._is_subdomain_running = True
        found_subdomains = set()

        # Method 1: Certificate Transparency Logs (crt.sh)
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
                if response.status_code == 200:
                    for cert in response.json():
                        if not self._is_subdomain_running: return # Stop check
                        name = cert.get('name_value', '')
                        names = name.split('\\n') if '\\n' in name else [name]
                        for n in names:
                            if n.endswith(domain) and '*' not in n and n not in found_subdomains:
                                found_subdomains.add(n)
                                yield {"subdomain": n, "source": "crt.sh"}
        except httpx.RequestError as e:
            yield {"error": f"crt.sh query failed: {e}"}

        # Method 2: DNS Brute-force
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        async def check_subdomain(sub):
            fqdn = f"{sub}.{domain}"
            if fqdn in found_subdomains:
                return None
            try:
                await asyncio.get_running_loop().run_in_executor(
                    None, lambda: resolver.resolve(fqdn, 'A')
                )
                return {"subdomain": fqdn, "source": "brute-force"}
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                return None
            except Exception as e:
                print(f"DNS error for {fqdn}: {e}")
                return None

        tasks = [check_subdomain(sub) for sub in self.subdomain_wordlist]
        for future in asyncio.as_completed(tasks):
            if not self._is_subdomain_running: # Stop check
                # Cancel remaining tasks
                for task in tasks:
                    if not task.done():
                        task.cancel()
                break

            try:
                result = await future
                if result and result["subdomain"] not in found_subdomains:
                    found_subdomains.add(result["subdomain"])
                    yield result
            except asyncio.CancelledError:
                continue
    
    # --- Directory Bruteforcer Logic ---
    def start_directory_bruteforce(self, base_url, wordlist_path, threads, status_codes):
        if self._is_bruteforce_running:
            return
        
        self._is_bruteforce_running = True
        self.task_manager.create_task(
            self._run_bruteforce(base_url, wordlist_path, threads, status_codes)
        )

    def stop_scan(self):
        self._is_bruteforce_running = False

    async def _fetch(self, client, url, path, status_codes_to_report):
        if not self._is_bruteforce_running:
            return
            
        try:
            response = await client.get(url, timeout=10)
            if response.status_code in status_codes_to_report:
                content_length = response.headers.get('content-length', '0')
                result = {
                    "path": path,
                    "status": response.status_code,
                    "length": content_length
                }
                self.path_found.emit(result)
        except httpx.RequestError:
            pass

    async def _run_bruteforce(self, base_url, wordlist_path, threads, status_codes):
        self.progress_updated.emit("Reading wordlist...")
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.scan_finished.emit(f"Error: Wordlist not found at {wordlist_path}")
            self._is_bruteforce_running = False
            return

        if not base_url.endswith('/'):
            base_url += '/'
        
        headers = {'User-Agent': f'NetOpsToolkitPro-Recon/5.3.0'}
        limits = httpx.Limits(max_connections=threads, max_keepalive_connections=threads)
        
        async with httpx.AsyncClient(headers=headers, limits=limits, verify=False) as client:
            tasks = []
            total = len(paths)
            self.progress_updated.emit(f"Starting scan with {total} paths and {threads} threads...")

            for i, path in enumerate(paths):
                if not self._is_bruteforce_running:
                    break
                
                full_url = f"{base_url}{path}"
                task = asyncio.create_task(self._fetch(client, full_url, path, status_codes))
                tasks.append(task)

                if len(tasks) >= threads or i == total - 1:
                    await asyncio.gather(*tasks)
                    tasks = []
                    self.progress_updated.emit(f"Progress: {i + 1} / {total}")

        self.scan_finished.emit("Scan finished." if self._is_bruteforce_running else "Scan stopped by user.")
        self._is_bruteforce_running = False
