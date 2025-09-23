# app/core/security_tester.py

# UPDATED: Adds robust CVE lookup with fallbacks when Vulners returns 402
# UPDATED: search_vulners() routes CVE IDs to lookup_cve() automatically
# UPDATED: run_subdomain_scan yields results for real-time display and can be stopped

import asyncio
import platform
import httpx
import vulners
import psutil
import logging
import shutil
import os
import time
import json
from typing import AsyncIterator, Optional, Dict, Any, List, Tuple

from scapy.all import send, IP, TCP, UDP, ICMP, RandShort
from Wappalyzer import Wappalyzer, WebPage

from app.config import AppConfig
from app.core.recon_engine import ReconEngine


class SecurityTester:
    def __init__(self, settings, task_manager):
        self.settings = settings
        self.task_manager = task_manager
        self.vulners_api = None
        self.hibp_api_key = ""

        wordlist_path = os.path.join(AppConfig.PROJECT_ROOT, "subdomains.txt")
        self.recon_engine = ReconEngine(task_manager=self.task_manager, wordlist_path=wordlist_path)

        if self.settings:
            vulners_api_key = self.settings.value("security/vulners_api_key", "")
            if vulners_api_key:
                try:
                    self.vulners_api = vulners.VulnersApi(api_key=vulners_api_key)
                except Exception as e:
                    logging.error(f"Failed to initialize Vulners API: {e}")
            self.hibp_api_key = self.settings.value("security/hibp_api_key", "")

    # ---------- Utility ----------

    def stop_subdomain_scan(self):
        """Passes the stop signal to the recon engine."""
        self.recon_engine.stop_subdomain_scan()

    async def _run_in_executor(self, func, *args, **kwargs):
        return await asyncio.get_running_loop().run_in_executor(None, lambda: func(*args, **kwargs))

    async def _run_command(self, command: str, tool_name: str = "") -> str:
        executable = tool_name or command.split()[0]
        if not shutil.which(executable):
            return f"ERROR: '{executable}' is not installed or not in your system's PATH."
        
        process = await asyncio.create_subprocess_shell(
            command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        output = stdout.decode(errors='ignore')
        error_output = stderr.decode(errors='ignore')

        if process.returncode != 0 and not output:
            return f"Error executing '{executable}':\n{error_output}"
        
        return output + "\n" + error_output

    async def _fetch_json(self, url: str, headers: Optional[dict] = None, timeout: float = 15.0):
        """
        Simple GET JSON with basic error bubbling.
        Returns dict on success; on HTTP error returns {'__status__': code, '__text__': body};
        on network error returns {'__error__': str(err)}.
        """
        try:
            async with httpx.AsyncClient(timeout=timeout, headers=headers or {"User-Agent": "NetOpsToolkitPro/1.0"}) as client:
                r = await client.get(url, follow_redirects=True)
                if r.status_code >= 400:
                    return {"__status__": r.status_code, "__text__": r.text}
                ct = r.headers.get("content-type", "")
                if "application/json" in ct or r.text.strip().startswith("{") or r.text.strip().startswith("["):
                    return r.json()
                # Non-JSON: still return text for debugging
                return {"__status__": r.status_code, "__text__": r.text}
        except Exception as e:
            return {"__error__": str(e)}

    # ---------- Recon / Subdomains ----------

    async def run_subdomain_scan(self, domain: str):
        """Yields subdomain results in real-time."""
        try:
            async for result in self.recon_engine.find_subdomains(domain):
                yield result
        except Exception as e:
            yield {"error": f"An unexpected error occurred during subdomain scan: {e}"}

    @staticmethod
    async def enumerate_subdomains(domain: str, wordlist: List[str]) -> AsyncIterator[dict]:
        timeout = httpx.Timeout(5.0, connect=5.0, read=5.0)
        async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": "NetOpsToolkitPro/1.0"}) as client:
            async def probe(name: str) -> Tuple[str, Optional[int]]:
                url = f"https://{name}.{domain}"
                try:
                    r = await client.get(url, follow_redirects=False)
                    return (url, r.status_code)
                except Exception:
                    return (url, None)

            tasks = [asyncio.create_task(probe(w)) for w in wordlist]
            for fut in asyncio.as_completed(tasks):
                url, code = await fut
                yield {"url": url, "status": code}

    # ---------- Web / Fingerprinting ----------

    async def run_wappalyzer(self, url: str) -> str:
        try:
            if not url.startswith(('http://', 'https://')): 
                url = 'https://' + url
            loop = asyncio.get_running_loop()
            webpage = await loop.run_in_executor(None, WebPage.new_from_url, url)
            wappalyzer = Wappalyzer.latest()
            technologies = wappalyzer.analyze_with_versions(webpage)
            if not technologies: 
                return "No technologies detected or site is unreachable."
            result = f"Technologies for {url}:\n" + "-"*30 + "\n"
            for tech, details in technologies.items():
                version = ", ".join(details.get("versions", []))
                result += f"- {tech} ({version or 'No version detected'})\n"
            return result
        except Exception as e: 
            return f"Error running Wappalyzer: {e}"

    # ---------- Scanners ----------

    async def run_nikto(self, target: str) -> str:
        if platform.system() != "Linux": 
            return "ERROR: Nikto is only available on Linux."
        return await self._run_command(f"nikto -h {target}")

    async def run_nmap_scan(self, target: str, scan_type: str) -> str:
        scan_map = { 
            "Quick Scan": "-T4 -F", 
            "Standard Scan": "-sV -sC", 
            "Vulnerability Scan": "-sV --script vuln" 
        }
        command = f"nmap {scan_map.get(scan_type, '-T4 -F')} {target}"
        return await self._run_command(command, tool_name="nmap")

    # ---------- CVE / Vulners ----------

    async def lookup_cve(self, cve_id: str) -> str:
        """
        Robust CVE lookup with layered fallbacks:
          1) Vulners (if configured)
          2) NVD (public endpoint)
          3) cve.org (MITRE)
          4) CIRCL
        Always returns a human-readable summary string.
        """
        normalized = (cve_id or "").strip().upper()
        if not normalized.startswith("CVE-"):
            return f"ERROR: '{cve_id}' is not a valid CVE ID (e.g., CVE-2025-34158)."

        # 1) Vulners first (if API is configured), but fall through gracefully on 402/any error
        if self.vulners_api:
            try:
                res = await self._run_in_executor(self.vulners_api.search, normalized, limit=5)
                if res:
                    lines = [f"[Vulners] Results for {normalized}:"]
                    for it in res:
                        title = it.get("title") or it.get("id", "")
                        score = (it.get("cvss") or {}).get("score")
                        href = it.get("href") or ""
                        lines.append(f"- {title} | CVSS: {score if score is not None else 'N/A'} | {href}")
                    return "\n".join(lines)
                # no result -> try public sources
            except Exception as e:
                # If 402 or anything else -> try public sources
                logging.info(f"Vulners failed for {normalized}: {e}")

        # 2) NVD (no key)
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={normalized}"
        nvd = await self._fetch_json(nvd_url)
        if isinstance(nvd, dict) and nvd.get("vulnerabilities"):
            try:
                v = nvd["vulnerabilities"][0].get("cve", {})
                metrics = (v.get("metrics") or {})
                score = None
                for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        score = metrics[key][0]["cvssData"].get("baseScore")
                        break
                desc = ""
                descs = (v.get("descriptions") or [])
                if descs:
                    desc = descs[0].get("value") or ""
                refs = [r.get("url") for r in (v.get("references") or []) if r.get("url")]
                out = [
                    f"{normalized}",
                    f"Source: NVD",
                    f"CVSS: {score if score is not None else 'N/A'}",
                    f"Description: {desc or 'N/A'}",
                    "References:"
                ]
                out.extend(f"- {u}" for u in refs[:10])
                return "\n".join(out)
            except Exception as e:
                logging.info(f"NVD parse error for {normalized}: {e}")

        # 3) cve.org (MITRE)
        mitre = await self._fetch_json(f"https://www.cve.org/CVERecord?id={normalized}")
        if isinstance(mitre, dict) and mitre.get("containers"):
            # compact render (don’t dump entire JSON to UI)
            containers = mitre.get("containers", {})
            # try to surface a short description if present
            desc = ""
            try:
                cna = containers.get("cna", {})
                probs = cna.get("descriptions") or []
                if probs:
                    desc = probs[0].get("value") or ""
            except Exception:
                pass
            return (
                f"{normalized}\n"
                f"Source: cve.org (MITRE)\n"
                f"Description: {desc or 'N/A'}\n"
                f"(Raw data available from cve.org)"
            )

        # 4) CIRCL
        circl = await self._fetch_json(f"https://cve.circl.lu/api/cve/{normalized}")
        if isinstance(circl, dict) and circl.get("id"):
            summary = circl.get("summary") or ""
            refs = circl.get("references") or []
            cvss = circl.get("cvss") or circl.get("cvss3") or "N/A"
            out = [
                f"{normalized}",
                f"Source: CIRCL",
                f"CVSS: {cvss}",
                f"Summary: {summary}",
                "References:",
            ]
            out.extend(f"- {u}" for u in refs[:10])
            return "\n".join(out)

        # All failed: assemble troubleshooting info
        details = []
        for label, blob in (("NVD", nvd), ("MITRE", mitre), ("CIRCL", circl)):
            if isinstance(blob, dict) and blob.get("__status__"):
                details.append(f"{label} HTTP {blob['__status__']}")
            elif isinstance(blob, dict) and blob.get("__error__"):
                details.append(f"{label} error: {blob['__error__']}")
        if not details:
            details.append("No data returned by any provider.")
        return f"Lookup failed for {normalized}. " + " | ".join(details)

    async def search_vulners(self, query: str) -> str:
        """
        Preserves your original Vulners search behavior for generic terms.
        If `query` looks like a CVE ID, it routes to lookup_cve() to ensure fallbacks.
        """
        q = (query or "").strip()
        if not q:
            return "ERROR: Please provide a search query."

        # If user typed a CVE ID, use the robust pipeline
        if q.upper().startswith("CVE-"):
            return await self.lookup_cve(q)

        # Otherwise, generic search via Vulners only (with graceful messages)
        if not self.vulners_api:
            return "ERROR: Vulners API key not configured. (Tip: Use a CVE ID to leverage public-source fallback.)"
        try:
            results = await self._run_in_executor(self.vulners_api.search, q, limit=10)
            if not results:
                return f"No vulnerabilities found for '{q}'."
            output = f"Top Vulners results for '{q}':\n" + "="*40 + "\n"
            for res in results:
                output += (
                    f"ID: {res.get('id', 'N/A')}\n"
                    f"Title: {res.get('title', 'No Title')}\n"
                    f"CVSS Score: {res.get('cvss', {}).get('score', 'N/A')}\n"
                    f"Link: {res.get('href', '#')}\n"
                    + "-"*20 + "\n"
                )
            return output
        except Exception as e:
            msg = str(e)
            if "402" in msg or "Payment Required" in msg:
                return (
                    "Vulners returned HTTP 402 (Payment Required). Your key/plan doesn't allow this call or you've run out of credits.\n"
                    "Tip: Run a CVE lookup (e.g., 'CVE-2025-34158') to use public-source fallback automatically."
                )
            return f"Error querying Vulners: {e}"

    # ---------- Audits ----------

    async def run_ddos_simulation(self, target: str, port: int, method: str, duration_seconds: int) -> str:
        try:
            packet_map = {
                "TCP SYN Flood": IP(dst=target)/TCP(sport=RandShort(), dport=port, flags="S"),
                "UDP Flood": IP(dst=target)/UDP(sport=RandShort(), dport=port),
                "ICMP Flood": IP(dst=target)/ICMP()
            }
            packet = packet_map.get(method)
            if not packet: 
                return f"Error: Unknown DDoS method '{method}'"
            end_time = time.time() + duration_seconds
            packet_count = 0
            while time.time() < end_time:
                send(packet, count=100, verbose=0)
                packet_count += 100
                await asyncio.sleep(0.01)
            return f"SUCCESS: Sent approximately {packet_count} '{method}' packets to {target}:{port} over {duration_seconds} seconds."
        except Exception as e:
            return f"Error during DDoS simulation: {e}"

    async def run_wifi_audit(self) -> str:
        system = platform.system()
        cmd_map = {"Windows": "netsh wlan show networks mode=Bssid", "Linux": "nmcli dev wifi list"}
        command = cmd_map.get(system)
        return await self._run_command(command) if command else f"WiFi audit is not supported on {system}."

    async def run_usb_audit(self) -> str:
        try:
            partitions = psutil.disk_partitions()
            usb_devices = [
                f"- Mount: {p.mountpoint}, Type: {p.fstype}, Device: {p.device}"
                for p in partitions
                if ('removable' in p.opts or 'cdrom' in p.opts) and os.path.exists(p.mountpoint)
            ]
            if not usb_devices: 
                return "No removable USB storage devices found."
            return "Connected USB Storage Devices:\n" + "="*30 + "\n" + "\n".join(usb_devices)
        except Exception as e:
            return f"Error auditing USB devices: {e}"

    async def run_password_leak_audit(self, accounts_csv: str) -> str:
        if not self.hibp_api_key: 
            return "ERROR: Have I Been Pwned (HIBP) API key not configured."
        accounts = [acc.strip() for acc in accounts_csv.split(',') if acc.strip()]
        if not accounts: 
            return "Please enter at least one account/email to check."
        results = []
        headers = {"hibp-api-key": self.hibp_api_key, "user-agent": "NetOpsToolkitPro"}
        async with httpx.AsyncClient() as client:
            for account in accounts:
                try:
                    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
                    res = await client.get(url, headers=headers, timeout=15)
                    if res.status_code == 200:
                        results.append(f"❌ {account}: Found in {len(res.json())} breaches.")
                    elif res.status_code == 404:
                        results.append(f"✅ {account}: No breaches found.")
                    else:
                        results.append(f"⚠️ {account}: Error (Code: {res.status_code})")
                except Exception as e:
                    results.append(f"⚠️ {account}: Network or request error - {e}")
        return "Password Leak Audit Results:\n" + "="*30 + "\n" + "\n".join(results)

    async def run_hydra_brute_force(self, target: str, service: str, userlist: str, passlist: str) -> str:
        if platform.system() != "Linux": 
            return "ERROR: Hydra is only available on Linux."
        if not os.path.exists(userlist): 
            return f"ERROR: User list file not found at '{userlist}'"
        if not os.path.exists(passlist): 
            return f"ERROR: Password list file not found at '{passlist}'"
        return await self._run_command(f"hydra -L {userlist} -P {passlist} {target} {service}")

    async def search_exploitdb(self, query: str) -> str:
        if platform.system() != "Linux": 
            return "ERROR: Searchsploit is only available on Linux."
        if not query: 
            return "ERROR: Please provide a search query for Exploit-DB."
        return await self._run_command(f"searchsploit {query}", tool_name="searchsploit")

