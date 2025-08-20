# -*- coding: utf-8 -*-
import asyncio
import httpx
import dns.resolver
import dns.exception
from typing import AsyncGenerator, List

class ReconEngine:
    """A collection of tools for reconnaissance and red team operations."""

    def __init__(self, wordlist_path: str):
        self.wordlist = []
        try:
            with open(wordlist_path, 'r') as f:
                self.wordlist = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Warning: Wordlist not found at {wordlist_path}")

    async def find_subdomains(self, domain: str) -> AsyncGenerator[dict, None]:
        """
        Finds subdomains using multiple methods and yields results as they are found.
        """
        found_subdomains = set()

        # Method 1: Certificate Transparency Logs (crt.sh)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
                if response.status_code == 200:
                    for cert in response.json():
                        name = cert.get('name_value', '')
                        if name.endswith(domain) and '*' not in name and name not in found_subdomains:
                            found_subdomains.add(name)
                            yield {"subdomain": name, "source": "crt.sh"}
        except httpx.RequestError as e:
            yield {"error": f"crt.sh query failed: {e}"}

        # Method 2: DNS Brute-force
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        async def check_subdomain(sub):
            """FIX: This is now a coroutine that returns a value, not a generator."""
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

        tasks = [check_subdomain(sub) for sub in self.wordlist]
        for future in asyncio.as_completed(tasks):
            result = await future
            if result and result["subdomain"] not in found_subdomains:
                found_subdomains.add(result["subdomain"])
                yield result