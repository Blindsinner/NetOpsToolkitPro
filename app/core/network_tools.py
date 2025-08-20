# -*- coding: utf-8 -*-
import asyncio
from typing import List, Any, Dict, AsyncGenerator

class NetworkTools:
    async def _run_in_executor(self, func, *args, **kwargs):
        return await asyncio.get_running_loop().run_in_executor(None, lambda: func(*args, **kwargs))

    async def get_ip_geolocation(self, ip: str) -> Dict[str, Any]:
        import httpx
        try:
            async with httpx.AsyncClient() as c:
                return (await c.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,as,query")).json()
        except httpx.RequestError as e:
            return {"error": str(e)}

    async def get_whois_info(self, domain: str) -> Dict[str, Any]:
        import whois
        try:
            return await self._run_in_executor(whois.whois, domain)
        except Exception as e:
            return {"error": str(e)}

    async def get_dns_records(self, domain: str, r_types: List[str]) -> Dict[str, Any]:
        import dns.resolver
        import dns.exception
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        results = {}
        for r_type in r_types:
            try:
                results[r_type] = [str(r) for r in await self._run_in_executor(resolver.resolve, domain, r_type)]
            except dns.exception.DNSException as e:
                results[r_type] = [f"Error: {e.__class__.__name__}"]
        return results

    async def run_nmap_scan(self, targets: str, args: List[str]) -> str:
        command = ['nmap', '-oX', '-'] + args + targets.split()
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"Nmap error: {stderr.decode('utf-8', 'ignore')}")
        return stdout.decode('utf-8', 'ignore')

    async def run_arp_scan(self, target_ip_range: str, interface: str) -> List[Dict[str, str]]:
        from scapy.all import arping
        ans, _ = await self._run_in_executor(arping, target_ip_range, iface=interface, verbose=0)
        return [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in ans]

    async def tcp_port_scan(self, target: str, ports: List[int], timeout: float = 0.5) -> AsyncGenerator[int, None]:
        tasks = {asyncio.create_task(asyncio.open_connection(target, port)): port for port in ports}
        for task in asyncio.as_completed(tasks.keys()):
            try:
                reader, writer = await asyncio.wait_for(task, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                yield tasks[task]
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue

    async def run_diagnostic_command(self, cmd: List[str]) -> AsyncGenerator[str, None]:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        if proc.stdout:
            async for line in proc.stdout:
                yield line.decode('utf-8', 'ignore').strip()
        await proc.wait()