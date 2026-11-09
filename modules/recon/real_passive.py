"""
Recolector REAL pasivo - Solo información pública verificable
"""
import asyncio
import aiohttp
import socket
import ssl
from typing import Dict, List
import json
from pathlib import Path

from modules.checks.ssrf_guard import validate_host

class RealPassiveCollector:
    """Recolector 100% pasivo con fuentes públicas"""
    
    def __init__(self):
        self.crtsh_url = "https://crt.sh/?q={}&output=json"
    
    async def get_crtsh_subdomains(self, domain: str) -> List[str]:
        """Obtiene subdominios desde crt.sh (público)"""
        subdomains = set()
        try:
            async with aiohttp.ClientSession() as session:
                url = self.crtsh_url.format(f"%.{domain}")
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json()
                            for entry in data:
                                name_value = entry.get('name_value', '')
                                for name in name_value.split('\n'):
                                    name = name.strip().lower()
                                    if name and name.endswith(domain) and '*' not in name:
                                        subdomains.add(name)
                        except:
                            pass
        except Exception as e:
            print(f"[crt.sh] Error: {e}")
        return sorted(list(subdomains))
    
    async def check_live(self, hostname: str) -> bool:
        """Verifica si el host responde por HTTP/HTTPS con HEAD"""
        safe, reason = validate_host(hostname)
        if not safe:
            print(f"[SSRF] Host omitido ({hostname}): {reason}")
            return False
        for scheme in ['https', 'http']:
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.head(f"{scheme}://{hostname}", timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                        if resp.status < 500:
                            return True
            except:
                continue
        return False
    
    async def collect_real(self, domain: str) -> Dict:
        """Recolecta solo información 100% pasiva y verificable"""
        safe, reason = validate_host(domain)
        if not safe:
            raise ValueError(f"Objetivo no permitido: {reason}")
        print(f"[REAL-PASSIVE] Collecting from public sources for {domain}")
        subdomains = await self.get_crtsh_subdomains(domain)
        print(f"[crt.sh] Found {len(subdomains)} candidate subdomains")
        
        live_hosts = []
        for sub in subdomains[:20]:  # Limitar para ser razonable
            if await self.check_live(sub):
                live_hosts.append(f"https://{sub}" if not sub.startswith(('http://','https://')) else sub)
        print(f"[REAL-PASSIVE] {len(live_hosts)} live hosts verified by HTTP(S) HEAD")
        
        # También verificar el dominio principal
        if domain not in [h.replace('https://','').replace('http://','') for h in live_hosts]:
            if await self.check_live(domain):
                live_hosts.insert(0, f"https://{domain}")
        
        return {
            "domain": domain,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "sources": ["crt.sh"],
            "method": "passive_public_only"
        }
