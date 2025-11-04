#!/usr/bin/env python3
"""
enhanced_subdomain_enum.py
Advanced subdomain enumeration combining multiple sources with intelligent filtering
"""

import asyncio
import aiohttp
import sys
import json
import re
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict
import dns.resolver
import dns.asyncresolver
from typing import Set, Dict, List, Tuple

class SubdomainEnumerator:
    def __init__(self, domain: str, output_dir: Path, concurrency: int = 50):
        self.domain = domain
        self.output_dir = output_dir
        self.concurrency = concurrency
        self.subdomains: Set[str] = set()
        self.sources: Dict[str, Set[str]] = defaultdict(set)
        self.resolved: Dict[str, List[str]] = {}
        
    async def enumerate_all(self):
        """Run all enumeration methods"""
        print(f"[*] Starting comprehensive enumeration for {self.domain}")
        
        tasks = [
            self.crtsh_enum(),
            self.certspotter_enum(),
            self.hackertarget_enum(),
            self.threatcrowd_enum(),
            self.virustotal_enum(),
            self.alienvault_enum(),
            self.urlscan_enum(),
            self.securitytrails_enum(),
            self.dns_dumpster_enum(),
            self.google_transparency_enum(),
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # DNS resolution and filtering
        await self.resolve_subdomains()
        await self.filter_interesting_subdomains()
        
        # Save results
        self.save_results()
        
    async def crtsh_enum(self):
        """Enhanced crt.sh with pagination"""
        source = "crtsh"
        print(f"[*] {source}: Enumerating...")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            for key in ('common_name', 'name_value'):
                                value = entry.get(key, '')
                                if value:
                                    for name in value.split('\n'):
                                        name = name.strip().lower()
                                        if self._is_valid_subdomain(name):
                                            self.subdomains.add(name)
                                            self.sources[source].add(name)
                        print(f"[+] {source}: Found {len(self.sources[source])} subdomains")
        except Exception as e:
            print(f"[!] {source} error: {e}")
    
    async def certspotter_enum(self):
        """CertSpotter API"""
        source = "certspotter"
        print(f"[*] {source}: Enumerating...")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            for name in entry.get('dns_names', []):
                                name = name.lower().strip()
                                if self._is_valid_subdomain(name):
                                    self.subdomains.add(name)
                                    self.sources[source].add(name)
                        print(f"[+] {source}: Found {len(self.sources[source])} subdomains")
        except Exception as e:
            print(f"[!] {source} error: {e}")
    
    async def hackertarget_enum(self):
        """HackerTarget API"""
        source = "hackertarget"
        print(f"[*] {source}: Enumerating...")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.split('\n'):
                            if ',' in line:
                                subdomain = line.split(',')[0].strip().lower()
                                if self._is_valid_subdomain(subdomain):
                                    self.subdomains.add(subdomain)
                                    self.sources[source].add(subdomain)
                        print(f"[+] {source}: Found {len(self.sources[source])} subdomains")
        except Exception as e:
            print(f"[!] {source} error: {e}")
    
    async def threatcrowd_enum(self):
        """ThreatCrowd API"""
        source = "threatcrowd"
        print(f"[*] {source}: Enumerating...")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for subdomain in data.get('subdomains', []):
                            subdomain = subdomain.lower().strip()
                            if self._is_valid_subdomain(subdomain):
                                self.subdomains.add(subdomain)
                                self.sources[source].add(subdomain)
                        print(f"[+] {source}: Found {len(self.sources[source])} subdomains")
        except Exception as e:
            print(f"[!] {source} error: {e}")
    
    async def virustotal_enum(self):
        """VirusTotal API (no key required for basic)"""
        source = "virustotal"
        print(f"[*] {source}: Enumerating...")
        
        # Note: This endpoint is limited without API key
        # Users should add VT_API_KEY environment variable for better results
        api_key = os.environ.get('VT_API_KEY')
        if not api_key:
            print(f"[!] {source}: Set VT_API_KEY environment variable for better results")
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'x-apikey': api_key}
                url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get('data', []):
                            subdomain = item.get('id', '').lower().strip()
                            if self._is_valid_subdomain(subdomain):
                                self.subdomains.add(subdomain)
                                self.sources[source].add(subdomain)
                        print(f"[+] {source}: Found {len(self.sources[source])} subdomains")
        except Exception as e:
            print(f"[!] {source} error: {e}")
    
    async def alienvault_enum(self):
        """AlienVault OTX API"""
        source = "alienvault"
        print(f"[*] {source}: Enumerating...")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get('passive_dns', []):
                            subdomain = item.get('hostname', '').lower().strip()
                            if self._is_valid_subdomain(subdomain):
                                self.subdomains.add(subdomain)
                                self.sources[source].add(subdomain)
                        print(f"[+] {source}: Found {len(self.sources[source])} subdomains")
        except Exception as e:
            print(f"[!] {source} error: {e}")
    
    async def urlscan_enum(self):
        """URLScan.io API"""
        source = "urlscan"
        print(f"[*] {source}: Enumerating...")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for result in data.get('results', []):
                            page_domain = result.get('page', {}).get('domain', '').lower().strip()
                            if self._is_valid_subdomain(page_domain):
                                self.subdomains.add(page_domain)
                                self.sources[source].add(page_domain)
                        print(f"[+] {source}: Found {len(self.sources[source])} subdomains")
        except Exception as e:
            print(f"[!] {source} error: {e}")
    
    async def securitytrails_enum(self):
        """SecurityTrails API (requires key)"""
        source = "securitytrails"
        api_key = os.environ.get('SECURITYTRAILS_API_KEY')
        if not api_key:
            return
        
        print(f"[*] {source}: Enumerating...")
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'APIKEY': api_key}
                url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get('subdomains', []):
                            subdomain = f"{sub}.{self.domain}".lower()
                            self.subdomains.add(subdomain)
                            self.sources[source].add(subdomain)
                        print(f"[+] {source}: Found {len(self.sources[source])} subdomains")
        except Exception as e:
            print(f"[!] {source} error: {e}")
    
    async def dns_dumpster_enum(self):
        """DNSDumpster scraping"""
        source = "dnsdumpster"
        print(f"[*] {source}: Enumerating (requires scraping)...")
        # This would require more complex scraping with session handling
        # Placeholder for now - recommend using dnsdumpster CLI tool instead
        pass
    
    async def google_transparency_enum(self):
        """Google Certificate Transparency"""
        source = "google_ct"
        print(f"[*] {source}: Enumerating...")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain={self.domain}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # Parse response and extract subdomains
                        matches = re.findall(r'[a-zA-Z0-9][\w\-\.]*\.' + re.escape(self.domain), text)
                        for match in matches:
                            subdomain = match.lower().strip()
                            if self._is_valid_subdomain(subdomain):
                                self.subdomains.add(subdomain)
                                self.sources[source].add(subdomain)
                        print(f"[+] {source}: Found {len(self.sources[source])} subdomains")
        except Exception as e:
            print(f"[!] {source} error: {e}")
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format and relevance"""
        if not subdomain or not subdomain.endswith(self.domain):
            return False
        
        # Remove wildcards
        if '*' in subdomain:
            return False
        
        # Basic validation
        parts = subdomain.split('.')
        if len(parts) < 2:
            return False
        
        # Check for invalid characters
        if not re.match(r'^[a-z0-9\-\.]+$', subdomain):
            return False
        
        return True
    
    async def resolve_subdomains(self):
        """Resolve all discovered subdomains to filter out dead ones"""
        print(f"[*] Resolving {len(self.subdomains)} subdomains...")
        
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        sem = asyncio.Semaphore(self.concurrency)
        
        async def resolve(subdomain):
            async with sem:
                try:
                    answers = await resolver.resolve(subdomain, 'A')
                    ips = [str(rdata) for rdata in answers]
                    self.resolved[subdomain] = ips
                    return True
                except:
                    return False
        
        tasks = [resolve(sub) for sub in self.subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        resolved_count = sum(1 for r in results if r is True)
        print(f"[+] Resolved {resolved_count}/{len(self.subdomains)} subdomains")
    
    async def filter_interesting_subdomains(self):
        """Identify potentially interesting subdomains for bug bounty"""
        interesting_patterns = [
            r'(dev|development|staging|stage|test|testing|qa|uat|preprod|pre-prod)',
            r'(admin|administrator|management|manage|console|panel)',
            r'(api|rest|graphql|ws|websocket)',
            r'(internal|corp|vpn|remote)',
            r'(jenkins|gitlab|github|ci|cd|build)',
            r'(jira|confluence|wiki)',
            r'(s3|storage|bucket|cdn|assets|static)',
            r'(mail|smtp|imap|exchange|webmail)',
            r'(portal|login|auth|sso|oauth)',
            r'(backup|old|legacy|archive)',
            r'(mobile|app|apps)',
            r'(payment|pay|billing|invoice)',
        ]
        
        interesting = set()
        for sub in self.resolved.keys():
            for pattern in interesting_patterns:
                if re.search(pattern, sub, re.IGNORECASE):
                    interesting.add(sub)
                    break
        
        interesting_file = self.output_dir / f"{self.domain}_interesting.txt"
        interesting_file.write_text('\n'.join(sorted(interesting)))
        print(f"[+] Found {len(interesting)} interesting subdomains -> {interesting_file}")
    
    def save_results(self):
        """Save all results to files"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # All discovered subdomains
        all_file = self.output_dir / f"{self.domain}_all_subdomains.txt"
        all_file.write_text('\n'.join(sorted(self.subdomains)))
        print(f"[+] Total discovered: {len(self.subdomains)} -> {all_file}")
        
        # Resolved subdomains only
        resolved_file = self.output_dir / f"{self.domain}_resolved.txt"
        resolved_file.write_text('\n'.join(sorted(self.resolved.keys())))
        print(f"[+] Resolved: {len(self.resolved)} -> {resolved_file}")
        
        # Resolved with IPs
        resolved_ips_file = self.output_dir / f"{self.domain}_resolved_ips.txt"
        with open(resolved_ips_file, 'w') as f:
            for sub, ips in sorted(self.resolved.items()):
                f.write(f"{sub}\t{','.join(ips)}\n")
        print(f"[+] With IPs -> {resolved_ips_file}")
        
        # Source breakdown
        sources_file = self.output_dir / f"{self.domain}_sources.json"
        sources_data = {src: sorted(list(subs)) for src, subs in self.sources.items()}
        sources_file.write_text(json.dumps(sources_data, indent=2))
        print(f"[+] Sources breakdown -> {sources_file}")

import os

async def main():
    if len(sys.argv) < 2:
        print("Usage: python3 enhanced_subdomain_enum.py <domain> [output_dir]")
        sys.exit(1)
    
    domain = sys.argv[1]
    output_dir = Path(sys.argv[2] if len(sys.argv) > 2 else f"output/{domain}")
    
    enumerator = SubdomainEnumerator(domain, output_dir)
    await enumerator.enumerate_all()
    
    print("\n[*] Enumeration complete!")
    print(f"[*] Check {output_dir} for results")
    print("\n[*] Pro tips:")
    print("  - Set VT_API_KEY environment variable for VirusTotal results")
    print("  - Set SECURITYTRAILS_API_KEY for SecurityTrails results")
    print("  - Run subfinder/amass separately for even more coverage")
    print("  - Check _interesting.txt for high-value targets")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
