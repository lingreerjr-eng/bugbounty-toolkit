#!/usr/bin/env python3
"""
robots_sitemap_parser.py
Parse robots.txt and sitemap.xml files from discovered hosts
Extracts URLs, directories, and interesting endpoints

Usage: python3 robots_sitemap_parser.py <alive_hosts_file.txt> <output_dir>
"""

import asyncio
import aiohttp
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from pathlib import Path
import sys
from typing import Set, List, Dict
import re

class RobotsSitemapParser:
    def __init__(self, output_dir: Path, concurrency: int = 20):
        self.output_dir = output_dir
        self.concurrency = concurrency
        
        # Results storage
        self.all_urls = set()
        self.disallowed_paths = set()
        self.allowed_paths = set()
        self.sitemap_urls = set()
        self.crawl_delays = {}
        self.user_agents = set()
        self.interesting_patterns = {
            'admin': set(),
            'api': set(),
            'backup': set(),
            'config': set(),
            'upload': set(),
            'test': set(),
            'dev': set(),
            'private': set(),
        }
        
        # Statistics
        self.stats = {
            'hosts_scanned': 0,
            'robots_found': 0,
            'sitemaps_found': 0,
            'urls_extracted': 0,
        }
    
    async def parse_hosts(self, hosts: List[str]):
        """Parse robots.txt and sitemaps for all hosts"""
        print(f"[*] Parsing robots.txt and sitemaps for {len(hosts)} hosts...")
        
        sem = asyncio.Semaphore(self.concurrency)
        
        async def parse_with_semaphore(host):
            async with sem:
                return await self.parse_host(host)
        
        tasks = [parse_with_semaphore(host) for host in hosts]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.save_results()
        self.print_summary()
    
    async def parse_host(self, host: str):
        """Parse robots.txt and sitemap for a single host"""
        # Ensure host has scheme
        if not host.startswith(('http://', 'https://')):
            # Try HTTPS first
            for scheme in ['https://', 'http://']:
                test_host = scheme + host
                if await self.check_host_alive(test_host):
                    host = test_host
                    break
            else:
                return  # Host not reachable
        
        self.stats['hosts_scanned'] += 1
        
        # Parse robots.txt
        await self.parse_robots(host)
        
        # Parse sitemap.xml
        await self.parse_sitemap(host)
    
    async def check_host_alive(self, url: str) -> bool:
        """Quick check if host is reachable"""
        try:
            async with aiohttp.ClientSession() as session:
                timeout = aiohttp.ClientTimeout(total=5)
                async with session.head(url, timeout=timeout, allow_redirects=True) as resp:
                    return resp.status < 500
        except:
            return False
    
    async def parse_robots(self, base_url: str):
        """Parse robots.txt file"""
        robots_url = urljoin(base_url, '/robots.txt')
        
        try:
            async with aiohttp.ClientSession() as session:
                timeout = aiohttp.ClientTimeout(total=10)
                async with session.get(robots_url, timeout=timeout) as resp:
                    if resp.status != 200:
                        return
                    
                    content = await resp.text()
                    self.stats['robots_found'] += 1
                    print(f"[+] Found robots.txt: {robots_url}")
                    
                    # Parse robots.txt
                    current_user_agent = '*'
                    for line in content.split('\n'):
                        line = line.strip()
                        
                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue
                        
                        # Parse different directives
                        if ':' in line:
                            directive, value = line.split(':', 1)
                            directive = directive.strip().lower()
                            value = value.strip()
                            
                            if directive == 'user-agent':
                                current_user_agent = value
                                self.user_agents.add(value)
                            
                            elif directive == 'disallow':
                                if value and value != '/':
                                    full_url = urljoin(base_url, value)
                                    self.disallowed_paths.add(full_url)
                                    self.all_urls.add(full_url)
                                    self.categorize_url(full_url)
                            
                            elif directive == 'allow':
                                if value:
                                    full_url = urljoin(base_url, value)
                                    self.allowed_paths.add(full_url)
                                    self.all_urls.add(full_url)
                                    self.categorize_url(full_url)
                            
                            elif directive == 'sitemap':
                                if value:
                                    self.sitemap_urls.add(value)
                                    # Parse this sitemap
                                    await self.parse_sitemap_url(value)
                            
                            elif directive == 'crawl-delay':
                                try:
                                    self.crawl_delays[base_url] = float(value)
                                except:
                                    pass
        
        except Exception as e:
            pass  # Silently skip failed requests
    
    async def parse_sitemap(self, base_url: str):
        """Parse sitemap.xml file"""
        # Try common sitemap locations
        sitemap_locations = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap1.xml',
            '/sitemap-index.xml',
            '/sitemap/sitemap.xml',
        ]
        
        for location in sitemap_locations:
            sitemap_url = urljoin(base_url, location)
            await self.parse_sitemap_url(sitemap_url)
    
    async def parse_sitemap_url(self, sitemap_url: str):
        """Parse a specific sitemap URL"""
        try:
            async with aiohttp.ClientSession() as session:
                timeout = aiohttp.ClientTimeout(total=15)
                async with session.get(sitemap_url, timeout=timeout) as resp:
                    if resp.status != 200:
                        return
                    
                    content = await resp.text()
                    
                    # Check if it's gzipped
                    if sitemap_url.endswith('.gz'):
                        import gzip
                        content = gzip.decompress(await resp.read()).decode('utf-8')
                    
                    self.stats['sitemaps_found'] += 1
                    print(f"[+] Found sitemap: {sitemap_url}")
                    
                    # Parse XML
                    try:
                        root = ET.fromstring(content)
                        
                        # Handle different sitemap formats
                        # Standard sitemap
                        namespaces = {
                            '': 'http://www.sitemaps.org/schemas/sitemap/0.9',
                            'xhtml': 'http://www.w3.org/1999/xhtml',
                            'image': 'http://www.google.com/schemas/sitemap-image/1.1',
                        }
                        
                        # Extract URLs from <loc> tags
                        for elem in root.iter():
                            # Remove namespace for easier matching
                            tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                            
                            if tag == 'loc' and elem.text:
                                url = elem.text.strip()
                                
                                # Check if it's a sitemap index (nested sitemap)
                                if url.endswith('.xml') or 'sitemap' in url.lower():
                                    # Recursively parse nested sitemap
                                    await self.parse_sitemap_url(url)
                                else:
                                    self.all_urls.add(url)
                                    self.categorize_url(url)
                                    self.stats['urls_extracted'] += 1
                    
                    except ET.ParseError:
                        # Try to extract URLs with regex as fallback
                        url_pattern = re.compile(r'<loc>(.*?)</loc>')
                        urls = url_pattern.findall(content)
                        for url in urls:
                            url = url.strip()
                            if url.endswith('.xml') or 'sitemap' in url.lower():
                                await self.parse_sitemap_url(url)
                            else:
                                self.all_urls.add(url)
                                self.categorize_url(url)
                                self.stats['urls_extracted'] += 1
        
        except Exception as e:
            pass  # Silently skip failed requests
    
    def categorize_url(self, url: str):
        """Categorize URL into interesting patterns"""
        url_lower = url.lower()
        
        patterns = {
            'admin': r'(admin|administrator|management|console|panel|dashboard)',
            'api': r'(api|rest|graphql|endpoint|v1|v2|v3)',
            'backup': r'(backup|bak|old|archive|dump|sql)',
            'config': r'(config|configuration|settings|env|\.ini|\.conf)',
            'upload': r'(upload|file|media|asset|document)',
            'test': r'(test|testing|qa|demo|sandbox|staging)',
            'dev': r'(dev|development|debug)',
            'private': r'(private|internal|secret|hidden)',
        }
        
        for category, pattern in patterns.items():
            if re.search(pattern, url_lower):
                self.interesting_patterns[category].add(url)
    
    def save_results(self):
        """Save all results to files"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # All URLs
        all_urls_file = self.output_dir / "all_urls.txt"
        all_urls_file.write_text('\n'.join(sorted(self.all_urls)))
        print(f"\n[+] Saved {len(self.all_urls)} URLs: {all_urls_file}")
        
        # Disallowed paths (often interesting!)
        if self.disallowed_paths:
            disallowed_file = self.output_dir / "robots_disallowed.txt"
            disallowed_file.write_text('\n'.join(sorted(self.disallowed_paths)))
            print(f"[+] Saved {len(self.disallowed_paths)} disallowed paths: {disallowed_file}")
        
        # Allowed paths
        if self.allowed_paths:
            allowed_file = self.output_dir / "robots_allowed.txt"
            allowed_file.write_text('\n'.join(sorted(self.allowed_paths)))
            print(f"[+] Saved {len(self.allowed_paths)} allowed paths: {allowed_file}")
        
        # Sitemap URLs
        if self.sitemap_urls:
            sitemap_file = self.output_dir / "sitemap_urls.txt"
            sitemap_file.write_text('\n'.join(sorted(self.sitemap_urls)))
            print(f"[+] Saved {len(self.sitemap_urls)} sitemap URLs: {sitemap_file}")
        
        # Interesting categories
        for category, urls in self.interesting_patterns.items():
            if urls:
                category_file = self.output_dir / f"interesting_{category}.txt"
                category_file.write_text('\n'.join(sorted(urls)))
                print(f"[+] Saved {len(urls)} {category} URLs: {category_file}")
        
        # Combined interesting
        all_interesting = set()
        for urls in self.interesting_patterns.values():
            all_interesting.update(urls)
        
        if all_interesting:
            interesting_file = self.output_dir / "interesting_all.txt"
            interesting_file.write_text('\n'.join(sorted(all_interesting)))
            print(f"[+] Saved {len(all_interesting)} total interesting URLs: {interesting_file}")
        
        # Statistics report
        stats_file = self.output_dir / "robots_sitemap_stats.txt"
        with open(stats_file, 'w') as f:
            f.write("ROBOTS.TXT & SITEMAP PARSING STATISTICS\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Hosts scanned: {self.stats['hosts_scanned']}\n")
            f.write(f"Robots.txt files found: {self.stats['robots_found']}\n")
            f.write(f"Sitemap files found: {self.stats['sitemaps_found']}\n")
            f.write(f"Total URLs extracted: {len(self.all_urls)}\n")
            f.write(f"Disallowed paths: {len(self.disallowed_paths)}\n")
            f.write(f"Allowed paths: {len(self.allowed_paths)}\n\n")
            
            f.write("Interesting URLs by Category:\n")
            f.write("-" * 80 + "\n")
            for category, urls in sorted(self.interesting_patterns.items()):
                f.write(f"  {category:15} : {len(urls):5} URLs\n")
            
            if self.user_agents:
                f.write("\n\nUser-Agents Found in robots.txt:\n")
                f.write("-" * 80 + "\n")
                for ua in sorted(self.user_agents):
                    f.write(f"  - {ua}\n")
            
            if self.crawl_delays:
                f.write("\n\nCrawl Delays:\n")
                f.write("-" * 80 + "\n")
                for host, delay in sorted(self.crawl_delays.items()):
                    f.write(f"  {host}: {delay} seconds\n")
        
        print(f"[+] Saved statistics: {stats_file}")
    
    def print_summary(self):
        """Print summary to console"""
        print("\n" + "=" * 80)
        print("ROBOTS.TXT & SITEMAP PARSING SUMMARY")
        print("=" * 80)
        print(f"Hosts scanned:        {self.stats['hosts_scanned']}")
        print(f"Robots.txt found:     {self.stats['robots_found']}")
        print(f"Sitemaps found:       {self.stats['sitemaps_found']}")
        print(f"Total URLs extracted: {len(self.all_urls)}")
        print(f"Disallowed paths:     {len(self.disallowed_paths)}")
        
        print("\nInteresting URLs:")
        for category, urls in sorted(self.interesting_patterns.items()):
            if urls:
                print(f"  {category:15} : {len(urls)} URLs")
        
        print("\nKey files:")
        print(f"  - All URLs: {self.output_dir / 'all_urls.txt'}")
        print(f"  - Disallowed: {self.output_dir / 'robots_disallowed.txt'}")
        print(f"  - Interesting: {self.output_dir / 'interesting_all.txt'}")

async def main():
    if len(sys.argv) < 3:
        print("Usage: python3 robots_sitemap_parser.py <alive_hosts_file.txt> <output_dir>")
        print("\nExample:")
        print("  python3 robots_sitemap_parser.py output/target.com/alive.txt output/target.com/robots_sitemap")
        print("\nInput file format:")
        print("  One host per line (with or without http/https)")
        print("  https://example.com")
        print("  sub.example.com")
        sys.exit(1)
    
    hosts_file = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    
    if not hosts_file.exists():
        print(f"[!] Hosts file not found: {hosts_file}")
        sys.exit(1)
    
    # Load hosts
    hosts = []
    for line in hosts_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        
        # Handle different formats
        # Format: "https://example.com\t200\tTitle" (from httpx)
        if '\t' in line:
            host = line.split('\t')[0]
        else:
            host = line
        
        hosts.append(host)
    
    if not hosts:
        print("[!] No hosts found in file")
        sys.exit(1)
    
    print(f"[*] Loaded {len(hosts)} hosts")
    
    # Parse robots.txt and sitemaps
    parser = RobotsSitemapParser(output_dir, concurrency=20)
    await parser.parse_hosts(hosts)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
