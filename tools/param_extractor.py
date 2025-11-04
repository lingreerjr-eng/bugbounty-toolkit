#!/usr/bin/env python3
"""
param_extractor.py
Extract URLs with parameters from various sources for testing.
Combines wayback URLs, JS endpoints, and crawled URLs.

Usage: python3 param_extractor.py <output_dir> <target_domain>
"""

import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
import re

class ParameterExtractor:
    def __init__(self, output_dir: Path, target_domain: str):
        self.output_dir = output_dir
        self.target_domain = target_domain
        self.urls_with_params = set()
        self.param_stats = defaultdict(int)
        self.interesting_params = set()
        
        # Parameters often vulnerable to SQL injection
        self.interesting_param_names = [
            'id', 'user', 'account', 'userid', 'user_id',
            'cat', 'category', 'page', 'pid', 'product',
            'article', 'item', 'order', 'invoice',
            'search', 'query', 'q', 'keyword',
            'file', 'doc', 'document', 'path',
            'email', 'username', 'name',
            'type', 'sort', 'filter',
            'ref', 'reference', 'redirect', 'url',
        ]
    
    def extract_from_file(self, file_path: Path):
        """Extract parameterized URLs from a file"""
        if not file_path.exists():
            print(f"[!] File not found: {file_path}")
            return 0
        
        count = 0
        for line in file_path.read_text().splitlines():
            url = line.strip()
            if not url:
                continue
            
            # Handle different formats
            # Format: "https://example.com/page?id=1"
            # Format: "https://example.com/page?id=1\t200\tTitle" (from httpx)
            if '\t' in url:
                url = url.split('\t')[0]
            
            if self.is_valid_url_with_params(url):
                self.urls_with_params.add(url)
                self.analyze_params(url)
                count += 1
        
        return count
    
    def is_valid_url_with_params(self, url: str) -> bool:
        """Check if URL is valid and has parameters"""
        try:
            # Must have query parameters
            if '?' not in url or '=' not in url:
                return False
            
            parsed = urlparse(url)
            
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Must be part of target domain
            if self.target_domain not in parsed.netloc:
                return False
            
            # Must have at least one parameter
            params = parse_qs(parsed.query)
            if not params:
                return False
            
            return True
        except Exception:
            return False
    
    def analyze_params(self, url: str):
        """Analyze parameters in URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name in params.keys():
                self.param_stats[param_name] += 1
                
                # Check if it's an interesting parameter
                param_lower = param_name.lower()
                if any(interesting in param_lower for interesting in self.interesting_param_names):
                    self.interesting_params.add(param_name)
        except Exception:
            pass
    
    def save_results(self):
        """Save extracted URLs and statistics"""
        # All parameterized URLs
        all_params_file = self.output_dir / "urls_with_params.txt"
        all_params_file.write_text('\n'.join(sorted(self.urls_with_params)))
        print(f"[+] Saved {len(self.urls_with_params)} URLs with parameters: {all_params_file}")
        
        # Interesting URLs (high-priority for testing)
        interesting_urls = set()
        for url in self.urls_with_params:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params.keys():
                if param_name in self.interesting_params:
                    interesting_urls.add(url)
                    break
        
        interesting_file = self.output_dir / "urls_interesting_params.txt"
        interesting_file.write_text('\n'.join(sorted(interesting_urls)))
        print(f"[+] Saved {len(interesting_urls)} URLs with interesting parameters: {interesting_file}")
        
        # Statistics report
        stats_file = self.output_dir / "param_statistics.txt"
        with open(stats_file, 'w') as f:
            f.write("PARAMETER STATISTICS\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Total URLs with parameters: {len(self.urls_with_params)}\n")
            f.write(f"URLs with interesting parameters: {len(interesting_urls)}\n\n")
            
            f.write("Top 20 Most Common Parameters:\n")
            f.write("-" * 80 + "\n")
            sorted_params = sorted(self.param_stats.items(), key=lambda x: x[1], reverse=True)
            for param, count in sorted_params[:20]:
                marker = " [INTERESTING]" if param in self.interesting_params else ""
                f.write(f"{param:30} : {count:5} occurrences{marker}\n")
            
            f.write("\n\nInteresting Parameters Found:\n")
            f.write("-" * 80 + "\n")
            for param in sorted(self.interesting_params):
                f.write(f"  - {param}\n")
        
        print(f"[+] Saved parameter statistics: {stats_file}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 param_extractor.py <output_dir> <target_domain>")
        print("\nExample:")
        print("  python3 param_extractor.py output/target.com target.com")
        print("\nThis will search for:")
        print("  - wayback_urls.txt")
        print("  - js_endpoints.txt")
        print("  - alive.txt")
        print("  - Any other URL files in the directory")
        sys.exit(1)
    
    output_dir = Path(sys.argv[1])
    target_domain = sys.argv[2]
    
    if not output_dir.exists():
        print(f"[!] Output directory not found: {output_dir}")
        sys.exit(1)
    
    print(f"[*] Extracting parameterized URLs from {output_dir}")
    print(f"[*] Target domain: {target_domain}\n")
    
    extractor = ParameterExtractor(output_dir, target_domain)
    
    # Common file names to check
    files_to_check = [
        "wayback_urls.txt",
        "js_endpoints.txt",
        "alive.txt",
        "burp_urls.txt",
        "urls.txt",
        "endpoints.txt",
    ]
    
    total_found = 0
    for filename in files_to_check:
        file_path = output_dir / filename
        if file_path.exists():
            count = extractor.extract_from_file(file_path)
            if count > 0:
                print(f"[+] {filename}: {count} parameterized URLs")
                total_found += count
    
    if total_found == 0:
        print("\n[!] No parameterized URLs found in any source files")
        print("[!] Make sure you've run the recon first:")
        print("    ./recon_async.py", target_domain)
        sys.exit(0)
    
    print(f"\n[*] Total unique parameterized URLs: {len(extractor.urls_with_params)}")
    
    extractor.save_results()
    
    print("\n" + "=" * 80)
    print("NEXT STEPS:")
    print("=" * 80)
    print("\n1. Review interesting parameters:")
    print(f"   cat {output_dir}/urls_interesting_params.txt")
    print("\n2. Run SQL injection detector on interesting URLs:")
    print(f"   python3 tools/sqli_detector.py {output_dir}/urls_interesting_params.txt {output_dir}/sqli")
    print("\n3. Or test all parameterized URLs:")
    print(f"   python3 tools/sqli_detector.py {output_dir}/urls_with_params.txt {output_dir}/sqli")
    print("\n4. Review findings:")
    print(f"   cat {output_dir}/sqli/sqli_findings.txt")

if __name__ == "__main__":
    main()
