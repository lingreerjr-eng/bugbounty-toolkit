#!/usr/bin/env python3
"""
recon_async.py
Async recon orchestrator with enhanced subdomain enumeration,
robots.txt parsing, and sitemap parsing
"""

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path
import argparse
import json
import os

HERE = Path(__file__).resolve().parent
TOOLS = HERE / "tools"
OUTPUT = HERE / "output"

# Import the enhanced subdomain enumerator if available
try:
    from enhanced_subdomain_enum import SubdomainEnumerator
    ENHANCED_ENUM_AVAILABLE = True
except ImportError:
    ENHANCED_ENUM_AVAILABLE = False
    print("[!] enhanced_subdomain_enum.py not found - using basic enumeration only")

DEFAULT_CONCURRENCY = 20

async def run_subprocess(cmd, capture=False):
    """Run subprocess asynchronously"""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE if capture else None,
        stderr=asyncio.subprocess.PIPE if capture else None
    )
    if capture:
        out, err = await proc.communicate()
        return proc.returncode, (out.decode(errors="ignore") if out else ""), (err.decode(errors="ignore") if err else "")
    else:
        await proc.wait()
        return proc.returncode, "", ""

async def enhanced_subdomain_discovery(domain, outdir, concurrency=50):
    """
    Use the enhanced multi-source subdomain enumerator.
    Falls back to basic enumeration if not available.
    """
    if ENHANCED_ENUM_AVAILABLE:
        print("[*] Using enhanced multi-source subdomain enumeration...")
        enumerator = SubdomainEnumerator(domain, outdir, concurrency=concurrency)
        await enumerator.enumerate_all()
        
        # Return paths to the generated files
        return {
            'all': outdir / f"{domain}_all_subdomains.txt",
            'resolved': outdir / f"{domain}_resolved.txt",
            'interesting': outdir / f"{domain}_interesting.txt",
            'resolved_ips': outdir / f"{domain}_resolved_ips.txt",
        }
    else:
        # Fallback to basic enumeration
        print("[*] Using basic subdomain enumeration (crt.sh + subfinder)...")
        sub_crt = outdir / "subdomains_crtsh.txt"
        subfinder_out = outdir / "subfinder.txt"
        
        await crtsh_enum(domain, sub_crt)
        await run_subfinder(domain, subfinder_out)
        
        # Merge results
        subs = set()
        for p in (sub_crt, subfinder_out):
            if p.exists():
                subs.update([l.strip() for l in p.read_text().splitlines() if l.strip()])
        
        subs_all = outdir / "subdomains.txt"
        if subs:
            subs_all.write_text("\n".join(sorted(subs)))
            print(f"[+] merged subdomains into {subs_all}")
        
        return {
            'all': subs_all,
            'resolved': subs_all,  # No resolution in basic mode
            'interesting': None,
        }

async def crtsh_enum(domain, outpath):
    """Use local tools/crtsh_enum.py (sync) via subprocess or fallback to crt.sh JSON"""
    outpath.parent.mkdir(parents=True, exist_ok=True)
    script = TOOLS / "crtsh_enum.py"
    if script.exists():
        rc, out, err = await run_subprocess([sys.executable, str(script), domain], capture=True)
        if rc == 0 and out:
            outpath.write_text(out)
            print(f"[+] crtsh_enum wrote {outpath}")
            return
    # fallback: direct HTTP query
    print("[*] crt.sh script missing or failed; trying HTTP fallback via curl")
    if shutil.which("curl"):
        c = ["curl", "-s", f"https://crt.sh/?q=%25.{domain}&output=json"]
        rc, out, err = await run_subprocess(c, capture=True)
        if rc == 0 and out:
            try:
                entries = json.loads(out)
                subs = set()
                for e in entries:
                    for key in ("common_name","name_value"):
                        v = e.get(key)
                        if not v:
                            continue
                        if isinstance(v, list):
                            vals = v
                        else:
                            vals = [v]
                        for n in vals:
                            for part in str(n).splitlines():
                                part = part.strip().lower()
                                if part.endswith(domain):
                                    subs.add(part)
                outpath.write_text("\n".join(sorted(subs)))
                print(f"[+] crt.sh fallback wrote {outpath}")
                return
            except Exception as e:
                print("[!] crt.sh JSON parse failed:", e)
    print("[!] crt.sh enumeration failed or produced no output")

async def run_subfinder(domain, outpath):
    if shutil.which("subfinder"):
        print("[*] running subfinder...")
        await run_subprocess(["subfinder", "-d", domain, "-o", str(outpath)])
    else:
        print("[!] subfinder not installed; skipping subfinder")

async def probe_httpx(in_subdomains_path, out_alive_path):
    out_alive_path.parent.mkdir(parents=True, exist_ok=True)
    if shutil.which("httpx"):
        print("[*] probing with httpx (local)...")
        await run_subprocess(["httpx", "-l", str(in_subdomains_path), "-silent", "-status-code", "-title", "-o", str(out_alive_path)])
    else:
        # fallback: try python-based probing (simple aiohttp)
        print("[*] httpx not found, using internal async probe (aiohttp)")
        await _internal_http_probe(in_subdomains_path, out_alive_path)

async def _internal_http_probe(in_subdomains_path, out_alive_path, concurrency=50):
    import aiohttp

    subs = []
    if in_subdomains_path.exists():
        subs = [s.strip() for s in in_subdomains_path.read_text().splitlines() if s.strip()]
    if not subs:
        print("[!] no subdomains to probe")
        return

    timeout = aiohttp.ClientTimeout(total=15)
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def check(host):
        async with sem:
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                for scheme in ("https://", "http://"):
                    url = scheme + host
                    try:
                        async with sess.get(url, allow_redirects=True) as resp:
                            title = ""
                            try:
                                txt = await resp.text()
                                i1 = txt.find("<title")
                                if i1 != -1:
                                    i2 = txt.find(">", i1)
                                    if i2 != -1:
                                        i3 = txt.find("</title>", i2)
                                        if i3 != -1:
                                            title = txt[i2+1:i3].strip()
                            except Exception:
                                title = ""
                            results.append(f"{url}\t{resp.status}\t{title}")
                            return
                    except Exception:
                        continue

    tasks = [asyncio.create_task(check(h)) for h in subs]
    await asyncio.gather(*tasks)
    out_alive_path.write_text("\n".join(sorted(results)))
    print(f"[+] wrote {out_alive_path}")

async def gather_wayback_and_js(domain, out_urls, out_js):
    out_urls.parent.mkdir(parents=True, exist_ok=True)
    urls = set()
    if shutil.which("waybackurls"):
        rc, out, err = await run_subprocess(["waybackurls", domain], capture=True)
        if out:
            urls.update(line.strip() for line in out.splitlines() if line.strip())
    if shutil.which("gau"):
        rc, out, err = await run_subprocess(["gau", domain], capture=True)
        if out:
            urls.update(line.strip() for line in out.splitlines() if line.strip())

    if not urls:
        if shutil.which("curl"):
            cdx = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            rc, out, err = await run_subprocess(["curl", "-s", cdx], capture=True)
            try:
                items = json.loads(out)
                for it in items[1:]:
                    urls.add(it[0])
            except Exception:
                pass

    out_urls.write_text("\n".join(sorted(urls)))
    js_files = {u for u in urls if u.lower().endswith(".js") or ".js?" in u or ".js/" in u}
    out_js.write_text("\n".join(sorted(js_files)))
    print(f"[+] wrote {out_urls} and {out_js}")

async def parse_robots_and_sitemaps(alive_file, outdir):
    """Parse robots.txt and sitemap.xml files from alive hosts"""
    script = TOOLS / "robots_sitemap_parser.py"
    if not script.exists():
        print("[!] robots_sitemap_parser.py not found; skipping robots/sitemap parsing")
        return None
    
    if not alive_file.exists():
        print("[!] No alive hosts file; skipping robots/sitemap parsing")
        return None
    
    robots_outdir = outdir / "robots_sitemap"
    print("[*] Parsing robots.txt and sitemap.xml files...")
    await run_subprocess([sys.executable, str(script), str(alive_file), str(robots_outdir)])
    
    return robots_outdir

async def run_nuclei(alive_path, out_nuclei):
    if not shutil.which("nuclei"):
        print("[!] nuclei not installed; skipping nuclei scan")
        return
    out_nuclei.parent.mkdir(parents=True, exist_ok=True)
    await run_subprocess(["nuclei", "-l", str(alive_path), "-silent", "-o", str(out_nuclei)])

async def js_endpoint_worker(js_list_path, out_endpoints_path, concurrency=30):
    script = TOOLS / "js_endpoints_async.py"
    if script.exists():
        await run_subprocess([sys.executable, str(script), str(js_list_path), str(out_endpoints_path)], capture=False)
    else:
        print("[!] js_endpoints_async.py missing; cannot extract endpoints")

async def generate_permutations(domain, discovered_subs_path, outdir):
    """Generate intelligent subdomain permutations"""
    script = TOOLS / "subdomain_permutations.py"
    if not script.exists():
        print("[!] subdomain_permutations.py not found; skipping permutation generation")
        return None
    
    if not discovered_subs_path.exists():
        print("[!] No discovered subdomains to generate permutations from")
        return None
    
    perms_file = outdir / "subdomain_permutations.txt"
    print("[*] Generating intelligent subdomain permutations...")
    await run_subprocess([sys.executable, str(script), domain, str(discovered_subs_path), str(perms_file)])
    
    return perms_file

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target domain")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrency level")
    parser.add_argument("--generate-permutations", action="store_true", help="Generate subdomain permutations")
    parser.add_argument("--skip-http-probe", action="store_true", help="Skip HTTP probing")
    parser.add_argument("--skip-js", action="store_true", help="Skip JS endpoint extraction")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip nuclei scan")
    parser.add_argument("--skip-robots", action="store_true", help="Skip robots.txt and sitemap parsing")
    args = parser.parse_args()
    
    target = args.target
    outdir = OUTPUT / target
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  RECON TOOLKIT - Target: {target}")
    print(f"{'='*60}\n")

    # Phase 1: Enhanced Subdomain Discovery
    print("[Phase 1] Subdomain Discovery")
    print("-" * 60)
    subdomain_files = await enhanced_subdomain_discovery(target, outdir, concurrency=args.concurrency)
    
    # Use resolved subdomains if available, otherwise use all
    active_subs_file = subdomain_files.get('resolved') or subdomain_files.get('all')
    
    # Phase 2: Optional Permutation Generation
    if args.generate_permutations and active_subs_file:
        print(f"\n[Phase 2] Permutation Generation")
        print("-" * 60)
        perms_file = await generate_permutations(target, active_subs_file, outdir)
        if perms_file:
            print(f"[*] Permutations saved to {perms_file}")
            print("[*] You can resolve these with: puredns resolve {perms_file} -r resolvers.txt")
    
    # Phase 3: HTTP Probing
    if not args.skip_http_probe and active_subs_file:
        print(f"\n[Phase 3] HTTP Probing")
        print("-" * 60)
        alive = outdir / "alive.txt"
        await probe_httpx(active_subs_file, alive)
    else:
        alive = outdir / "alive.txt"
    
    # Phase 4: Robots.txt & Sitemap Parsing (NEW!)
    if not args.skip_robots and alive.exists():
        print(f"\n[Phase 4] Robots.txt & Sitemap.xml Parsing")
        print("-" * 60)
        robots_outdir = await parse_robots_and_sitemaps(alive, outdir)
    
    # Phase 5: Historical URLs + JS
    if not args.skip_js:
        print(f"\n[Phase 5] Historical URLs & JavaScript Discovery")
        print("-" * 60)
        wayback_urls = outdir / "wayback_urls.txt"
        js_files = outdir / "js_files.txt"
        js_endpoints = outdir / "js_endpoints.txt"
        
        await gather_wayback_and_js(target, wayback_urls, js_files)
        await js_endpoint_worker(js_files, js_endpoints, concurrency=args.concurrency)
    
    # Phase 6: Vulnerability Scanning
    if not args.skip_nuclei and alive.exists():
        print(f"\n[Phase 6] Vulnerability Scanning")
        print("-" * 60)
        nuclei_out = outdir / "nuclei.txt"
        await run_nuclei(alive, nuclei_out)
    
    # Summary
    print(f"\n{'='*60}")
    print("  RECON COMPLETE")
    print(f"{'='*60}")
    print(f"\nResults saved to: {outdir}")
    print("\nKey files:")
    if subdomain_files.get('resolved'):
        print(f"  - Resolved subdomains: {subdomain_files['resolved'].name}")
    if subdomain_files.get('interesting'):
        print(f"  - Interesting targets: {subdomain_files['interesting'].name}")
    if alive.exists():
        print(f"  - Live HTTP hosts: {alive.name}")
    if (outdir / "robots_sitemap").exists():
        print(f"  - Robots/Sitemap findings: robots_sitemap/")
        print(f"    · All URLs: robots_sitemap/all_urls.txt")
        print(f"    · Disallowed paths: robots_sitemap/robots_disallowed.txt")
        print(f"    · Interesting URLs: robots_sitemap/interesting_all.txt")
    
    print("\nNext steps:")
    print("  1. Review interesting subdomains for high-value targets")
    print("  2. Check alive.txt for active web services")
    print("  3. Review robots_sitemap/robots_disallowed.txt (often contains sensitive paths!)")
    print("  4. Check robots_sitemap/interesting_*.txt files")
    print("  5. Review js_endpoints.txt for API endpoints")
    if args.generate_permutations:
        print("  6. Resolve generated permutations with massdns/puredns/shuffledns")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
