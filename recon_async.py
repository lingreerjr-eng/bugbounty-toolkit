#!/usr/bin/env python3
"""
recon_async.py
Async recon orchestrator. Uses asyncio + aiohttp for network tasks,
and will call local binaries (subfinder, httpx, waybackurls, gau, nuclei)
if they exist. Falls back to HTTP APIs when needed.
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

# concurrency knobs
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

async def crtsh_enum(domain, outpath):
    """Use local tools/tools/crtsh_enum.py (sync) via subprocess or fallback to crt.sh JSON"""
    outpath.parent.mkdir(parents=True, exist_ok=True)
    script = TOOLS / "crtsh_enum.py"
    if script.exists():
        rc, out, err = await run_subprocess([sys.executable, str(script), domain], capture=True)
        if rc == 0 and out:
            outpath.write_text(out)
            print(f"[+] crtsh_enum wrote {outpath}")
            return
    # fallback: direct HTTP query (sync using curl if available)
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
    from urllib.parse import urlparse

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
        # try https then http
        async with sem:
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                for scheme in ("https://", "http://"):
                    url = scheme + host
                    try:
                        async with sess.get(url, allow_redirects=True) as resp:
                            title = ""
                            try:
                                txt = await resp.text()
                                # cheap title extraction
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
        # nothing alive

    tasks = [asyncio.create_task(check(h)) for h in subs]
    await asyncio.gather(*tasks)
    out_alive_path.write_text("\n".join(sorted(results)))
    print(f"[+] wrote {out_alive_path}")

async def gather_wayback_and_js(domain, out_urls, out_js):
    # prefer waybackurls/gau if installed, else use CDX API
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
        # fallback to web.archive.org CDX API using curl
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

async def run_nuclei(alive_path, out_nuclei):
    if not shutil.which("nuclei"):
        print("[!] nuclei not installed; skipping nuclei scan")
        return
    out_nuclei.parent.mkdir(parents=True, exist_ok=True)
    # try to extract hosts/urls for nuclei (basic)
    await run_subprocess(["nuclei", "-l", str(alive_path), "-silent", "-o", str(out_nuclei)])

async def js_endpoint_worker(js_list_path, out_endpoints_path, concurrency=30):
    # call the async JS endpoint extractor
    script = TOOLS / "js_endpoints_async.py"
    if script.exists():
        await run_subprocess([sys.executable, str(script), str(js_list_path), str(out_endpoints_path)], capture=False)
    else:
        print("[!] js_endpoints_async.py missing; cannot extract endpoints")

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    args = parser.parse_args()
    target = args.target

    outdir = OUTPUT / target
    outdir.mkdir(parents=True, exist_ok=True)

    sub_crt = outdir / "subdomains_crtsh.txt"
    subfinder_out = outdir / "subfinder.txt"
    subs_all = outdir / "subdomains.txt"
    alive = outdir / "alive.txt"
    wayback_urls = outdir / "wayback_urls.txt"
    js_files = outdir / "js_files.txt"
    js_endpoints = outdir / "js_endpoints.txt"
    nuclei_out = outdir / "nuclei.txt"

    await crtsh_enum(target, sub_crt)
    await run_subfinder(target, subfinder_out)

    # merge unique subs
    subs = set()
    for p in (sub_crt, subfinder_out):
        if p.exists():
            subs.update([l.strip() for l in p.read_text().splitlines() if l.strip()])
    if subs:
        subs_all.write_text("\n".join(sorted(subs)))
        print(f"[+] merged subdomains into {subs_all}")
    else:
        print("[!] no subdomains discovered yet")

    # probe
    await probe_httpx(subs_all, alive)

    # historical urls + js
    await gather_wayback_and_js(target, wayback_urls, js_files)

    # JS endpoints (async fetcher)
    await js_endpoint_worker(js_files, js_endpoints, concurrency=args.concurrency)

    # optional nuclei scan
    await run_nuclei(alive, nuclei_out)

    print("[*] Recon complete. Outputs in", outdir)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted")

