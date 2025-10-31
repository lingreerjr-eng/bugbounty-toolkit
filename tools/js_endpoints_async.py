#!/usr/bin/env python3
"""
js_endpoints_async.py
Async fetch JavaScript files (many in parallel) and extract likely endpoints.
Usage: python3 js_endpoints_async.py js_files.txt out_endpoints.txt
"""

import asyncio
import sys
from pathlib import Path
import re
from urllib.parse import urlparse
import aiohttp
import async_timeout

if len(sys.argv) < 3:
    print("usage: js_endpoints_async.py js_files.txt out_endpoints.txt")
    sys.exit(1)

js_list_file = Path(sys.argv[1])
out_file = Path(sys.argv[2])
CONCURRENCY = 40
REQUEST_TIMEOUT = 15  # seconds
MAX_SIZE = 2_000_000  # bytes - skip very large files

# Regex patterns
URL_STRING_RE = re.compile(r'''(?:"|')((?:https?:)?//[^"']{3,800})(?:"|')''')  # protocol or protocol-relative
REL_PATH_RE = re.compile(r'''(?:"|')((?:/[^"']{2,500}))(?:["'])''')  # relative paths starting with /
PARAM_LIKE_RE = re.compile(r"[a-zA-Z0-9_\-]{2,60}=[a-zA-Z0-9_\-]{0,200}")

async def fetch(session, url):
    try:
        async with async_timeout.timeout(REQUEST_TIMEOUT):
            async with session.get(url, headers={"User-Agent":"Mozilla/5.0 (ReconToolkit/1.0)"}) as resp:
                # quick size check
                length = resp.headers.get("Content-Length")
                if length and int(length) > MAX_SIZE:
                    return None
                text = await resp.text(errors="ignore")
                return text
    except Exception:
        return None

async def process_url(session, url, endpoints_set):
    text = await fetch(session, url)
    if not text:
        return
    # find absolute and protocol-relative urls (//host/path)
    for m in URL_STRING_RE.findall(text):
        u = m
        if u.startswith("//"):
            # assume https by default for protocol-relative
            u = "https:" + u
        endpoints_set.add(u)
    # relative paths
    for m in REL_PATH_RE.findall(text):
        endpoints_set.add(m)
    # query-like param fragments
    for m in PARAM_LIKE_RE.findall(text):
        endpoints_set.add("?" + m)

async def worker(name, session, queue, endpoints_set):
    while True:
        url = await queue.get()
        if url is None:
            queue.task_done()
            return
        await process_url(session, url, endpoints_set)
        queue.task_done()

async def main():
    if not js_list_file.exists():
        print("[!] js files list not found:", js_list_file)
        return

    js_urls = [l.strip() for l in js_list_file.read_text().splitlines() if l.strip()]
    if not js_urls:
        print("[!] js list empty")
        return

    queue = asyncio.Queue()
    endpoints_set = set()

    for u in js_urls:
        queue.put_nowait(u)

    conn = aiohttp.TCPConnector(limit_per_host=10, limit=CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        tasks = []
        for i in range(min(CONCURRENCY, len(js_urls))):
            tasks.append(asyncio.create_task(worker(f"w{i}", session, queue, endpoints_set)))
        await queue.join()
        # stop workers
        for _ in tasks:
            queue.put_nowait(None)
        await asyncio.gather(*tasks, return_exceptions=True)

    # basic normalization: sort and write
    out_file.write_text("\n".join(sorted(endpoints_set)))
    print(f"[+] extracted {len(endpoints_set)} candidate endpoints -> {out_file}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted")
