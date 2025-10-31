#!/usr/bin/env python3
"""
burp_export.py
Create newline URL list and a CSV site map for Burp usage.
Usage:
    python3 burp_export.py <output_dir>
It looks for these files in the output_dir:
 - alive.txt      (from http probe) -- lines like: https://sub.example.com<TAB>200<TAB>title
 - js_endpoints.txt  (endpoints extracted from JS)
 - wayback_urls.txt (historical urls)
"""

import csv
import sys
from pathlib import Path
from urllib.parse import urlparse, urljoin

if len(sys.argv) < 2:
    print("usage: burp_export.py <output_dir>")
    sys.exit(1)

outdir = Path(sys.argv[1])
if not outdir.exists():
    print("output dir not found:", outdir)
    sys.exit(1)

alive = outdir / "alive.txt"
js_endpoints = outdir / "js_endpoints.txt"
wayback = outdir / "wayback_urls.txt"

urls_set = set()

def add_url(u):
    if not u:
        return
    u = u.strip()
    # ignore data:, about: etc
    if u.startswith("data:") or u.startswith("about:") or u.startswith("javascript:"):
        return
    # for relative endpoints that start with '/', we cannot resolve host here.
    if u.startswith("/"):
        # leave as-is for manual inspection
        urls_set.add(u)
        return
    # ensure we have scheme for protocol-relative
    if u.startswith("//"):
        u = "https:" + u
    # ensure scheme exists
    if not urlparse(u).scheme:
        # skip poor fragments
        return
    urls_set.add(u)

# alive.txt lines may be "https://host\t200\ttitle"
if alive.exists():
    for line in alive.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        # first column could be full URL or host
        first = parts[0].strip()
        # if it's just host, assume https
        if first.startswith("http://") or first.startswith("https://"):
            add_url(first)
        else:
            # try build https and http
            add_url("https://" + first)
            add_url("http://" + first)

# js_endpoints
if js_endpoints.exists():
    for line in js_endpoints.read_text().splitlines():
        add_url(line.strip())

# wayback urls
if wayback.exists():
    for line in wayback.read_text().splitlines():
        add_url(line.strip())

# write urls.txt (newline list)
urls_txt = outdir / "burp_urls.txt"
urls_txt.write_text("\n".join(sorted(urls_set)))
print(f"[+] wrote {urls_txt} ({len(urls_set)} urls)")

# create a CSV site map (best-effort fields)
csv_file = outdir / "burp_site_map.csv"
with open(csv_file, "w", newline="", encoding="utf-8") as fh:
    writer = csv.writer(fh)
    writer.writerow(["url","method","host","port","protocol","path","status","length","comment"])
    for u in sorted(urls_set):
        if u.startswith("/"):
            # unknown host; put blanks where appropriate
            writer.writerow([u,"GET","","", "","", "","", "relative endpoint"])
            continue
        p = urlparse(u)
        scheme = p.scheme
        host = p.hostname or ""
        port = p.port or (443 if scheme=="https" else 80)
        path = p.path or "/"
        q = ("?" + p.query) if p.query else ""
        fullpath = path + q
        writer.writerow([u,"GET",host,port,scheme,fullpath,"","", "imported"])
print(f"[+] wrote CSV {csv_file}")
