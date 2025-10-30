#!/usr/bin/env python3
# usage: python3 js_endpoints.py js_files.txt out_endpoints.txt
import sys, re, requests
from urllib.parse import urlparse

if len(sys.argv) < 3:
    print("usage: js_endpoints.py js_files.txt out_endpoints.txt")
    sys.exit(1)

js_list = [l.strip() for l in open(sys.argv[1]) if l.strip()]
outf = sys.argv[2]
endpoints = set()

# simple regexes for endpoints
regex = re.compile(r"""(?:"|')((?:/|https?://)[^"']{3,300})(?:"|')""")
params_re = re.compile(r"[a-zA-Z0-9_\-]+=[a-zA-Z0-9_\-]+")

for url in js_list:
    try:
        r = requests.get(url, timeout=10)
        text = r.text
    except Exception:
        continue
    for m in regex.findall(text):
        # filter out static files
        if any(m.endswith(x) for x in (".png",".jpg",".jpeg",".svg",".css",".woff",".ttf")):
            continue
        endpoints.add(m)
    # find param-like items inside JS to make candidate endpoints
    for p in params_re.findall(text):
        endpoints.add("?" + p)

open(outf,"w").write("\n".join(sorted(endpoints)))
print(f"[+] wrote {outf}")
