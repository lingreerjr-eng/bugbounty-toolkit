#!/usr/bin/env python3
# usage: python3 crtsh_enum.py example.com

import sys, requests, json, tldextract

if len(sys.argv) < 2:
    print("Usage: crtsh_enum.py domain")
    sys.exit(1)

domain = sys.argv[1]

url = f"https://crt.sh/?q=%25.{domain}&output=json"
resp = requests.get(url, timeout=30)
if resp.status_code != 200:
    sys.exit(0)

try:
    data = resp.json()
except:
    print("", end="")
    sys.exit(0)

subdomains = set()
for e in data:
    name = e.get("common_name") or e.get("name_value")
    if not name:
        continue
    for n in (name if isinstance(name, list) else [name]):
        n = n.strip()
        # sometimes name contains multiple domains at once
        for part in n.splitlines():
            part = part.strip().lower()
            if part.endswith(domain):
                subdomains.add(part)

for s in sorted(subdomains):
    print(s)
