#!/usr/bin/env python3
# usage: python3 wayback_agg.py example.com wayback_urls.txt js_files.txt

import sys, subprocess, os
from pathlib import Path

if len(sys.argv) < 4:
    print("usage: wayback_agg.py domain out_urls out_js")
    sys.exit(1)

domain, out_urls, out_js = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
urls = set()

# try waybackurls (go tool)
if shutil := __import__('shutil'); shutil.which("waybackurls"):
    p = subprocess.run(["waybackurls", domain], capture_output=True, text=True)
    urls.update(line.strip() for line in p.stdout.splitlines() if line.strip())
else:
    # fallback: use web.archive.org's CDX API
    import requests
    cdx = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    r = requests.get(cdx, timeout=20)
    try:
        items = r.json()
        for it in items[1:]:
            urls.add(it[0])
    except:
        pass

# also try gau if installed
if shutil.which("gau"):
    p = subprocess.run(["gau", domain], capture_output=True, text=True)
    urls.update(line.strip() for line in p.stdout.splitlines() if line.strip())

out_urls.write_text("\n".join(sorted(urls)))
print(f"[+] wrote {out_urls}")

# extract JS files
js = {u for u in urls if u.lower().endswith(".js") or ".js?" in u}
out_js.write_text("\n".join(sorted(js)))
print(f"[+] wrote {out_js}")
