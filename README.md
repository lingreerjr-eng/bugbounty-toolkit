# Bug Bounty Toolkit
Quick recon and triage toolkit for bug bounty recon. Modular, pluggable, and designed to be extended.

Usage:
1. Install dependencies
2. Run: ./recon.sh example.com
3. Inspect outputs in output/example.com

Author: onyx

Optional but highly recommended external tools (install if you want fast scanning):

# Go tools (needs Go >= 1.20+)
# set GOPATH/bin on your PATH (e.g., export PATH=$PATH:$(go env GOPATH)/bin)

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

go install -v github.com/OWASP/Amass/v3/...@latest

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

go install -v github.com/tomnomnom/waybackurls@latest

go install -v github.com/tomnomnom/httprobe@latest

go install -v github.com/tomnomnom/gf@latest

go install -v github.com/ffuf/ffuf@latest

# If you use gau:

go install -v github.com/lc/gau/v2/cmd/gau@latest


How to use — quick workflow

Clone repo, create .venv and install requirements.

Install at least httpx (or the Go httpx) and subfinder for speed.

# Run the pipeline for a target:
./recon.sh example.com
# or use python orchestrator
python3 recon.py example.com

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

inspect output/example.com/ for:

subdomains.txt — all discovered subdomains

alive.txt — hosts responding over HTTP/HTTPS

js_files.txt — candidate JS files to review

js_endpoints.txt — endpoints pulled from JS


# You can make script better by:

Add concurrency to the Python scripts (async + aiohttp) for speed.

Add nuclei templates for high-value checks and schedule nightly scans on safe targets.

Integrate amass passive + active enumeration (DNS bruteforce).

Add a Burp extension or import flow to push js_endpoints.txt into Burp for scanning.

Add a triage script to automatically check for interesting strings in JS (AWS keys, S3 buckets, firebase urls, API keys).

Add GPG/secure storage for any creds and never store sensitive data in git.

Add a report/ generator that summarizes findings and creates templated disclosure notes.

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Only run active scans (ffuf, nuclei -severity high, nmap -sS) on targets you are authorized to test. For public bug bounties, follow program scope and rules.

For private programs, get written authorization if you’ll do intrusive testing.

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Install requirements with:
source .venv/bin/activate

pip install -r requirements.txt

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Quick example workflow
1) run async recon
python3 recon_async.py example.com

2) after it completes:
ls output/example.com
you'll find subdomains, alive, wayback_urls.txt, js_files.txt, js_endpoints.txt, etc.

3) export for Burp
python3 tools/burp_export.py output/example.com

4) Import 'burp_urls.txt' into Burp via Target -> right-click -> Import URLs

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Quick troubleshooting

No subdomains.txt? Check subdomains_crtsh.txt and subfinder.txt to see which source failed.

alive.txt empty? Try installing httpx or inspect network egress/rate limits.

js_endpoints.txt empty but js_files.txt has URLs? Try lowering the JS fetch concurrency or increasing timeout in tools/js_endpoints_async.py (adjust CONCURRENCY / REQUEST_TIMEOUT / MAX_SIZE).

Permission errors? Run from repo root and ensure your user can write the output/ folder.
