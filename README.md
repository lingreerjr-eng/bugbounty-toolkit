# Bug Bounty Toolkit
Quick recon and triage toolkit for bug bounty recon. Modular, pluggable, and designed to be extended.

Usage:
1. Install dependencies: see INSTALL.md
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
