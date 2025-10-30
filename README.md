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
