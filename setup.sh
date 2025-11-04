#!/usr/bin/env bash
# setup.sh - Setup script for the recon toolkit

set -e

echo "=================================================="
echo "  Bug Bounty Recon Toolkit - Setup"
echo "=================================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python
echo -e "${YELLOW}[*] Checking Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is required but not installed${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Python 3 found: $(python3 --version)${NC}"

# Install Python dependencies
echo -e "\n${YELLOW}[*] Installing Python dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    python3 -m pip install -r requirements.txt
    echo -e "${GREEN}[+] Python dependencies installed${NC}"
else
    echo -e "${RED}[!] requirements.txt not found${NC}"
fi

# Create directory structure
echo -e "\n${YELLOW}[*] Creating directory structure...${NC}"
mkdir -p tools
mkdir -p output
echo -e "${GREEN}[+] Directories created${NC}"

# Make scripts executable
echo -e "\n${YELLOW}[*] Making scripts executable...${NC}"
chmod +x recon.sh 2>/dev/null || true
chmod +x recon_async.py 2>/dev/null || true
chmod +x enhanced_subdomain_enum.py 2>/dev/null || true
chmod +x tools/*.py 2>/dev/null || true
echo -e "${GREEN}[+] Scripts made executable${NC}"

# Check optional tools
echo -e "\n${YELLOW}[*] Checking optional tools...${NC}"

check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}[+] $1 found${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] $1 not found (optional)${NC}"
        return 1
    fi
}

MISSING_TOOLS=""

check_tool "subfinder" || MISSING_TOOLS="$MISSING_TOOLS\n  - subfinder (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)"
check_tool "httpx" || MISSING_TOOLS="$MISSING_TOOLS\n  - httpx (go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest)"
check_tool "nuclei" || MISSING_TOOLS="$MISSING_TOOLS\n  - nuclei (go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest)"
check_tool "waybackurls" || MISSING_TOOLS="$MISSING_TOOLS\n  - waybackurls (go install github.com/tomnomnom/waybackurls@latest)"
check_tool "gau" || MISSING_TOOLS="$MISSING_TOOLS\n  - gau (go install github.com/lc/gau/v2/cmd/gau@latest)"
check_tool "massdns" || MISSING_TOOLS="$MISSING_TOOLS\n  - massdns (git clone https://github.com/blechschmidt/massdns.git && cd massdns && make)"
check_tool "puredns" || MISSING_TOOLS="$MISSING_TOOLS\n  - puredns (go install github.com/d3mondev/puredns/v2@latest)"

# DNS Resolvers
echo -e "\n${YELLOW}[*] Setting up DNS resolvers...${NC}"
if [ ! -f "resolvers.txt" ]; then
    echo "Creating resolvers.txt..."
    cat > resolvers.txt << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
208.67.222.222
208.67.220.220
9.9.9.9
149.112.112.112
EOF
    echo -e "${GREEN}[+] Basic resolvers.txt created${NC}"
    echo -e "${YELLOW}    For better results, download a comprehensive list:${NC}"
    echo -e "${YELLOW}    curl https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -o resolvers.txt${NC}"
else
    echo -e "${GREEN}[+] resolvers.txt already exists${NC}"
fi

# Summary
echo -e "\n=================================================="
echo -e "  Setup Complete!"
echo -e "=================================================="
echo ""
echo -e "${GREEN}✓ Core toolkit is ready to use${NC}"
echo ""

if [ -n "$MISSING_TOOLS" ]; then
    echo -e "${YELLOW}Optional tools not installed:${NC}"
    echo -e "${MISSING_TOOLS}"
    echo ""
    echo "Install them for better results (requires Go):"
    echo "  1. Install Go: https://go.dev/doc/install"
    echo "  2. Run the commands above"
    echo ""
fi

echo "Environment variables (optional):"
echo "  export VT_API_KEY='your_virustotal_key'"
echo "  export SECURITYTRAILS_API_KEY='your_securitytrails_key'"
echo ""
echo "Quick start:"
echo "  ./recon_async.py example.com"
echo "  ./recon_async.py example.com --generate-permutations"
echo ""
echo "For more options:"
echo "  ./recon_async.py --help"
