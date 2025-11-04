#!/usr/bin/env bash
# quick_robots_check.sh - Quick check of robots.txt and sitemap for a single domain
# Usage: ./quick_robots_check.sh example.com

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: ./quick_robots_check.sh <domain>"
    echo ""
    echo "Examples:"
    echo "  ./quick_robots_check.sh example.com"
    echo "  ./quick_robots_check.sh https://example.com"
    exit 1
fi

DOMAIN=$1

# Remove protocol if present
DOMAIN_CLEAN=$(echo "$DOMAIN" | sed -e 's|^https\?://||' -e 's|/.*||')

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Quick Robots.txt & Sitemap Checker                  ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo ""
echo -e "Target: ${GREEN}$DOMAIN_CLEAN${NC}"
echo ""

# Function to try URL
try_url() {
    local url=$1
    local name=$2
    
    echo -e "${YELLOW}[*] Checking $name...${NC}"
    
    response=$(curl -s -o /dev/null -w "%{http_code}" -L "$url" 2>/dev/null || echo "000")
    
    if [ "$response" = "200" ]; then
        echo -e "${GREEN}[✓] Found: $url${NC}"
        return 0
    else
        echo -e "${RED}[✗] Not found (HTTP $response)${NC}"
        return 1
    fi
}

# Try HTTPS first, then HTTP
for protocol in "https" "http"; do
    BASE_URL="${protocol}://${DOMAIN_CLEAN}"
    
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Testing with $protocol://${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Check robots.txt
    ROBOTS_URL="${BASE_URL}/robots.txt"
    if try_url "$ROBOTS_URL" "robots.txt"; then
        echo ""
        echo -e "${GREEN}━━━ ROBOTS.TXT CONTENT ━━━${NC}"
        curl -s -L "$ROBOTS_URL" | head -50
        echo ""
        echo -e "${YELLOW}[*] Extracting interesting paths...${NC}"
        
        # Extract disallowed paths
        DISALLOWED=$(curl -s -L "$ROBOTS_URL" | grep -i "^Disallow:" | awk '{print $2}' | grep -v "^/$" | head -20)
        if [ -n "$DISALLOWED" ]; then
            echo -e "${RED}Disallowed paths (often interesting!):${NC}"
            echo "$DISALLOWED" | while read -r path; do
                echo -e "  ${RED}✗${NC} $path"
            done
        fi
        echo ""
        
        # Extract sitemap URLs from robots.txt
        SITEMAP_URLS=$(curl -s -L "$ROBOTS_URL" | grep -i "^Sitemap:" | awk '{print $2}')
        if [ -n "$SITEMAP_URLS" ]; then
            echo -e "${GREEN}Sitemaps declared in robots.txt:${NC}"
            echo "$SITEMAP_URLS" | while read -r sitemap; do
                echo -e "  ${GREEN}→${NC} $sitemap"
            done
        fi
    fi
    
    echo ""
    
    # Check common sitemap locations
    SITEMAP_LOCATIONS=(
        "/sitemap.xml"
        "/sitemap_index.xml"
        "/sitemap1.xml"
        "/sitemap-index.xml"
        "/sitemap/sitemap.xml"
        "/sitemap.php"
    )
    
    echo -e "${YELLOW}[*] Checking common sitemap locations...${NC}"
    FOUND_SITEMAP=false
    
    for sitemap_path in "${SITEMAP_LOCATIONS[@]}"; do
        SITEMAP_URL="${BASE_URL}${sitemap_path}"
        if try_url "$SITEMAP_URL" "sitemap${sitemap_path}"; then
            FOUND_SITEMAP=true
            echo ""
            echo -e "${GREEN}━━━ SITEMAP PREVIEW ━━━${NC}"
            curl -s -L "$SITEMAP_URL" | head -30
            echo ""
            echo -e "${YELLOW}[*] Counting URLs in sitemap...${NC}"
            URL_COUNT=$(curl -s -L "$SITEMAP_URL" | grep -c "<loc>" || echo "0")
            echo -e "  ${GREEN}Found $URL_COUNT URLs${NC}"
            echo ""
        fi
    done
    
    if [ "$FOUND_SITEMAP" = true ]; then
        break  # Found sitemap, no need to try HTTP if we used HTTPS
    fi
    
    # If we found robots.txt with HTTPS, don't try HTTP
    if [ "$response" = "200" ] && [ "$protocol" = "https" ]; then
        break
    fi
done

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Check complete!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}💡 Pro Tips:${NC}"
echo "  • Disallowed paths in robots.txt often hide sensitive areas"
echo "  • Check sitemap for hidden endpoints and parameter patterns"
echo "  • Look for admin, api, test, dev, backup paths"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  • Parse all discovered hosts with: python3 tools/robots_sitemap_parser.py"
echo "  • Test disallowed paths for actual access (may not be protected)"
echo "  • Extract parameters from sitemap URLs for testing"
echo ""
