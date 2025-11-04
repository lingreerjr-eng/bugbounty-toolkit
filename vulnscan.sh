#!/usr/bin/env bash
# vuln_scan.sh - Integrated vulnerability scanning workflow
# Usage: ./vuln_scan.sh <target.com>

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: ./vuln_scan.sh <target.com>"
    echo ""
    echo "This script will:"
    echo "  1. Extract URLs with parameters"
    echo "  2. Run SQL injection detection (ethical/non-exploitative)"
    echo "  3. Generate vulnerability report"
    exit 1
fi

TARGET=$1
OUTDIR="output/$TARGET"
TOOLS_DIR="tools"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "=================================================="
echo "  Vulnerability Scanner - Target: $TARGET"
echo "=================================================="
echo -e "${NC}"

# Check if recon has been run
if [ ! -d "$OUTDIR" ]; then
    echo -e "${RED}[!] Recon output not found for $TARGET${NC}"
    echo -e "${YELLOW}[*] Run recon first: ./recon_async.py $TARGET${NC}"
    exit 1
fi

# Phase 1: Extract parameterized URLs
echo -e "${YELLOW}[Phase 1] Extracting URLs with parameters${NC}"
echo "------------------------------------------------------"
python3 "$TOOLS_DIR/param_extractor.py" "$OUTDIR" "$TARGET"

# Check if we found any parameterized URLs
if [ ! -f "$OUTDIR/urls_with_params.txt" ]; then
    echo -e "${RED}[!] No parameterized URLs found${NC}"
    exit 1
fi

PARAM_COUNT=$(wc -l < "$OUTDIR/urls_with_params.txt" || echo "0")
INTERESTING_COUNT=0
if [ -f "$OUTDIR/urls_interesting_params.txt" ]; then
    INTERESTING_COUNT=$(wc -l < "$OUTDIR/urls_interesting_params.txt" || echo "0")
fi

echo -e "${GREEN}[+] Found $PARAM_COUNT URLs with parameters${NC}"
echo -e "${GREEN}[+] Found $INTERESTING_COUNT URLs with interesting parameters${NC}"

# Phase 2: SQL Injection Detection
echo ""
echo -e "${YELLOW}[Phase 2] SQL Injection Detection${NC}"
echo "------------------------------------------------------"
echo -e "${BLUE}[*] Testing interesting parameters first...${NC}"

SQLI_DIR="$OUTDIR/sqli"
mkdir -p "$SQLI_DIR"

if [ -f "$OUTDIR/urls_interesting_params.txt" ] && [ "$INTERESTING_COUNT" -gt 0 ]; then
    python3 "$TOOLS_DIR/sqli_detector.py" "$OUTDIR/urls_interesting_params.txt" "$SQLI_DIR/interesting"
else
    echo -e "${YELLOW}[!] No interesting parameters to test${NC}"
fi

# Ask if user wants to test all URLs (can take a while)
echo ""
if [ "$PARAM_COUNT" -gt "$INTERESTING_COUNT" ]; then
    REMAINING=$((PARAM_COUNT - INTERESTING_COUNT))
    echo -e "${YELLOW}[?] Test remaining $REMAINING URLs? This may take a while. (y/n)${NC}"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${BLUE}[*] Testing all parameterized URLs...${NC}"
        python3 "$TOOLS_DIR/sqli_detector.py" "$OUTDIR/urls_with_params.txt" "$SQLI_DIR/all"
    fi
fi

# Phase 3: Report Generation
echo ""
echo -e "${YELLOW}[Phase 3] Report Summary${NC}"
echo "------------------------------------------------------"

# Count findings
FINDING_COUNT=0
if [ -f "$SQLI_DIR/interesting/sqli_findings.json" ]; then
    INTERESTING_FINDINGS=$(python3 -c "import json; print(len(json.load(open('$SQLI_DIR/interesting/sqli_findings.json'))))" 2>/dev/null || echo "0")
    FINDING_COUNT=$((FINDING_COUNT + INTERESTING_FINDINGS))
    echo -e "${GREEN}[+] Interesting parameters: $INTERESTING_FINDINGS potential vulnerabilities${NC}"
fi

if [ -f "$SQLI_DIR/all/sqli_findings.json" ]; then
    ALL_FINDINGS=$(python3 -c "import json; print(len(json.load(open('$SQLI_DIR/all/sqli_findings.json'))))" 2>/dev/null || echo "0")
    FINDING_COUNT=$((FINDING_COUNT + ALL_FINDINGS))
    echo -e "${GREEN}[+] All parameters: $ALL_FINDINGS potential vulnerabilities${NC}"
fi

echo ""
if [ "$FINDING_COUNT" -gt 0 ]; then
    echo -e "${RED}[!] VULNERABILITIES DETECTED: $FINDING_COUNT potential SQL injection points${NC}"
    echo ""
    echo -e "${YELLOW}IMPORTANT:${NC}"
    echo "  - These are DETECTION results only"
    echo "  - Do NOT attempt to exploit these vulnerabilities"
    echo "  - Report findings through the bug bounty program"
    echo ""
    echo -e "${BLUE}Reports available at:${NC}"
    if [ -f "$SQLI_DIR/interesting/sqli_findings.txt" ]; then
        echo "  - $SQLI_DIR/interesting/sqli_findings.txt"
    fi
    if [ -f "$SQLI_DIR/all/sqli_findings.txt" ]; then
        echo "  - $SQLI_DIR/all/sqli_findings.txt"
    fi
else
    echo -e "${GREEN}[+] No SQL injection vulnerabilities detected${NC}"
fi

# Generate combined report
echo ""
echo -e "${YELLOW}[*] Generating combined report...${NC}"
COMBINED_REPORT="$OUTDIR/vulnerability_report.txt"

cat > "$COMBINED_REPORT" << EOF
================================================================================
                    VULNERABILITY SCAN REPORT
================================================================================

Target: $TARGET
Date: $(date)
Scan Type: SQL Injection Detection (Ethical/Non-Exploitative)

================================================================================
                              SUMMARY
================================================================================

Total URLs Scanned: $PARAM_COUNT
URLs with Interesting Parameters: $INTERESTING_COUNT
Potential Vulnerabilities Found: $FINDING_COUNT

================================================================================
                           IMPORTANT NOTICE
================================================================================

This report contains DETECTION results only. These findings have NOT been
exploited. All testing was performed ethically within bug bounty guidelines.

DO NOT:
  ❌ Attempt to exploit these vulnerabilities
  ❌ Extract or access unauthorized data
  ❌ Perform destructive operations

DO:
  ✓ Report findings through proper bug bounty channels
  ✓ Provide this report as proof of concept
  ✓ Wait for remediation before retesting

================================================================================
                            DETAILED FINDINGS
================================================================================

EOF

# Append detailed findings if they exist
if [ -f "$SQLI_DIR/interesting/sqli_findings.txt" ]; then
    echo "--- Interesting Parameters ---" >> "$COMBINED_REPORT"
    cat "$SQLI_DIR/interesting/sqli_findings.txt" >> "$COMBINED_REPORT"
    echo "" >> "$COMBINED_REPORT"
fi

if [ -f "$SQLI_DIR/all/sqli_findings.txt" ]; then
    echo "--- All Parameters ---" >> "$COMBINED_REPORT"
    cat "$SQLI_DIR/all/sqli_findings.txt" >> "$COMBINED_REPORT"
fi

echo -e "${GREEN}[+] Combined report saved: $COMBINED_REPORT${NC}"

# Summary
echo ""
echo -e "${BLUE}=================================================="
echo "  Vulnerability Scan Complete"
echo "==================================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Review the reports in $SQLI_DIR/"
echo "  2. Verify findings manually (ethical testing only)"
echo "  3. Submit bug bounty report with evidence"
echo "  4. Document: URL, parameter, payload, evidence"
echo ""
