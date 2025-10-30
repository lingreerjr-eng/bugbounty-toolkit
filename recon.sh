#!/usr/bin/env bash
set -euo pipefail

TARGET=$1
OUTDIR=output/$TARGET
mkdir -p "$OUTDIR"

echo "[*] Recon for $TARGET -> $OUTDIR"

# 1) Passive subdomain enumeration: crt.sh + subfinder (if available)
echo "[*] crt.sh passive enum..."
python3 tools/crtsh_enum.py "$TARGET" > "$OUTDIR/subdomains_crtsh.txt" || true

if command -v subfinder >/dev/null 2>&1; then
  echo "[*] running subfinder..."
  subfinder -d "$TARGET" -o "$OUTDIR/subfinder.txt" || true
fi

# merge uniques
cat "$OUTDIR/"*_subdomains*.txt "$OUTDIR/subfinder.txt" "$OUTDIR/subdomains_crtsh.txt" 2>/dev/null \
  | sort -u > "$OUTDIR/subdomains.txt" || true

# 2) probe for alive HTTP(S) hosts (httpx preferred)
if command -v httpx >/dev/null 2>&1; then
  echo "[*] probing with httpx..."
  cat "$OUTDIR/subdomains.txt" | httpx -silent -status-code -title -o "$OUTDIR/alive.txt" || true
else
  echo "[!] httpx not found — try 'pip install httpx' or install projectdiscovery/httpx"
fi

# 3) gather js & endpoints using wayback/gau + custom tool
echo "[*] enumerating historical URLs (wayback/gau) and js files..."
python3 tools/wayback_agg.py "$TARGET" "$OUTDIR/wayback_urls.txt" "$OUTDIR/js_files.txt" || true

# 4) extract endpoints and parameters from JS
echo "[*] extracting endpoints from JS files..."
python3 tools/js_endpoints.py "$OUTDIR/js_files.txt" "$OUTDIR/js_endpoints.txt" || true

# 5) quick vulnerability scan templates (nuclei) if installed
if command -v nuclei >/dev/null 2>&1; then
  echo "[*] running nuclei quick scan..."
  cat "$OUTDIR/alive.txt" | awk '{print $1}' | nuclei -silent -o "$OUTDIR/nuclei.txt" || true
fi

echo "[*] Done. Outputs in $OUTDIR"
