#!/bin/bash

# ================================================
# Report Generator for Auto Pentest Script
# Converts scan output into a structured Markdown report
# ================================================

TARGET=$1
RESULTS_DIR=$2
REPORT_FILE="$RESULTS_DIR/report.md"

if [[ -z "$TARGET" || -z "$RESULTS_DIR" ]]; then
  echo "Usage: $0 <target-hostname> <results-dir>"
  exit 1
fi

# Create/overwrite report file
echo "# Penetration Test Report: $TARGET" > "$REPORT_FILE"
echo "_Generated on $(date)_\n" >> "$REPORT_FILE"

# Nmap
if [[ -f "$RESULTS_DIR/nmap.txt" ]]; then
  echo "## 1. Network Scan (Nmap)" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  cat "$RESULTS_DIR/nmap.txt" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo >> "$REPORT_FILE"
fi

# WhatWeb
if [[ -f "$RESULTS_DIR/whatweb.txt" ]]; then
  echo "## 2. Web Fingerprinting (WhatWeb)" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  cat "$RESULTS_DIR/whatweb.txt" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo >> "$REPORT_FILE"
fi

# Nikto
if [[ -f "$RESULTS_DIR/nikto.txt" ]]; then
  echo "## 3. Vulnerability Scan (Nikto)" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  cat "$RESULTS_DIR/nikto.txt" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo >> "$REPORT_FILE"
fi

# Gobuster
if [[ -f "$RESULTS_DIR/gobuster.txt" ]]; then
  echo "## 4. Directory Brute-force (Gobuster)" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  cat "$RESULTS_DIR/gobuster.txt" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo >> "$REPORT_FILE"
fi

# Hydra
if [[ -f "$RESULTS_DIR/hydra.txt" ]]; then
  echo "## 5. Login Brute-force (Hydra)" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  cat "$RESULTS_DIR/hydra.txt" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo >> "$REPORT_FILE"
fi

# SQLMap
SQLMAP_DIR="$RESULTS_DIR/sqlmap"
if [[ -d "$SQLMAP_DIR" ]]; then
  echo "## 6. SQL Injection Testing (sqlmap)" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  for f in "$SQLMAP_DIR"/*/log; do
    if [[ -f "$f" ]]; then
      echo "### $(basename "$(dirname "$f")")" >> "$REPORT_FILE"
      cat "$f" >> "$REPORT_FILE"
      echo >> "$REPORT_FILE"
    fi
  done
  echo '```' >> "$REPORT_FILE"
  echo >> "$REPORT_FILE"
fi

# Final Note
echo "## 7. Recommendations & Patching" >> "$REPORT_FILE"
echo "- Review each section above for identified vulnerabilities." >> "$REPORT_FILE"
echo "- Apply patches for outdated software or misconfigurations." >> "$REPORT_FILE"
echo "- Harden access to exposed services (e.g., login endpoints, open ports)." >> "$REPORT_FILE"
echo "- Re-run this test after patching to verify." >> "$REPORT_FILE"

echo "[✓] Markdown report generated: $REPORT_FILE"
