#!/bin/bash

# ================================================
# Auto Pentest Script for Local Websites
# Tools: nmap, whatweb, nikto, gobuster, sqlmap, hydra
# Author: cyberambora dchunterops@gmail.com
# ================================================

TARGET=$1
OUTPUT_DIR="results_$TARGET"
WORDLIST="/usr/share/wordlists/dirb/common.txt"
LOGIN_URL="http://$TARGET/login-submit"
USERNAME_LIST="usernames.txt"
PASSWORD_WORDLIST="/usr/share/wordlists/rockyou.txt"

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target-hostname>"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Ensure rockyou.txt exists – fetch the fresh, uncompressed file
if [[ ! -f "$PASSWORD_WORDLIST" ]]; then
    echo "[!] rockyou.txt not found – fetching a clean copy …"
    curl -L -o /usr/share/wordlists/rockyou.txt \
         https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt
    sudo chmod 644 /usr/share/wordlists/rockyou.txt
fi

# Determine the fail-string dynamically (fallback to "Invalid")
echo "[*] Probing login form to detect failure string …"
FAIL_STRING=$(curl -s -d "username=wrong&password=wrong" "$LOGIN_URL" | \
              grep -i -o 'Invalid\|incorrect\|failed\|error' | head -1 || echo "Invalid")
              
echo -e "${GREEN}[1] Scanning with nmap...${NC}"
nmap -sS -sV -p- -oN "$OUTPUT_DIR/nmap.txt" "$TARGET"

echo -e "${GREEN}[2] Fingerprinting with WhatWeb...${NC}"
whatweb -v "http://$TARGET" > "$OUTPUT_DIR/whatweb.txt"

echo -e "${GREEN}[3] Vulnerability scanning with Nikto...${NC}"
nikto -h "http://$TARGET" -output "$OUTPUT_DIR/nikto.txt"

echo -e "${GREEN}[4] Directory brute-forcing with Gobuster...${NC}"
if command -v gobuster &>/dev/null; then
  WORDLIST="${WORDLIST:-/usr/share/wordlists/dirb/common.txt}"
  
  if [[ ! -f "$WORDLIST" ]]; then
    echo "[!] Wordlist not found at: $WORDLIST"
    echo "[!] Skipping Gobuster scan."
  elif [[ -f "$OUTPUT_DIR/gobuster.txt" ]]; then
    echo "[*] Gobuster output already exists. Skipping..."
  else
    gobuster dir -u "http://$TARGET" -w "$WORDLIST" -o "$OUTPUT_DIR/gobuster.txt"
  fi
else
  echo "[!] Gobuster not found. Skipping directory brute-force."
fi

echo -e "${GREEN}[5] SQLi testing with sqlmap...${NC}"
sqlmap -u "$LOGIN_URL" --batch --forms --crawl=1 --output-dir="$OUTPUT_DIR/sqlmap" --risk=3 --level=5 --random-agent

echo -e "${GREEN}[6] Brute-force login with Hydra...${NC}"
if command -v hydra &>/dev/null; then
  hydra -L "$USERNAME_LIST" -P "$PASSWORD_WORDLIST" -f -V \
        "$TARGET" http-post-form "/login-submit:username=^USER^&password=^PASS^:F=$FAIL_STRING" \
        -o "$OUTPUT_DIR/hydra.txt"
else
  echo "[!] Hydra not found. Skipping brute-force login."
fi

# ==================================================
# 7. Final Results
# ==================================================

RESULTS_DIR=$OUTPUT_DIR
echo -e "${GREEN}[*] Generating structured Markdown findings...${NC}"

# Generate report
./report.sh "$TARGET" "$RESULTS_DIR"

echo -e "${GREEN}[*] All tasks completed. Report is located in $OUTPUT_DIR/report.md${NC}"

./report_html.sh "$TARGET" "$RESULTS_DIR"

echo -e "${GREEN}[*] HTML report generated at $RESULTS_DIR/report.html${NC}"

# (This is just a blank line)
