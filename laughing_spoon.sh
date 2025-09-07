#!/bin/bash

# ================================================
# Auto Pentest Script for Local Websites
# Tools: nmap, whatweb, nikto, gobuster, sqlmap, hydra
# Author: cyberambora dchunterops@gmail.com
# ================================================

TARGET=$1
OUTPUT_DIR="results_$TARGET"
WORDLIST_DIR="/usr/share/wordlists"
CURRENT_WORDLIST="$WORDLIST_DIR/wordlist-current.txt"
LOGIN_URL="http://$TARGET/login-submit"
USERNAME_LIST="usernames.txt"

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target-hostname>"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# ==================================================
# Wordlist Management
# ==================================================
declare -A WORDLISTS=(
  ["rockyou"]="$WORDLIST_DIR/rockyou.txt"
  ["500worst"]="500-worst-passwords.txt"
  ["john"]="/usr/share/john/password.lst"
  ["common"]="$WORDLIST_DIR/dirb/common.txt"
)

switch_wordlist() {
  local choice=$1
  if [[ -n "${WORDLISTS[$choice]}" && -f "${WORDLISTS[$choice]}" ]]; then
    ln -sf "${WORDLISTS[$choice]}" "$CURRENT_WORDLIST"
    echo "[*] Switched current wordlist → $choice (${WORDLISTS[$choice]})"
  else
    echo "[!] Wordlist \"$choice\" not found or missing. Available options:"
    for key in "${!WORDLISTS[@]}"; do
      echo "  - $key"
    done
    exit 1
  fi
}

# Ask user which wordlist to use
echo "Choose password wordlist: rockyou | 500worst | john | common"
read -p "Enter choice: " WL_CHOICE
switch_wordlist "$WL_CHOICE"

PASSWORD_WORDLIST="$CURRENT_WORDLIST"

# Ensure rockyou.txt exists – fetch if missing
if [[ "$WL_CHOICE" == "rockyou" && ! -f "$WORDLIST_DIR/rockyou.txt" ]]; then
    echo "[!] rockyou.txt not found – fetching a clean copy …"
    curl -L -o "$WORDLIST_DIR/rockyou.txt" \
         https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt
    sudo chmod 644 "$WORDLIST_DIR/rockyou.txt"
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
  if [[ ! -f "$PASSWORD_WORDLIST" ]]; then
    echo "[!] Wordlist not found at: $PASSWORD_WORDLIST"
    echo "[!] Skipping Gobuster scan."
  elif [[ -f "$OUTPUT_DIR/gobuster.txt" ]]; then
    echo "[*] Gobuster output already exists. Skipping..."
  else
    gobuster dir -u "http://$TARGET" -w "$PASSWORD_WORDLIST" -o "$OUTPUT_DIR/gobuster.txt"
  fi
else
  echo "[!] Gobuster not found. Skipping directory brute-force."
fi

echo -e "${GREEN}[5] SQLi testing with sqlmap...${NC}"
sqlmap -u "$LOGIN_URL" --batch --forms --crawl=1 --output-dir="$OUTPUT_DIR/sqlmap" --risk=3 --level=5 --random-agent

echo -e "${GREEN}[6] Brute-force login with Hydra...${NC}"
if command -v hydra &>/dev/null; then
  hydra -L "$USERNAME_LIST" -P "$PASSWORD_WORDLIST" -f -vV \
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

./report.sh "$TARGET" "$RESULTS_DIR"

echo -e "${GREEN}[*] All tasks completed. Report is located in $OUTPUT_DIR/report.md${NC}"

./report_html.sh "$TARGET" "$RESULTS_DIR"

echo -e "${GREEN}[*] HTML report generated at $RESULTS_DIR/report.html${NC}"
