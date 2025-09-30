#!/bin/bash

# ================================================
# Auto Pentest Script for Local Websites
# Tools: nmap, whatweb, nikto, gobuster, sqlmap, hydra
# Author: cyberambora dchunterops@gmail.com
# ================================================

TARGET=$1
OUTPUT_DIR="results_$TARGET"
WORDLIST_DIR="/usr/share/wordlists/dirb"
CURRENT_WORDLIST="$WORDLIST_DIR/common.txt"
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
  ["500worst"]="./500-worst-passwords.txt"
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

echo -e "${GREEN}[6] Brute-force login with Hydra...${NC}"

# --- NEW: SMART LOGIN ANALYSIS ---
# This function performs a manual login attempt and analyzes the FULL response
# to determine reliable success (S) and failure (F) patterns for Hydra.
analyze_login() {
  local test_user="invalid_user_$(date +%s)"
  local test_pass="invalid_pass_$(date +%s)"

  echo "[*] Probing login form to determine Hydra parameters..."

  RESPONSE_HEADERS=$(curl -i -s -d "username=$test_user&password=$test_pass" "$LOGIN_URL")
  
  if echo "$RESPONSE_HEADERS" | grep -q "^Location:"; then
    
    LOCATION_HEADER=$(echo "$RESPONSE_HEADERS" | grep -i "^Location:" | tr -d '\r')
    echo "[!] Login attempt resulted in a redirect: $LOCATION_HEADER"
    
    RESPONSE_BODY=$(curl -L -s -d "username=$test_user&password=$test_pass" "$LOGIN_URL")
  else
    
    RESPONSE_BODY=$(curl -s -d "username=$test_user&password=$test_pass" "$LOGIN_URL")
  fi

  LOCAL_FAIL_STRING=$(echo "$RESPONSE_BODY" | grep -i -o 'Invalid\|incorrect\|failed\|error\|login.*failed' | head -1 || echo "Invalid")
  echo "[*] Detected failure string in body: '$LOCAL_FAIL_STRING'"

  if echo "$RESPONSE_HEADERS" | grep -q "^Location:"; then
    REDIRECT_URL=$(echo "$RESPONSE_HEADERS" | grep -i "^Location:" | head -1 | awk '{print $2}' | tr -d '\r')
    echo "[*] Failed login redirects to: $REDIRECT_URL"

    echo "[*] Note: Application uses redirects. Using failure string '$LOCAL_FAIL_STRING'. Verify Hydra results manually."
    HYDRA_FAIL_CONDITION="F=$LOCAL_FAIL_STRING"

  else

    HYDRA_FAIL_CONDITION="F=$LOCAL_FAIL_STRING"
  fi

  export HYDRA_FAIL_CONDITION
}

# --- END NEW LOGIC ---

if command -v hydra &>/dev/null; then
  # Check if we have the username list
  if [[ ! -f "$USERNAME_LIST" ]]; then
    echo "[!] Username list '$USERNAME_LIST' not found. Please create it or specify the correct path."
    echo "[!] Skipping Hydra brute-force."
  else
    # Run our analysis function
    analyze_login

    echo "[*] Starting Hydra with condition: $HYDRA_FAIL_CONDITION"
    hydra -L "$USERNAME_LIST" -P "$PASSWORD_WORDLIST" -f -vV \
          "$TARGET" http-post-form "/login-submit:username=^USER^&password=^PASS^:$HYDRA_FAIL_CONDITION" \
          -o "$OUTPUT_DIR/hydra.txt"

    # --- NEW: POST-HYDRA VERIFICATION ---
    echo "[*] Hydra scan complete. Verifying top results..."
    # Extract the first found credential
    HYDRA_RESULT=$(grep -E "^\[[0-9]+\]\[http-post-form\]" "$OUTPUT_DIR/hydra.txt" | head -1)
    if [[ -n "$HYDRA_RESULT" ]]; then
        LOGIN=$(echo "$HYDRA_RESULT" | awk '{print $5}')
        PASSWORD=$(echo "$HYDRA_RESULT" | awk '{print $7}')
        echo "[!] Hydra found credentials: $LOGIN / $PASSWORD"
        echo "[*] Manually testing these credentials to prevent false positives..."

        # Perform a manual login attempt with the found credentials
        LOGIN_RESPONSE=$(curl -i -s -d "username=$LOGIN&password=$PASSWORD" "$LOGIN_URL")
        # Check for a redirect, which likely indicates success
        if echo "$LOGIN_RESPONSE" | grep -q "^Location:"; then
            REDIRECT_TARGET=$(echo "$LOGIN_RESPONSE" | grep -i "^Location:" | head -1 | awk '{print $2}' | tr -d '\r')
            echo "[+] MANUAL VERIFICATION SUCCESSFUL: Login with '$LOGIN:$PASSWORD' redirects to: $REDIRECT_TARGET"
            echo "[+] This appears to be a valid credential pair."
        else
            # Check if the failure string is present
            if echo "$LOGIN_RESPONSE" | grep -q -i "$LOCAL_FAIL_STRING"; then
                echo "[-] MANUAL VERIFICATION FAILED: Login response contains the failure string '$LOCAL_FAIL_STRING'."
                echo "[-] This is likely a FALSE POSITIVE. Please check the application logic."
                # Append a warning to the hydra output file
                echo "# WARNING: The found credential $LOGIN:$PASSWORD was manually verified and appears to be a FALSE POSITIVE." >> "$OUTPUT_DIR/hydra.txt"
            else
                echo "[?] MANUAL VERIFICATION INCONCLUSIVE: No clear redirect or failure message. Inspect the response manually."
            fi
        fi
    else
        echo "[*] Hydra did not find any valid credentials."
    fi
    # --- END VERIFICATION ---

  fi
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
