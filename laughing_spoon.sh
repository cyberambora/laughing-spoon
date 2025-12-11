#!/bin/bash

# ================================================
# Auto Pentest Script for Local Websites (POC v2.0)
# Emulates the iterative, human-guided workflow from the POC diagram.
# Tools: nmap, whatweb, nikto, gobuster, sqlmap, hydra
# Author: cyberambora https://github.com/cyberambora/  
# Licence: MIT 
# Version: 2.0
# ================================================

TARGET=$1
LOGIN_URI=${2:-/login-submit} # Default login URI if not provided
OUTPUT_DIR="results_$TARGET"
WORDLIST_DIR="/usr/share/wordlists/"
LOGIN_URL="http://$TARGET$LOGIN_URI"
USERNAME_LIST="usernames.txt"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Load target context if available
load_target_context() {
  local context_file="target_context.json"
  if [[ -f "$context_file" ]]; then
    echo "[*] Loading target context from $context_file"
    FRAMEWORK=$(jq -r '.framework' "$context_file" 2>/dev/null)
    if [[ $? -eq 0 && -n "$FRAMEWORK" ]]; then
      echo "[*] Target identified as: $FRAMEWORK"
    else
      echo "[!] Could not parse framework from context file."
    fi
  else
    echo "[*] No target context file found. Proceeding without context-aware filtering."
  fi
}

# Call it after setting up variables
load_target_context

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target-hostname> [<login-uri>]"
  echo "Example: $0 example.com /login"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# ==================================================
# Wordlist Management & Dynamic Adaptation
# ==================================================
declare -A WORDLISTS=(
  ["rockyou"]="$WORDLIST_DIR/rockyou.txt"
  ["500worst"]="./500-worst-passwords.txt"
  ["john"]="/usr/share/john/password.lst"
  ["common"]="$WORDLIST_DIR/dirb/common.txt"
)

# Ask user which wordlist to use
echo "Choose password wordlist: rockyou | 500worst | john | common"
read -p "Enter choice: " WL_CHOICE

if [[ -z "${WORDLISTS[$WL_CHOICE]}" || ! -f "${WORDLISTS[$WL_CHOICE]}" ]]; then
  echo "[!] Wordlist '$WL_CHOICE' not found or is not a file. Available options:"
  for key in "${!WORDLISTS[@]}"; do
    echo "  - $key (${WORDLISTS[$key]})"
  done
  exit 1
fi

PASSWORD_WORDLIST="${WORDLISTS[$WL_CHOICE]}"
echo "[*] Using wordlist: $PASSWORD_WORDLIST"

# Ensure rockyou.txt exists – fetch if missing
if [[ "$WL_CHOICE" == "rockyou" && ! -f "$WORDLIST_DIR/rockyou.txt" ]]; then
    echo "[!] rockyou.txt not found – fetching a clean copy …"
    curl -L -o "$WORDLIST_DIR/rockyou.txt" \
         https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt  
    sudo chmod 644 "$WORDLIST_DIR/rockyou.txt"
fi

# ==================================================
# PHASE 1: Initial Recon & Human Operator Input
# ==================================================
echo -e "${GREEN}[*] PHASE 1: Initial Recon - Human operator provides target.${NC}"
echo "[*] Target set to: $TARGET"
echo "[*] Starting initial scan to gather baseline data..."

# Initial Nmap Scan (Phase 2 equivalent)
echo -e "${GREEN}[1] Scanning with nmap...${NC}"
nmap -sS -sV -p- -oN "$OUTPUT_DIR/nmap.txt" "$TARGET"

# WhatWeb Fingerprinting
echo -e "${GREEN}[2] Fingerprinting with WhatWeb...${NC}"
whatweb -v "http://$TARGET" > "$OUTPUT_DIR/whatweb.txt"

# Nikto Vulnerability Scan
echo -e "${GREEN}[3] Vulnerability scanning with Nikto...${NC}"
nikto -h "http://$TARGET" -output "$OUTPUT_DIR/nikto.txt"

# ==================================================
# PHASE 2: Data Analysis & Human Review (The Core Loop)
# ==================================================
echo -e "${GREEN}[*] PHASE 2: Findings recorded and analyzed. Human reviews summary.${NC}"

# Generate a quick summary for the human operator
echo "=== INITIAL FINDINGS SUMMARY ===" > "$OUTPUT_DIR/phase2_summary.txt"
echo "Target: $TARGET" >> "$OUTPUT_DIR/phase2_summary.txt"
echo "" >> "$OUTPUT_DIR/phase2_summary.txt"

echo "Nmap Top Ports:" >> "$OUTPUT_DIR/phase2_summary.txt"
grep -E "^(open|filtered)" "$OUTPUT_DIR/nmap.txt" | head -10 >> "$OUTPUT_DIR/phase2_summary.txt"
echo "" >> "$OUTPUT_DIR/phase2_summary.txt"

echo "WhatWeb Technologies:" >> "$OUTPUT_DIR/phase2_summary.txt"
grep -E "^(CMS|Framework|Server|X-Powered-By)" "$OUTPUT_DIR/whatweb.txt" | head -5 >> "$OUTPUT_DIR/phase2_summary.txt"
echo "" >> "$OUTPUT_DIR/phase2_summary.txt"

# Inside the PHASE 2 summary generation...
echo "Nikto Critical Issues (POTENTIAL FALSE POSITIVES):" >> "$OUTPUT_DIR/phase2_summary.txt"

NIKTO_CRITICAL=$(grep -i -E "(critical|high|error)" "$OUTPUT_DIR/nikto.txt" | head -5)

if [[ -n "$NIKTO_CRITICAL" ]]; then
    echo "$NIKTO_CRITICAL" >> "$OUTPUT_DIR/phase2_summary.txt"
    
    # Check for common framework misidentifications
    if echo "$NIKTO_CRITICAL" | grep -q -i "xoops"; then
        echo "[!] WARNING: Nikto detected 'Xoops' related issues. Since your target is '$FRAMEWORK', this is likely a FALSE POSITIVE." >> "$OUTPUT_DIR/phase2_summary.txt"
        echo "    Please verify manually by checking the source code or page structure." >> "$OUTPUT_DIR/phase2_summary.txt"
    fi
    
    if echo "$NIKTO_CRITICAL" | grep -q -i "wordpress"; then
        echo "[!] WARNING: Nikto detected 'WordPress' related issues. Since your target is '$FRAMEWORK', this is likely a FALSE POSITIVE." >> "$OUTPUT_DIR/phase2_summary.txt"
        echo "    Please verify manually by checking the source code or page structure." >> "$OUTPUT_DIR/phase2_summary.txt"
    fi

else
    echo "No critical issues found by Nikto." >> "$OUTPUT_DIR/phase2_summary.txt"
fi

# ==================================================
# PHASE 3: Iterative Vulnerability Scan Based on Findings
# ==================================================
echo -e "${GREEN}[*] PHASE 3: Directs an iterative vulnerability scan based on findings.${NC}"

# Determine next steps based on initial findings
echo "[*] Analyzing findings to direct next phase..."

# Check for web server and potential directories
WEB_SERVER=$(grep -E "Server:|Apache|Nginx|IIS" "$OUTPUT_DIR/whatweb.txt" | head -1)
if [[ -n "$WEB_SERVER" ]]; then
  echo "[*] Web server detected: $WEB_SERVER"
  # Run Gobuster only if we have a wordlist and it's not already run
  if command -v gobuster &>/dev/null; then
    if [[ ! -f "$PASSWORD_WORDLIST" ]]; then
      echo "[!] Wordlist not found at: $PASSWORD_WORDLIST"
      echo "[!] Skipping Gobuster scan."
    elif [[ -f "$OUTPUT_DIR/gobuster.txt" ]]; then
      echo "[*] Gobuster output already exists. Skipping..."
    else
      echo -e "${GREEN}[4] Directory brute-forcing with Gobuster...${NC}"
      gobuster dir -u "http://$TARGET" -w "$PASSWORD_WORDLIST" -o "$OUTPUT_DIR/gobuster.txt"
    fi
  else
    echo "[!] Gobuster not found. Skipping directory brute-force."
  fi
fi

# Check for SQL injection potential
SQL_INJECTION_HINTS=$(grep -i -E "(sql|database|query|error)" "$OUTPUT_DIR/nikto.txt" | wc -l)
if [[ $SQL_INJECTION_HINTS -gt 0 ]]; then
  echo "[*] Potential SQL injection hints found ($SQL_INJECTION_HINTS). Running sqlmap..."
  echo -e "${GREEN}[5] SQLi testing with sqlmap...${NC}"
  sqlmap -u "$LOGIN_URL" --batch --forms --crawl=1 --output-dir="$OUTPUT_DIR/sqlmap" --risk=3 --level=5 --random-agent
else
  echo "[*] No strong SQL injection hints found. Skipping sqlmap for now."
fi

# ==================================================
# PHASE 4 & 5: Exploitation, Validation, and Data Exfiltration
# ==================================================
echo -e "${GREEN}[*] PHASES 4 & 5: Internal recon, obtains credentials, accesses data, attempts exploits, validates callbacks.${NC}"

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

  FAIL_STRING=$(echo "$RESPONSE_BODY" | grep -i -o 'Invalid\|incorrect\|failed\|error\|login.*failed' | head -1 || echo "Invalid")
  echo "[*] Detected failure string in body: '$FAIL_STRING'"

  if echo "$RESPONSE_HEADERS" | grep -q "^Location:"; then
    REDIRECT_URL=$(echo "$RESPONSE_HEADERS" | grep -i "^Location:" | head -1 | awk '{print $2}' | tr -d '\r')
    echo "[*] Failed login redirects to: $REDIRECT_URL"

    echo "[*] Note: Application uses redirects. Using failure string '$FAIL_STRING'. Verify Hydra results manually."
    HYDRA_FAIL_CONDITION="F=$FAIL_STRING"

  else

    HYDRA_FAIL_CONDITION="F=$FAIL_STRING"
  fi

  export HYDRA_FAIL_CONDITION
  export FAIL_STRING
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
          "$TARGET" "http-post-form:$LOGIN_URI:username=^USER^&password=^PASS^:$HYDRA_FAIL_CONDITION" \
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
            
            # If successful, add this to a new file for further exploitation
            echo "$LOGIN:$PASSWORD" > "$OUTPUT_DIR/valid_credentials.txt"
            
        else
            # Check if the failure string is present
            if echo "$LOGIN_RESPONSE" | grep -q -i "$FAIL_STRING"; then
                echo "[-] MANUAL VERIFICATION FAILED: Login response contains the failure string '$FAIL_STRING'."
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
# Final Results & Human Review Loop
# ==================================================
RESULTS_DIR=$OUTPUT_DIR
echo -e "${GREEN}[*] Generating structured Markdown findings...${NC}"

./report.sh "$TARGET" "$RESULTS_DIR"

echo -e "${GREEN}[*] All tasks completed. Report is located in $OUTPUT_DIR/report.md${NC}"

./report_html.sh "$TARGET" "$RESULTS_DIR"

echo -e "${GREEN}[*] HTML report generated at $RESULTS_DIR/report.html${NC}"

echo -e "${YELLOW}[*] PHASE 5 COMPLETE: Human operator should now review the final report and decide on further action.${NC}"
echo "Review the report at $OUTPUT_DIR/report.html"
echo "If more exploitation is needed, re-run this script with additional parameters or use the discovered credentials for manual testing."

# Optional: Add a loop for continuous improvement based on human feedback
echo ""
echo "Would you like to initiate another round of scanning based on new findings? (y/N)"
read -p "Enter choice: " CONTINUE
if [[ "$CONTINUE" =~ ^[Yy]$ ]]; then
  echo "[*] Initiating another round of scanning..."
  # Here you could implement logic to adjust the scan based on previous results
  # For example, if sqlmap found a vulnerable parameter, you could run a more targeted scan
  # This is where the true "iterative" nature of the POC would come into play.
  echo "[*] This feature is currently a placeholder. In a real implementation, you would parse the report and adjust the scan accordingly."
fi

echo -e "${GREEN}[*] Pentest session ended. Thank you for using Auto Pentest Script v2.0${NC}"