# Laughing Spoon

A simple but powerful bash script that automates the initial reconnaissance and vulnerability scanning phases of a web application penetration test against a target website.

## Features

This script chains together several popular open-source security tools to perform a comprehensive initial scan:

  * **Port Scanning:** Uses **Nmap** to discover open ports and running services.
  * **Tech Stack Identification:** Uses **WhatWeb** to identify the technologies used by the web application (CMS, frameworks, server, etc.).
  * **Vulnerability Scanning:** Uses **Nikto** to check for common web server vulnerabilities and misconfigurations.
  * **Directory Brute-Forcing:** Uses **Gobuster** to discover hidden directories and files.
  * **SQL Injection Testing:** Uses **SQLmap** to automatically crawl the site and test forms for SQL injection vulnerabilities.
  * **Login Brute-Forcing:** Uses **Hydra** to attempt to brute-force a login form.

-----

## Prerequisites

Before running the script, you need to have the necessary tools installed.

On Debian-based systems (like Ubuntu or Kali Linux), you can install them with:

```bash
sudo apt-get update && sudo apt-get install nmap whatweb nikto gobuster sqlmap hydra -y
```

The script also depends on two external reporting scripts which it calls at the end. Make sure these files are in the same directory:

  * `report_md.sh`
  * `report_html.sh`

-----

## Setup & Usage

1.  **Make the shell script executable:**

    ```bash
    chmod +x laughing_spoon.sh report_md.sh report_html.sh
    ```

2.  **Create a username list:** The script requires a file named `usernames.txt` for the Hydra brute-force attack. Create this file in the same directory and add one potential username per line.

    ```
    admin
    root
    administrator
    user
    ```

3.  **Run the scan:** Execute the script with `sudo` (required for downloading `rockyou.txt` if it's missing) and provide the target hostname as an argument.

    ```bash
    sudo ./laughing_spoon.sh target-website.com
    ```

    **Note:** Do not include `http://` or `https://` in the target hostname.

-----

## Output

All findings and log files are saved in a new directory named `results_<target-hostname>`.

Upon completion, the script generates two summary reports inside this directory:

  * `report.md`: A clean Markdown summary of the findings.
  * `report.html`: An HTML version of the report for easy viewing in a browser.

-----

## Disclaimer

This script is intended for **educational purposes and for use on authorized systems only**. Unauthorized scanning of websites is illegal. The author is not responsible for any misuse or damage caused by this script. **Always obtain explicit permission before scanning any target.**