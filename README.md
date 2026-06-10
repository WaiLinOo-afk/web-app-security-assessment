# Web Application Security Assessment

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Purpose](https://img.shields.io/badge/purpose-educational-orange.svg)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-red.svg)

A hands-on penetration testing lab against two intentionally vulnerable web applications — **DVWA** and **OWASP Juice Shop** — covering all OWASP Top 10 (2021) vulnerability categories. Built as a personal project to develop practical web security assessment skills from recon through to documentation.

> ⚠️ **Ethical Disclaimer:** This project was conducted entirely in an isolated local lab environment using applications that are *deliberately designed* to be vulnerable, for the explicit purpose of security education. All techniques shown here must only be used on systems you own or have explicit written authorisation to test. Unauthorised testing is illegal under laws such as the Computer Fraud and Abuse Act (CFAA) and the Computer Misuse Act (CMA).

---

## Table of Contents

- [Overview](#overview)
- [Environment](#environment)
- [Lab Setup](#lab-setup)
- [Vulnerabilities Found](#vulnerabilities-found)
- [Notable Findings](#notable-findings)
- [Custom Fuzzer](#custom-fuzzer)
- [Repo Structure](#repo-structure)
- [Reflections](#reflections)

---

## Overview

This assessment systematically tested each OWASP Top 10 category across both targets using a combination of manual techniques (Burp Suite, browser DevTools) and automated tooling (SQLmap, Nikto, OWASP ZAP). I also wrote a custom Python fuzzer to automate payload delivery across the four main injection endpoints.

The focus was on building a complete testing workflow — not just running scanners and recording output, but understanding each vulnerability, reproducing it reliably, and documenting it in a way that would be useful to a developer trying to fix it.

**Tools:** Burp Suite Community, OWASP ZAP, SQLmap, Nikto, Python 3  
**Targets:** DVWA, OWASP Juice Shop (both running locally via Docker)  
**Methodology:** [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/)

---

## Environment

| Component | Details |
|-----------|---------|
| DVWA | `vulnerables/web-dvwa` (latest) |
| OWASP Juice Shop | `bkimminich/juice-shop` (latest) |
| Burp Suite | Community Edition |
| SQLmap | Latest |
| Python | 3.8+ |
| Docker | Required to run both targets |
| OS | Any (tested on Ubuntu 22.04) |

---

## Lab Setup

```bash
# Pull and run DVWA
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# Pull and run OWASP Juice Shop
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
```

**DVWA:** Go to `http://localhost` → click **Setup / Reset Database** → log in with `admin / password` → set Security Level to **Low** under DVWA Security.

**Juice Shop:** Go to `http://localhost:3000` — no setup needed.

For Burp Suite proxy configuration, see [`configs/burp-setup.md`](configs/burp-setup.md).

---

## Vulnerabilities Found

16 vulnerabilities identified across both targets, spanning 8 of 10 OWASP Top 10 (2021) categories.

| # | Vulnerability | Target | Severity | OWASP 2021 Category |
|---|--------------|--------|----------|---------------------|
| 1 | SQL Injection (UNION-based) | DVWA | **Critical** | [A03 Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| 2 | SQL Injection (login bypass) | Juice Shop | **Critical** | [A07 Identification & Auth Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| 3 | Command Injection (RCE) | DVWA | **Critical** | [A03 Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| 4 | Stored XSS | DVWA | **High** | [A03 Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| 5 | Local File Inclusion (LFI) | DVWA | **High** | [A03 Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| 6 | IDOR — Basket API | Juice Shop | **High** | [A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| 7 | Admin panel exposed without authentication | Juice Shop | **High** | [A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| 8 | Passwords stored as unsalted MD5 | DVWA | **High** | [A02 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| 9 | Reflected XSS | DVWA | Medium | [A03 Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| 10 | DOM-based XSS | DVWA | Medium | [A03 Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| 11 | No rate limiting on login endpoint | Juice Shop | Medium | [A07 Identification & Auth Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| 12 | Verbose SQL error messages in responses | DVWA | Medium | [A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| 13 | Default credentials accepted | DVWA | Medium | [A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| 14 | Missing CSRF tokens on state-changing requests | DVWA | Medium | [A08 Software & Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) |
| 15 | No logging on failed login attempts | Juice Shop | Low | [A09 Security Logging & Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) |
| 16 | Server version disclosed in response headers | DVWA | Low | [A06 Vulnerable & Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) |

---

## Notable Findings

**SQL Injection → Credential Dump (DVWA)**  
No input sanitisation on the SQLi endpoint whatsoever. Used `' OR 1=1-- -` to enumerate all users, then chained UNION SELECT to extract the database name and all password hashes. The hashes turned out to be unsalted MD5 — crackable offline in seconds. Confirmed and replicated with SQLmap.

**SQLi Login Bypass (Juice Shop)**  
The login form passed the email field directly into a SQL query. Entering `' OR 1=1-- -` as the email (any password) authenticated as the admin account. This is a clean example of A03 and A07 chaining in a single request — you bypass both the query logic and the authentication gate at once.

**Command Injection / RCE (DVWA)**  
The ping utility appended user input directly to a shell command with no sanitisation. `127.0.0.1; id` returned `uid=33(www-data)`, confirming unauthenticated remote code execution. Escalated to reading `/etc/passwd` with `; cat /etc/passwd`.

**Local File Inclusion (DVWA)**  
The `page=` parameter included files from the local filesystem with no path validation or allowlisting. `?page=../../../../../../etc/passwd` read arbitrary system files in the browser. `allow_url_include` was disabled in `php.ini` so RFI wasn't possible, but LFI alone is enough to read sensitive config files and source code.

---

## Custom Fuzzer

`scripts/fuzzer.py` automates SQLi, XSS, command injection, and LFI payload delivery across DVWA's four main vulnerable endpoints. It was written to reduce repetitive manual testing and to better understand what tools like SQLmap are doing under the hood.

### Prerequisites

```bash
pip install -r scripts/requirements.txt
```

### Usage

```bash
# 1. Start DVWA
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# 2. Log in at http://localhost, run Setup, set Security Level to Low

# 3. Copy your PHPSESSID from DevTools → Application → Cookies

# 4. Paste it into SESSION_COOKIE in fuzzer.py

# 5. Run the fuzzer
python3 scripts/fuzzer.py
```

Results are saved to `fuzzer_results.txt` in the project root.

---

## Repo Structure

```
web-app-security-assessment/
├── README.md
├── .gitignore
├── scripts/
│   ├── fuzzer.py                       ← custom payload fuzzer (SQLi, XSS, CMDi, LFI)
│   └── requirements.txt
├── configs/
│   └── burp-setup.md                   ← Burp Suite proxy setup notes
├── notes/
│   └── raw-testing-notes.md            ← working notes from each test session
├── report/                             ← (WIP) formal findings report
└── screenshots/                        ← evidence (Burp captures, browser screenshots)
```

---

## Reflections

- Manual testing with Burp Suite is significantly more valuable than running automated scanners alone — you develop an intuition for what's happening and why, rather than just interpreting output
- OWASP Top 10 categories aren't isolated: the SQLi login bypass simultaneously triggered A03 and A07, which affects how you calculate combined risk
- Writing `fuzzer.py` clarified what SQLmap is doing internally, which makes it much easier to tune and interpret correctly when things don't work as expected
- Documenting findings properly is genuinely harder than finding them — good write-ups require enough detail for a developer to reproduce, understand, and fix the issue, which is a different skill from exploitation

---
