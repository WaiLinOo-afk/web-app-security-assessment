# Web Application Security Assessment (OWASP Top 10)

> **Ethical use notice:** This project is for **authorised testing only** on local lab environments you own and control. The tools, scripts, and techniques documented here must not be used against systems without explicit written permission. Running these against live or third-party systems without authorisation is illegal.

A personal lab project where I set up two deliberately vulnerable web apps and practised finding/exploiting common web vulnerabilities.

**Tools used:** Burp Suite, OWASP ZAP, SQLmap, Nikto, Python  
**Target apps:** DVWA, OWASP Juice Shop (both running locally via Docker)  

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) — to run DVWA and Juice Shop
- Python 3.8+ — for the fuzzer script
- [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload) — as the main proxy/testing tool
- Basic familiarity with web proxies and HTTP

---

## What I did

I deployed DVWA and OWASP Juice Shop in Docker, then worked through each OWASP Top 10 category manually using Burp Suite. I also wrote a Python script to automate some of the fuzzing I was doing by hand.

The goal was to get comfortable with the full testing workflow — not just running automated scanners, but actually understanding why each vulnerability works and how to document it properly.

---

## Vulnerabilities found

| # | Vulnerability | App | Severity | OWASP Category |
|---|--------------|-----|----------|----------------|
| 1 | SQL Injection (UNION-based) | DVWA | Critical | A03 Injection |
| 2 | SQL Injection (login bypass) | Juice Shop | Critical | A07 Auth Failures |
| 3 | Reflected XSS | DVWA | Medium | A03 Injection |
| 4 | Stored XSS | DVWA | High | A03 Injection |
| 5 | DOM-based XSS | DVWA | Medium | A03 Injection |
| 6 | Command Injection (RCE) | DVWA | Critical | A03 Injection |
| 7 | Local File Inclusion | DVWA | High | A03 Injection |
| 8 | IDOR on basket API | Juice Shop | High | A01 Broken Access Control |
| 9 | Admin panel accessible without auth | Juice Shop | High | A01 Broken Access Control |
| 10 | Passwords stored as unsalted MD5 | DVWA | High | A02 Crypto Failures |
| 11 | No rate limiting on login | Juice Shop | Med | A07 Auth Failures |
| 12 | Verbose SQL errors in response | DVWA | Medium | A03 Injection |
| 13 | Default credentials accepted | DVWA | Medium | A05 Misconfiguration |
| 14 | Missing CSRF tokens | DVWA | Medium | A08 Integrity Failures |
| 15 | No logging on failed logins | DVWA | Low | A09 Logging Failures |
| 16 | Outdated server version in headers | DVWA | Low | A06 Vulnerable Components |

---

## Highlights

**SQL Injection** — The DVWA SQLi page had no input sanitisation at all. I used `' OR 1=1-- -` to dump all users, then UNION SELECT to pull the database name and eventually all password hashes. Ran SQLmap to confirm and automate the extraction.

**Login bypass on Juice Shop** — The login form was also injectable. Entering `' OR 1=1-- -` as the email logged me straight in as the admin account. Juice Shop even confirmed it with a challenge notification.

**Command Injection** — The ping utility on DVWA didn't sanitise the input at all. Injecting `127.0.0.1; id` returned `uid=33(www-data)`, confirming RCE. Then tried `; cat /etc/passwd` which printed the full file.

**LFI** — The file inclusion page used a `page=` parameter with no validation. Navigating to `?page=../../../../../../etc/passwd` dumped the whole passwd file in the browser.

**Fuzzer script** — I got tired of manually testing each input field so I wrote `fuzzer.py` to automatically send SQLi and XSS payloads and check responses for error signatures or reflected content.

---

## How to run the fuzzer

```bash
# 1. Start DVWA in Docker
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# 2. Log into DVWA (admin/password), go to Setup and click Create Database
#    Then grab your PHPSESSID from browser dev tools

# 3. Edit SESSION_COOKIE in fuzzer.py with your session ID

# 4. Run it
pip3 install requests
python3 scripts/fuzzer.py
```

---

## Lab setup

```bash
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
```

- DVWA: `http://localhost` → Setup → Create/Reset Database → login `admin/password`
- Juice Shop: `http://localhost:3000`

---

## Project structure

```
web-app-security-assessment/
├── README.md
├── scripts/
│   ├── fuzzer.py          ← custom Python fuzzer
│   └── requirements.txt
├── configs/
│   └── burp_config_notes.md
├── screenshots/           ← exploitation evidence
│   └── README.md
├── report/
│   └── assessment_report.md
└── notes/
    ├── raw_testing_notes.md
    ├── nikto_dvwa.txt
    └── nikto_juiceshop.txt
```

---

## What I learned

- Manual testing with Burp Suite is way more valuable than just running automated scanners — you actually understand what's happening
- OWASP Top 10 isn't just a checklist, there's real overlap between categories (e.g. SQLi can cause both injection AND auth bypass)
- Writing the fuzzer helped me understand what tools like SQLmap are doing under the hood
- Documenting findings properly is harder than finding them — took me a while to get the format right

---

## TODO / What's next

- [ ] Test XXE (XML External Entity injection) — ran out of time but wanted to cover A04
- [ ] Try SSRF on Juice Shop — heard there's an endpoint that's vulnerable
- [ ] Improve fuzzer to handle authenticated sessions better and add proper logging
- [ ] Add proper CVSS scores to the report (was doing it manually and it got tedious)
- [ ] Maybe try an intermediate DVWA security level instead of just Low
