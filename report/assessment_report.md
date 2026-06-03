# Findings Report

This is my write-up of everything I found during the lab. Not a formal pentest report, just documenting what I did and what worked.

**Apps tested:** DVWA (security=low), OWASP Juice Shop  
**Tools:** Burp Suite, SQLmap, Nikto, Python fuzzer  
**Date:** June 2024

---

## Findings

### 1. SQL Injection — DVWA

**Endpoint:** `/dvwa/vulnerabilities/sqli/?id=`  
**Severity:** Critical

The id parameter goes straight into a SQL query with no sanitisation. Using `' OR 1=1-- -` returned all users. Then used UNION SELECT to grab the database name and dump the users table including password hashes.

```
' UNION SELECT null,database()-- -      --> dvwa
' UNION SELECT user,password FROM users-- -  --> dumped all 5 users + hashes
```

All hashes were unsalted MD5 and cracked immediately on crackstation.net (e.g. admin = "password").

Also confirmed everything with SQLmap which found the same injection point automatically.

**Fix:** Use prepared statements / parameterised queries. Don't store passwords as MD5 - use bcrypt.

---

### 2. SQL Injection Login Bypass — Juice Shop

**Endpoint:** `POST /rest/user/login`  
**Severity:** Critical

Same idea as above but on the login form. Entering `' OR 1=1-- -` as the email with any password logged me in as admin. Juice Shop confirmed with a challenge notification.

**Fix:** Parameterise the login query.

---

### 3. Command Injection (RCE) — DVWA

**Endpoint:** `/dvwa/vulnerabilities/exec/`  
**Severity:** Critical

The ping input goes directly to a shell exec call. Injecting `127.0.0.1; id` returned:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then tried `127.0.0.1; cat /etc/passwd` and got the full passwd file. Full RCE.

**Fix:** Never pass user input to shell functions. Use language-native socket/ping implementations instead.

---

### 4. Reflected XSS — DVWA

**Endpoint:** `/dvwa/vulnerabilities/xss_r/?name=`  
**Severity:** Medium

Input is reflected back with no HTML encoding. `<script>alert('XSS')</script>` fired immediately. Also works with img onerror and svg onload for bypassing basic filters.

**Fix:** HTML encode all user output. htmlspecialchars() in PHP.

---

### 5. Stored XSS — DVWA

**Endpoint:** Guestbook page  
**Severity:** High

The name field has maxlength=10 in the HTML but that's client-side only. Removed it in devtools and submitted a script tag. It persists in the database and fires on every page load.

In real life you'd use this to steal session cookies from every visitor.

**Fix:** HTML encode stored output and validate server-side, not just client-side.

---

### 6. DOM-based XSS — DVWA

**Endpoint:** `/dvwa/vulnerabilities/xss_d/?default=`  
**Severity:** Medium

Different from reflected XSS - the payload never hits the server. The JS on the page reads the URL parameter and writes it to the DOM with document.write() without sanitising it. Alert fired but the Burp request shows a clean server response - the injection is purely client-side.

This is harder to detect with server-side scanners.

**Fix:** Don't use document.write() or innerHTML with user-controlled data. Use textContent instead.

---

### 7. Local File Inclusion — DVWA

**Endpoint:** `/dvwa/vulnerabilities/fi/?page=`  
**Severity:** High

The page parameter gets passed to PHP include() with no validation. Path traversal with `../../../../../../etc/passwd` printed the full file in the browser.

Also tried the PHP filter wrapper to read PHP source:
```
?page=php://filter/convert.base64-encode/resource=index.php
```
That worked too.

allow_url_include was off so no remote file inclusion, but LFI alone is bad enough.

**Fix:** Whitelist allowed page values server-side. Never use user input in include() directly.

---

### 8. IDOR on Basket API — Juice Shop

**Endpoint:** `POST /api/BasketItems`  
**Severity:** High

Added something to my basket and intercepted in Burp. The request includes `"BasketId": 2` (my basket). Changed it to `"BasketId": 1` in Repeater and got back `201 Created` - item added to someone else's basket. No ownership check on the server.

Also tested reading another basket directly with `GET /rest/basket/1` using my token - returned basket 1's contents fine.

**Fix:** Check that the authenticated user actually owns the basket ID they're requesting.

---

### 9. Admin Panel Without Auth — Juice Shop

**Endpoint:** `/#/administration`  
**Severity:** High

Logged in as a regular user and navigated directly to the admin page URL. It loaded and showed all user emails and reviews. The frontend router blocks it visually but the backend APIs don't enforce the role check.

**Fix:** Check user role server-side on every API endpoint, not just in the Angular router.

---

### 10. Missing CSRF Protection — DVWA

**Endpoint:** `/dvwa/vulnerabilities/csrf/`  
**Severity:** Medium

The password change form uses GET and has no CSRF token. Built a proof of concept:

```html
<img src="http://localhost/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" width="0">
```

If a logged in user visits a page with this tag, their password changes silently. My fuzzer also confirmed this automatically.

**Fix:** Add a per-session CSRF token validated server-side.

---

### 11. No Rate Limiting on Login — Juice Shop

**Severity:** Medium

Sent 50 rapid login requests via Burp Intruder, all got 401 with no throttling, no 429, no lockout. Ran Hydra briefly at ~100 req/s and nothing stopped it.

**Fix:** Rate limit the login endpoint, add exponential backoff after repeated failures.

---

### 12-16. Misc Findings

**Verbose SQL errors** — DVWA returns full MySQL error messages on injection, confirms database type and query structure. Should suppress these in production.

**Default credentials** — Both apps accepted default creds (admin/password on DVWA, admin@juice-sh.op/admin123 on Juice Shop) without any prompt to change them.

**Unsalted MD5** — Already mentioned under finding 1 but worth flagging separately. All 5 DVWA passwords stored as plain MD5, all cracked in seconds.

**No logging on failed logins** — Ran brute force against DVWA, checked docker logs after, no authentication events were logged at all.

**Outdated server headers** — DVWA returns `Server: Apache/2.4.25` and `X-Powered-By: PHP/7.0.33`. Both are years out of date with known CVEs. Nikto flagged these too.

---

## What Nikto found

Ran Nikto against both apps separately, outputs in `notes/nikto_dvwa.txt` and `notes/nikto_juiceshop.txt`.

Main things it caught: outdated Apache/PHP versions, missing security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection), phpinfo.php exposed, directory indexing on several paths, HTTP TRACE enabled.

Nikto missed most of the actual vulnerabilities (SQLi, XSS, etc.) - those needed manual testing with Burp.

---

## Fuzzer results

Ran fuzzer.py against DVWA with security=low. It detected SQLi, reflected XSS, command injection, LFI, and the CSRF issue automatically. Output went to fuzzer_results.txt.

The fuzzer is pretty basic - it checks for known error strings and reflected payloads. It wouldn't catch stored XSS, DOM XSS, IDOR or the admin panel issue since those need more context.
