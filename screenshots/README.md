# Screenshots

Evidence screenshots captured during the assessment. Each image corresponds to a finding in the assessment report.

| File | Finding | Description |
|------|---------|-------------|
| 01_sqli_union_dvwa.png | Finding 1 — SQLi UNION extraction | Burp Repeater showing `' UNION SELECT user,password FROM users-- -` response with all 5 user hashes |
| 02_sqli_login_bypass_juiceshop.png | Finding 2 — SQLi login bypass | Juice Shop login with `' OR 1=1-- -` — challenge notification visible confirming admin login |
| 03_command_injection_rce.png | Finding 3 — RCE via command injection | DVWA exec page showing `127.0.0.1; id` output: `uid=33(www-data)` |
Add screenshots/README.md with evidence index for all 16 findings| 05_stored_xss_guestbook.png | Finding 4 — Stored XSS | DVWA guestbook page executing stored script payload on page load |
| 06_lfi_etc_passwd.png | Finding 5 — LFI | DVWA file inclusion page showing `/etc/passwd` contents via `?page=../../../../../../etc/passwd` |
| 07_idor_basket_burp.png | Finding 6 — IDOR | Burp Repeater showing BasketId changed from 2→1, server returns 201 Created |
| 08_admin_panel_juiceshop.png | Finding 7 — Admin panel | Juice Shop `/#/administration` page visible to non-admin user, showing all emails |
| 09_md5_hashes_cracked.png | Finding 8 — Unsalted MD5 | CrackStation results showing all 5 DVWA password hashes cracked instantly |
| 10_csrf_poc.png | Finding 9 — CSRF | Browser showing password change request in Burp with no token in request params |
| 11_reflected_xss.png | Finding 10 — Reflected XSS | Browser alert dialog triggered by `?name=<script>alert('XSS')</script>` |
| 12_dom_xss.png | Finding 11 — DOM XSS | Browser alert triggered via URL fragment — Burp HTTP history shows clean server response |
| 13_no_rate_limit_intruder.png | Finding 12 — No rate limiting | Burp Intruder results showing 50 rapid requests all returning 401 with no throttling |
| 14_verbose_sql_error.png | Finding 13 — Verbose errors | DVWA response showing full MySQL error string after single-quote injection |
| 15_default_creds_dvwa.png | Finding 14 — Default creds | DVWA login page accepting admin/password — dashboard visible after login |
| 16_server_headers_burp.png | Finding 16 — Outdated headers | Burp HTTP history showing `Server: Apache/2.4.25` and `X-Powered-By: PHP/7.0.33` headers |
| 17_sqlmap_output.png | Finding 1 (confirmation) | SQLmap terminal output confirming database enumeration |
| 18_nikto_dvwa_terminal.png | Step 7 | Terminal showing Nikto scan running against DVWA |
| 19_nikto_juiceshop_terminal.png | Step 7 | Terminal showing Nikto scan running against Juice Shop |
| 20_fuzzer_results.png | Step 8 | Terminal output of fuzzer.py showing all 9 findings detected |

## How screenshots were captured

- **Burp Suite:** Proxy → HTTP History, right-click → Send to Repeater for manual testing
- **Browser:** Firefox with Burp CA cert installed, Dev Tools used for cookie extraction and DOM inspection
- **Terminal:** Kali Linux terminal for SQLmap, Nikto, Hydra, and fuzzer.py runs
- **Juice Shop challenges:** Challenge completion banners visible in screenshots confirm successful exploitation
