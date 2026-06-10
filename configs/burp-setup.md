# Burp Suite Proxy Setup

Notes on how I configured Burp Suite to intercept DVWA and Juice Shop traffic.

## Setup

1. Open Burp Suite → **Proxy** tab → **Options** → listener on `127.0.0.1:8080`

2. Configure Firefox proxy:
   - Settings → Network Settings → Manual Proxy
   - HTTP Proxy: `127.0.0.1`  Port: `8080`

3. Install Burp CA cert:
   - With proxy active, visit `http://burpsuite` in Firefox
   - Download CA cert → import into Firefox (Privacy & Security → Certificates → Import)
   - Trust for: "identifying websites"

4. Test: browse to `http://localhost` (DVWA) — requests should show in Proxy → HTTP History

## Features I used

| Feature | What I used it for |
|---------|-------------------|
| HTTP History | Reviewing all requests passively |
| Repeater | Manually tweaking and replaying requests |
| Intruder | Automated payload injection |
| Decoder | Decoding base64, URL-encoded stuff |

## Shortcuts

- `Ctrl+R` — Send to Repeater
- `Ctrl+I` — Send to Intruder

## Intercept workflow

1. Enable intercept: Proxy → Intercept → On
2. Submit a form in DVWA
3. Request appears → modify the parameter → Forward
4. Right-click → Send to Repeater to keep testing it
