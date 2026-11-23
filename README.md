# TRUSTSHIELD — Local Website Threat Intelligence Platform

A local educational web application for preliminary URL-risk assessment. It includes account authentication, a SQLite user database, heuristic URL checks, optional URLhaus reputation lookup, best-effort RDAP domain-age lookup, scan history in the current browser, and PDF reports.

## Features
- Local login, signup, logout and password change
- First account on a fresh database becomes administrator; later self-signups are standard users
- Admin panel to create accounts, choose user/admin role, reset passwords and enable/disable accounts
- Passwords stored as salted Werkzeug password hashes, never plain text
- SQLite database stored locally as `trustshield.db`
- URL validation, explainable heuristic indicators and weighted risk score
- Best-effort domain registration age lookup through RDAP; recent domains add a caution signal
- Optional URLhaus exact-URL threat intelligence
- PDF scan report export
- Browser-local recent scan history

## Windows / VS Code setup
1. Extract the ZIP.
2. Open the extracted `TRUSTSHIELD_LOCAL` folder in VS Code.
3. Open Terminal → New Terminal and run:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

If PowerShell blocks activation, run this in the same terminal first:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

Open `http://127.0.0.1:5000`.

## First-time setup and account sharing
1. Open `/signup` or follow the login page's create-account link.
2. The **first account** created in a fresh database automatically becomes the administrator. Create this account yourself and keep its credentials private.
3. Other people can create their own standard accounts using Signup on this same computer, or you can create accounts for them from **Admin**.
4. Admin can reset a user's password and disable or re-enable that account.
5. Users can change their own password from **Account**.

Accounts and passwords are local to this installation and stored in `trustshield.db`. Back up this file if you need to preserve accounts. Do not share the database file if it contains accounts you want to keep private.

## Local access model
The app binds to `127.0.0.1`, so it is available only on the computer running it. A person on another computer cannot access it merely by knowing the URL. For this project, give them access to the same computer and let them sign in with their account. Multi-computer LAN access or internet hosting requires additional network and deployment security work; do not expose this development build directly to the public internet.

## Domain age and RDAP
TRUSTSHIELD requests public registration data from `https://rdap.org/domain/`. If a registration date is available, it calculates approximate age. Domains under 30 days receive a 15-point caution signal; domains under 180 days receive 7 points. A new domain is not automatically malicious, and an old domain is not automatically safe. Some registries hide or omit creation dates, and RDAP may be unavailable. The registered-domain extraction handles common suffixes such as `.co.in` and `.co.uk`, but it is not a complete public-suffix implementation.

## URLhaus (optional)
Read https://urlhaus.abuse.ch/api/ and obtain an API key. In PowerShell:

```powershell
$env:URLHAUS_AUTH_KEY="YOUR_KEY_HERE"
python app.py
```

The key is server-side only. Never place it in frontend files, screenshots or public repositories. URLhaus focuses on reported malware-hosting URLs and is not a complete phishing database.

## Demo inputs
Enter these as text in TRUSTSHIELD. Do not open random suspicious links:
- `https://example.com`
- `http://example.com`
- `http://secure-login-verification.example.xyz/account?redirect=payment`
- `http://192.0.2.1/login`

These are illustrative test inputs, not claims that the domains are malicious.

## Limitations and security notes
- Educational prototype, not a certified security product.
- Heuristics can produce false positives and false negatives.
- Domain age is best-effort RDAP metadata and can be missing or inaccurate.
- It does not crawl page content, execute scripts, inspect downloads, follow redirects, inspect DNS or validate TLS certificates.
- Low score or no URLhaus match does not prove safety.
- Local app uses loopback binding and is not hardened for public internet exposure. Use it on a trusted computer only.

## Project structure
```text
TRUSTSHIELD_LOCAL/
├── app.py
├── requirements.txt
├── README.md
├── trustshield.db       # created automatically on first run
├── templates/
│   ├── auth.html
│   ├── index.html
│   ├── account.html
│   └── admin.html
└── static/
    ├── app.js
    └── styles.css
```
