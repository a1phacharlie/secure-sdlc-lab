"""
secure-sdlc-lab | app.py
========================
Deliberately VULNERABLE Flask application.
Purpose: give SAST, DAST, and SCA tools real findings to report.

DO NOT deploy this. Every bug below is intentional.

Vulnerability index
-------------------
[V-01] SQL Injection            /login          — string concat into SQL query
[V-02] OS Command Injection     /ping           — shell=True with user input
[V-03] Hardcoded Secret         module level    — SECRET_KEY in source code
[V-04] Insecure Deserialization /deserialize    — pickle.loads on user data
[V-05] Path Traversal / LFI     /read-file      — open() with unsanitized path
[V-06] Reflected XSS            /search         — user input rendered raw in HTML
[V-07] Weak Cryptography        /hash           — MD5 used for hashing
[V-08] Debug Mode Enabled       app.run()       — Werkzeug debugger exposed
[V-09] IDOR                     /user/<id>      — no authentication check
[V-10] Open Redirect            /redirect       — no allowlist on target URL
"""

import os
import pickle
import hashlib
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, redirect


# ── [V-03] Hardcoded secret ───────────────────────────────────────────────────
# Bandit rule: B105 (hardcoded password string)
# Real fix:    os.environ.get("SECRET_KEY") and load from .env
SECRET_KEY  = "sup3rs3cr3t-do-not-ship"
DB_PASSWORD = "admin:hunter2"          # B106 — hardcoded password in funcarg

app = Flask(__name__)
app.secret_key = SECRET_KEY            # same value wired in here too


# ── Database helper (in-memory SQLite, reset each request for demo) ───────────
def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    conn.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "admin",  "admin123",  "admin"),
        (2, "alice",  "alice456",  "user"),
        (3, "bob",    "bob789",    "user"),
    ])
    conn.commit()
    return conn


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Landing page — lists all endpoints so ZAP can spider them."""
    return render_template_string("""
    <!doctype html>
    <html>
    <head><title>secure-sdlc-lab | Vulnerable App</title></head>
    <body>
      <h2>&#x1F513; secure-sdlc-lab — intentionally vulnerable app</h2>
      <p>All endpoints are exploitable. This exists so security tools have
         real findings to report.</p>
      <ul>
        <li><a href="/login?user=admin&amp;pass=admin123">/login</a>
            — [V-01] SQL Injection</li>
        <li><a href="/ping?host=127.0.0.1">/ping</a>
            — [V-02] Command Injection</li>
        <li><a href="/search?q=hello">/search</a>
            — [V-06] Reflected XSS</li>
        <li><a href="/user/1">/user/&lt;id&gt;</a>
            — [V-09] IDOR</li>
        <li><a href="/read-file?name=app.py">/read-file</a>
            — [V-05] Path Traversal</li>
        <li><a href="/hash?data=test">/hash</a>
            — [V-07] Weak Hash (MD5)</li>
        <li><a href="/redirect?url=https://example.com">/redirect</a>
            — [V-10] Open Redirect</li>
        <li><a href="/deserialize">/deserialize</a>
            — [V-04] Insecure Deserialization</li>
      </ul>
    </body>
    </html>
    """)


@app.route("/login")
def login():
    """
    [V-01] SQL Injection
    --------------------
    The username and password are dropped directly into an f-string SQL query.
    Payload: ?user=admin'--&pass=anything  → logs in as admin, no password needed
    Bandit:  B608 (possible SQL injection via string-based query construction)
    Fix:     Use parameterised queries → conn.execute("SELECT ... WHERE username=?", (user,))
    """
    user = request.args.get("user", "")
    pwd  = request.args.get("pass", "")
    db   = get_db()

    # VULNERABLE: f-string interpolation directly into SQL
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"

    try:
        row    = db.execute(query).fetchone()
        result = f"Logged in as: {row}" if row else "Invalid credentials"
    except Exception as exc:
        result = f"DB error: {exc}"

    return f"<pre>Query:  {query}\nResult: {result}</pre>"


@app.route("/ping")
def ping():
    """
    [V-02] OS Command Injection
    ---------------------------
    User-supplied host is interpolated directly into a shell command string.
    Payload: ?host=127.0.0.1;cat /etc/passwd
    Bandit:  B602 (subprocess call with shell=True)
             B605 (starting a process with a shell — security issue)
    Fix:     subprocess.run(["ping", "-c", "1", host], shell=False)
             plus validate host is a valid IP/hostname
    """
    host   = request.args.get("host", "127.0.0.1")

    # VULNERABLE: shell=True + unsanitised user input
    output = subprocess.check_output(
        f"ping -c 1 {host}",
        shell=True,                    # B602
        stderr=subprocess.STDOUT,
    )
    return f"<pre>{output.decode()}</pre>"


@app.route("/search")
def search():
    """
    [V-06] Reflected XSS
    --------------------
    The query string is rendered directly into the HTML response with no escaping.
    Payload: ?q=<script>alert(document.cookie)</script>
    Bandit:  Not caught by Bandit (needs runtime — this is where DAST shines)
    ZAP:     Active scan XSS rule 40012 / 40014
    Fix:     Use Jinja2 templates (auto-escaping) or html.escape(q)
    """
    q = request.args.get("q", "")

    # VULNERABLE: raw f-string into HTML, no html.escape()
    return f"<html><body><h3>Results for: {q}</h3><p>No results found.</p></body></html>"


@app.route("/user/<int:user_id>")
def get_user(user_id):
    """
    [V-09] IDOR — Insecure Direct Object Reference
    -----------------------------------------------
    Any visitor can enumerate all user records by changing the ID in the URL.
    No session check, no ownership check, no role check.
    ZAP:     Fuzzer / active scan
    Fix:     Check session.get("user_id") == user_id or role == "admin"
    """
    db  = get_db()
    row = db.execute(
        "SELECT id, username, role FROM users WHERE id=?", (user_id,)
    ).fetchone()

    if row:
        return f"<pre>id={row[0]}  username={row[1]}  role={row[2]}</pre>"
    return "User not found", 404


@app.route("/read-file")
def read_file():
    """
    [V-05] Path Traversal / Local File Inclusion
    ---------------------------------------------
    The filename comes from the URL and is passed directly to open().
    Payload: ?name=../../etc/passwd
    Bandit:  Flagged as medium (open with unvalidated input)
    ZAP:     Active scan path traversal rule 6
    Fix:     Use os.path.basename(name) and restrict to a safe directory;
             check realpath starts with allowed prefix
    """
    name = request.args.get("name", "app.py")

    # VULNERABLE: no path sanitisation
    with open(name, "r") as fh:
        content = fh.read()

    return f"<pre>{content}</pre>"


@app.route("/hash")
def weak_hash():
    """
    [V-07] Weak Cryptographic Hash (MD5)
    -------------------------------------
    MD5 is cryptographically broken — collisions found, not suitable for
    password storage or integrity checks.
    Bandit:  B303 (use of MD5 / insecure hash functions)
             B324 (hashlib insecure hash functions — Python 3.9+)
    Fix:     hashlib.sha256() for integrity checks;
             bcrypt / argon2 for passwords
    """
    data   = request.args.get("data", "test")

    # VULNERABLE: MD5 is broken
    result = hashlib.md5(data.encode()).hexdigest()   # B303 / B324
    return f"<p>MD5({data!r}) = <code>{result}</code></p>"


@app.route("/redirect")
def open_redirect():
    """
    [V-10] Open Redirect
    --------------------
    The redirect target comes from user input with no validation.
    Payload: ?url=https://evil.com  → phishing / OAuth token theft
    ZAP:     Passive rule 10028
    Fix:     Maintain an allowlist of permitted domains;
             never redirect to arbitrary user-supplied URLs
    """
    url = request.args.get("url", "/")

    # VULNERABLE: redirect to any URL the attacker provides
    return redirect(url)


@app.route("/deserialize", methods=["GET", "POST"])
def deserialize():
    """
    [V-04] Insecure Deserialization (pickle RCE)
    --------------------------------------------
    pickle.loads() will execute arbitrary Python when the attacker
    controls the serialised bytes — this is Remote Code Execution.
    Bandit:  B301 (pickle deserialise — possible security issue)
    Fix:     Never deserialise untrusted data with pickle.
             Use JSON (json.loads) or a schema-validated format instead.
    """
    if request.method == "POST":
        raw = request.get_data()

        # VULNERABLE: executes whatever Python object the client serialised
        obj = pickle.loads(raw)        # B301
        return f"<pre>Deserialised: {obj!r}</pre>"

    return """
    <form method="post" enctype="application/x-www-form-urlencoded">
      <textarea name="data" rows="4" cols="40">
send pickle bytes via curl: curl -X POST --data-binary @payload.pkl /deserialize
      </textarea><br>
      <button type="submit">Submit</button>
    </form>
    """


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # [V-08] debug=True exposes the Werkzeug interactive debugger
    # An attacker with debugger access can execute arbitrary Python
    # Bandit: B201 (Flask app run with debug=True)
    # Fix:    debug=False in production; use gunicorn/uvicorn instead
    app.run(host="0.0.0.0", port=5000, debug=True)   # B201
