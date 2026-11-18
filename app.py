"""
SecureVault - a simple secured Management Information System (MIS).
Stores confidential records (encrypted) for authenticated users.

Security controls implemented (see README.md for the mapping to the brief):
  - Strong password policy + salted hashing        -> brute force / credential attacks
  - MFA (TOTP, Google Authenticator compatible)    -> phishing / stolen passwords
  - JWT (short-lived, HttpOnly, SameSite cookie)   -> session security
  - RBAC (IAM): user vs admin roles                -> least privilege
  - Encryption of data before it reaches the DB    -> data breach protection
  - Parameterised SQL queries                      -> SQL injection
  - Rate limiting + account lockout                -> DDoS / brute force
  - HTTPS + HSTS + secure cookies                  -> man-in-the-middle
  - CSRF tokens, CSP, anti-clickjacking headers    -> phishing / XSS / CSRF
  - HMAC-signed webhooks with replay protection    -> forged webhooks
  - Security perimeter: IP allow-list for /admin   -> network perimeter
  - Audit log of every security event              -> monitoring / forensics
"""
import functools
import hashlib
import hmac
import io
import base64
import json
import os
import re
import secrets
import sqlite3
import time

import jwt
import pyotp
import qrcode
from cryptography.fernet import Fernet
from flask import (Flask, abort, g, jsonify, redirect, render_template_string,
                   request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# Configuration & secrets (generated once, never hard-coded in source)
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "securevault.db")
SECRETS_FILE = os.path.join(BASE_DIR, "secrets.json")
USE_HTTPS = os.environ.get("USE_HTTPS", "1") == "1"
ADMIN_ALLOWED_IPS = os.environ.get("ADMIN_ALLOWED_IPS", "127.0.0.1,::1").split(",")
JWT_LIFETIME = 15 * 60          # 15 minutes
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 5 * 60
COMMON_PASSWORDS = {"password123!", "qwerty123456", "admin123456!", "welcome12345"}


def load_secrets():
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE) as f:
            return json.load(f)
    s = {
        "flask": secrets.token_hex(32),
        "jwt": secrets.token_hex(32),
        "fernet": Fernet.generate_key().decode(),
        "webhook": secrets.token_hex(32),
    }
    with open(SECRETS_FILE, "w") as f:
        json.dump(s, f)
    try:
        os.chmod(SECRETS_FILE, 0o600)
    except OSError:
        pass
    return s


SECRETS = load_secrets()
fernet = Fernet(SECRETS["fernet"].encode())

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRETS["flask"],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=USE_HTTPS,
    SESSION_COOKIE_SAMESITE="Strict",
    MAX_CONTENT_LENGTH=16 * 1024,   # reject huge request bodies
)

limiter = Limiter(get_remote_address, app=app,
                  default_limits=["60 per minute"],   # anti-DDoS baseline
                  storage_uri="memory://")


# --------------------------------------------------------------------------
# Database (parameterised queries ONLY -> SQL injection is impossible)
# --------------------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL,
            mfa_secret TEXT NOT NULL,          -- stored encrypted
            role TEXT NOT NULL DEFAULT 'user',
            failed INTEGER NOT NULL DEFAULT 0,
            locked_until REAL NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS records(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body_enc TEXT NOT NULL);           -- stored encrypted
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, ip TEXT, event TEXT, detail TEXT);
        """)


def audit(event, detail=""):
    with db() as c:
        c.execute("INSERT INTO audit(ts, ip, event, detail) VALUES (?,?,?,?)",
                  (time.strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr, event, detail[:200]))


# --------------------------------------------------------------------------
# Helpers: password policy, CSRF, JWT, RBAC, templates
# --------------------------------------------------------------------------
def password_problems(pw):
    p = []
    if len(pw) < 12: p.append("at least 12 characters")
    if not re.search(r"[a-z]", pw): p.append("a lowercase letter")
    if not re.search(r"[A-Z]", pw): p.append("an uppercase letter")
    if not re.search(r"\d", pw): p.append("a digit")
    if not re.search(r"[^\w\s]", pw): p.append("a symbol")
    if pw.lower() in COMMON_PASSWORDS: p.append("not a common password")
    return p


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf():
    if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
        audit("CSRF_BLOCKED", request.path)
        abort(400, "Invalid CSRF token")


def issue_jwt(user):
    now = int(time.time())
    return jwt.encode({"sub": str(user["id"]), "role": user["role"], "iss": "securevault",
                       "iat": now, "exp": now + JWT_LIFETIME},
                      SECRETS["jwt"], algorithm="HS256")


def login_required(role=None):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            token = request.cookies.get("access_token", "")
            try:
                # algorithms is pinned -> "alg: none" and algorithm-confusion attacks fail
                data = jwt.decode(token, SECRETS["jwt"], algorithms=["HS256"],
                                  issuer="securevault", options={"require": ["exp", "sub"]})
            except jwt.PyJWTError:
                if token:
                    audit("JWT_REJECTED", request.path)
                return redirect(url_for("login"))
            g.user = {"id": int(data["sub"]), "role": data["role"]}
            if role and g.user["role"] != role:
                audit("FORBIDDEN", f"{request.path} role={g.user['role']}")
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


BASE = """<!doctype html><html><head><meta charset="utf-8"><title>SecureVault</title>
<style>body{font-family:system-ui;max-width:720px;margin:2rem auto;padding:0 1rem;color:#222}
input,textarea{width:100%;padding:.5rem;margin:.25rem 0 .75rem;box-sizing:border-box}
button{padding:.5rem 1rem;cursor:pointer}.err{color:#b00020}.ok{color:#0a7d2c}
nav a{margin-right:1rem}.card{border:1px solid #ccc;border-radius:6px;padding:.75rem;margin:.5rem 0}
table{border-collapse:collapse;width:100%;font-size:.85rem}td,th{border:1px solid #ddd;padding:4px}</style>
</head><body><h2>SecureVault <small>(secure records MIS)</small></h2>
<nav>{% if logged_in %}<a href="/dashboard">Dashboard</a><a href="/admin">Admin</a>
<a href="/logout">Logout</a>{% else %}<a href="/login">Login</a><a href="/register">Register</a>{% endif %}</nav><hr>
{{ content }}</body></html>"""


def page(body, **ctx):
    inner = Markup(render_template_string(body, csrf_token=csrf_token, **ctx))  # autoescaped -> no XSS
    return render_template_string(BASE, content=inner, logged_in=bool(request.cookies.get("access_token")))


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                               "style-src 'self' 'unsafe-inline'; form-action 'self'; "
                                               "frame-ancestors 'none'")
    resp.headers["X-Frame-Options"] = "DENY"                         # clickjacking / phishing overlays
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    if USE_HTTPS:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"  # anti-MITM
    return resp


@app.errorhandler(429)
def too_many(e):
    audit("RATE_LIMITED", request.path)
    return jsonify(error="Too many requests. Slow down."), 429


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    error = None
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        problems = password_problems(pw)
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            error = "Username: 3-30 letters, digits or underscore."
        elif problems:
            error = "Password needs: " + ", ".join(problems)
        else:
            mfa_secret = pyotp.random_base32()
            try:
                with db() as c:
                    first = c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
                    c.execute("INSERT INTO users(username, pw_hash, mfa_secret, role) VALUES (?,?,?,?)",
                              (username, generate_password_hash(pw),
                               fernet.encrypt(mfa_secret.encode()).decode(),
                               "admin" if first else "user"))
            except sqlite3.IntegrityError:
                error = "Username already taken."
            else:
                audit("REGISTER", username)
                uri = pyotp.TOTP(mfa_secret).provisioning_uri(username, issuer_name="SecureVault")
                buf = io.BytesIO()
                qrcode.make(uri).save(buf, format="PNG")
                qr = base64.b64encode(buf.getvalue()).decode()
                return page("""<p class="ok">Account created. Scan this QR code with Google/Microsoft
                    Authenticator <b>now</b> (it is shown only once).</p>
                    <img src="data:image/png;base64,{{ qr }}" width="220"><p>Manual key: <code>{{ key }}</code></p>
                    <a href="/login">Go to login</a>""", qr=qr, key=mfa_secret)
    return page("""<h3>Register</h3>{% if error %}<p class="err">{{ error }}</p>{% endif %}
        <form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
        Username<input name="username" required>
        Password (12+ chars, upper, lower, digit, symbol)<input name="password" type="password" required>
        <button>Create account</button></form>""", error=error)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    error = None
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "")
        pw = request.form.get("password", "")
        with db() as c:
            u = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()  # parameterised
            now = time.time()
            if u and u["locked_until"] > now:
                audit("LOGIN_LOCKED", username)
                error = "Invalid credentials or account locked."
            elif u and check_password_hash(u["pw_hash"], pw):
                c.execute("UPDATE users SET failed=0 WHERE id=?", (u["id"],))
                session["pending_uid"], session["pending_ts"] = u["id"], now
                audit("LOGIN_PASSWORD_OK", username)
                return redirect(url_for("mfa"))
            else:
                if u:
                    failed = u["failed"] + 1
                    lock = now + LOCKOUT_SECONDS if failed >= MAX_FAILED_LOGINS else 0
                    c.execute("UPDATE users SET failed=?, locked_until=? WHERE id=?",
                              (0 if lock else failed, lock, u["id"]))
                audit("LOGIN_FAILED", username)
                error = "Invalid credentials or account locked."   # same message: no user enumeration
    return page("""<h3>Login</h3>{% if error %}<p class="err">{{ error }}</p>{% endif %}
        <form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
        Username<input name="username" required>Password<input name="password" type="password" required>
        <button>Continue</button></form>""", error=error)


@app.route("/mfa", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def mfa():
    uid = session.get("pending_uid")
    if not uid or time.time() - session.get("pending_ts", 0) > 300:
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        check_csrf()
        with db() as c:
            u = c.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        secret = fernet.decrypt(u["mfa_secret"].encode()).decode()
        if pyotp.TOTP(secret).verify(request.form.get("code", "").strip(), valid_window=1):
            session.pop("pending_uid", None)
            audit("LOGIN_SUCCESS", u["username"])
            resp = redirect(url_for("dashboard"))
            resp.set_cookie("access_token", issue_jwt(u), max_age=JWT_LIFETIME, httponly=True,
                            secure=USE_HTTPS, samesite="Strict")
            return resp
        audit("MFA_FAILED", u["username"])
        error = "Wrong code."
    return page("""<h3>Two-factor authentication</h3>{% if error %}<p class="err">{{ error }}</p>{% endif %}
        <form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
        6-digit code from your authenticator app<input name="code" inputmode="numeric" required>
        <button>Verify</button></form>""", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = redirect(url_for("login"))
    resp.delete_cookie("access_token")
    return resp


@app.route("/dashboard", methods=["GET", "POST"])
@login_required()
def dashboard():
    if request.method == "POST":
        check_csrf()
        title = request.form.get("title", "").strip()[:100]
        body = request.form.get("body", "")[:1000]
        if title:
            with db() as c:
                c.execute("INSERT INTO records(user_id, title, body_enc) VALUES (?,?,?)",
                          (g.user["id"], title, fernet.encrypt(body.encode()).decode()))  # encrypted before DB
            audit("RECORD_ADDED", f"user={g.user['id']}")
        return redirect(url_for("dashboard"))
    q = request.args.get("q", "")
    with db() as c:
        rows = c.execute("SELECT * FROM records WHERE user_id = ? AND title LIKE ?",  # parameterised
                         (g.user["id"], f"%{q}%")).fetchall()
    records = [{"title": r["title"], "body": fernet.decrypt(r["body_enc"].encode()).decode()} for r in rows]
    return page("""<h3>My confidential records</h3>
        <form method="get"><input name="q" placeholder="Search titles" value="{{ q }}"></form>
        {% for r in records %}<div class="card"><b>{{ r.title }}</b><br>{{ r.body }}</div>
        {% else %}<p>No records yet.</p>{% endfor %}
        <h4>Add record</h4><form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
        Title<input name="title" required>Details (will be encrypted)<textarea name="body"></textarea>
        <button>Save</button></form>""", records=records, q=q)


@app.route("/admin")
@login_required(role="admin")                         # RBAC: admins only
def admin():
    if request.remote_addr not in ADMIN_ALLOWED_IPS:   # security perimeter: IP allow-list
        audit("ADMIN_IP_BLOCKED", request.remote_addr)
        abort(403)
    with db() as c:
        logs = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 50").fetchall()
    return page("""<h3>Security audit log (last 50)</h3><table><tr><th>Time</th><th>IP</th><th>Event</th>
        <th>Detail</th></tr>{% for l in logs %}<tr><td>{{ l.ts }}</td><td>{{ l.ip }}</td><td>{{ l.event }}</td>
        <td>{{ l.detail }}</td></tr>{% endfor %}</table>""", logs=logs)


@app.route("/webhook/payment", methods=["POST"])
@limiter.limit("30 per minute")
def webhook():
    """Accepts events only if signed: X-Signature = HMAC_SHA256(secret, timestamp + '.' + body)."""
    ts = request.headers.get("X-Timestamp", "")
    sig = request.headers.get("X-Signature", "")
    body = request.get_data()
    try:
        fresh = abs(time.time() - int(ts)) <= 300      # replay protection (5 min window)
    except ValueError:
        fresh = False
    expected = hmac.new(SECRETS["webhook"].encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not (fresh and hmac.compare_digest(sig, expected)):
        audit("WEBHOOK_REJECTED", request.remote_addr)
        return jsonify(error="invalid signature"), 401
    audit("WEBHOOK_ACCEPTED", body.decode(errors="replace"))
    return jsonify(status="ok")


if __name__ == "__main__":
    init_db()
    print("Webhook secret (give to the sender):", SECRETS["webhook"])
    app.run(host="127.0.0.1", port=5000, ssl_context="adhoc" if USE_HTTPS else None)
