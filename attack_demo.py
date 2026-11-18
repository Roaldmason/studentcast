"""
Attack simulation: run AFTER starting app.py. Shows each attack being denied.
Usage:  python attack_demo.py
"""
import base64, hashlib, hmac, json, os, time
import requests
import urllib3

urllib3.disable_warnings()
BASE = os.environ.get("BASE", "https://127.0.0.1:5000")
S = lambda: requests.Session()


def result(name, ok, note=""):
    print(f"[{'DEFENDED' if ok else 'VULNERABLE!'}] {name} {note}")


def csrf_from(html):
    return html.split('name="csrf" value="')[1].split('"')[0]


# 1. SQL injection on login ------------------------------------------------
s = S()
tok = csrf_from(s.get(BASE + "/login", verify=False).text)
r = s.post(BASE + "/login", data={"username": "' OR '1'='1' --", "password": "x", "csrf": tok},
           verify=False, allow_redirects=False)
result("SQL injection (login)", r.status_code != 302, f"-> HTTP {r.status_code}, no session granted")

# 2. CSRF / phishing form posted from another site (no token) --------------
r = requests.post(BASE + "/login", data={"username": "a", "password": "b"}, verify=False)
result("CSRF / forged form post", r.status_code == 400, f"-> HTTP {r.status_code}")

# 3. Forged JWT with alg=none, claiming admin ------------------------------
b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
fake = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': '1', 'role': 'admin', 'iss': 'securevault', 'exp': int(time.time()) + 999})}."
r = requests.get(BASE + "/admin", cookies={"access_token": fake}, verify=False, allow_redirects=False)
result("Forged JWT (alg=none)", r.status_code == 302, "-> redirected to login")

# 4. Unauthenticated access to protected area ------------------------------
r = requests.get(BASE + "/dashboard", verify=False, allow_redirects=False)
result("Access without login", r.status_code == 302)

# 5. Forged webhook (bad signature) + replayed old webhook -----------------
r = requests.post(BASE + "/webhook/payment", data=b'{"amount":999}',
                  headers={"X-Timestamp": str(int(time.time())), "X-Signature": "deadbeef"}, verify=False)
result("Forged webhook", r.status_code == 401)
secret = json.load(open("secrets.json"))["webhook"] if os.path.exists("secrets.json") else ""
old = str(int(time.time()) - 3600)
sig = hmac.new(secret.encode(), old.encode() + b".{}", hashlib.sha256).hexdigest()
r = requests.post(BASE + "/webhook/payment", data=b"{}", headers={"X-Timestamp": old, "X-Signature": sig}, verify=False)
result("Replayed webhook (valid sig, old timestamp)", r.status_code == 401)
ts = str(int(time.time()))
sig = hmac.new(secret.encode(), ts.encode() + b".{}", hashlib.sha256).hexdigest()
r = requests.post(BASE + "/webhook/payment", data=b"{}", headers={"X-Timestamp": ts, "X-Signature": sig}, verify=False)
print(f"[INFO] Legitimate signed webhook -> HTTP {r.status_code} (expected 200)")

# 6. Brute force / DDoS-style flood ----------------------------------------
codes = [requests.get(BASE + "/login", verify=False).status_code for _ in range(80)]
result("Request flood (DDoS) ", 429 in codes, f"-> got {codes.count(429)} x HTTP 429 after limit")

# 7. Security headers (MITM / clickjacking) --------------------------------
h = requests.get(BASE + "/login", verify=False).headers
need = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
result("Security headers present", all(k in h for k in need))
print("\nNow log in as admin and open /admin to see every attempt in the audit log.")
