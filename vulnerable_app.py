"""
vulnerable_app.py — INTENTIONALLY INSECURE CODE FOR AUDIT PURPOSES
This file contains deliberate security vulnerabilities for the
CodeAlpha Secure Coding Review (Task 3). DO NOT deploy this code.
"""

import sqlite3
import os
import subprocess
import hashlib
import pickle
import base64
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)
app.secret_key = "12345"  # VULN-05: Hardcoded weak secret key

# ── VULN-01: Hardcoded credentials ────────────────────────────────────────────
DB_PASSWORD = "admin123"
API_KEY     = "sk-live-abc123supersecret"

# ── VULN-02: SQL Injection ─────────────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("users.db")
    # Direct string interpolation — attacker can inject: ' OR '1'='1
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query).fetchone()
    if result:
        return f"Welcome {username}!"
    return "Invalid credentials"

# ── VULN-03: Cross-Site Scripting (XSS) ───────────────────────────────────────
@app.route("/search")
def search():
    term = request.args.get("q", "")
    # User input rendered directly into HTML — attacker injects <script>
    return render_template_string(f"<h1>Results for: {term}</h1>")

# ── VULN-04: Command Injection ─────────────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # Shell=True with user input — attacker appends: ; rm -rf /
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result

# ── VULN-06: Insecure Deserialization ─────────────────────────────────────────
@app.route("/load_session")
def load_session():
    data = request.cookies.get("session_data", "")
    # Pickle deserialization of untrusted input — arbitrary code execution
    obj = pickle.loads(base64.b64decode(data))
    return str(obj)

# ── VULN-07: Weak Password Hashing ────────────────────────────────────────────
def hash_password(password: str) -> str:
    # MD5 is cryptographically broken; no salt used
    return hashlib.md5(password.encode()).hexdigest()

# ── VULN-08: Path Traversal ────────────────────────────────────────────────────
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    # No sanitization — attacker requests: ../../etc/passwd
    with open(os.path.join("uploads", filename)) as f:
        return f.read()

# ── VULN-09: IDOR (Insecure Direct Object Reference) ─────────────────────────
@app.route("/user/<int:user_id>")
def get_user(user_id):
    # No authorization check — any user can access any account
    conn = sqlite3.connect("users.db")
    result = conn.execute(f"SELECT * FROM users WHERE id={user_id}").fetchone()
    return str(result)

# ── VULN-10: Sensitive Data Exposure ──────────────────────────────────────────
@app.route("/debug")
def debug():
    # Exposes environment variables including secrets in production
    return str(os.environ)

if __name__ == "__main__":
    app.run(debug=True)  # VULN-11: debug=True in production exposes stack traces
