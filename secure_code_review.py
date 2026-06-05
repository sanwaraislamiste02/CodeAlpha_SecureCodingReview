#!/usr/bin/env python3
"""
=============================================================
  Secure Coding Review Tool — CodeAlpha Cybersecurity Task 3
  Performs static analysis on a Python file and generates
  a detailed vulnerability report with remediation guidance.
=============================================================

Usage:
    python3 secure_code_review.py vulnerable_app.py
    python3 secure_code_review.py vulnerable_app.py --output report.html
    python3 secure_code_review.py vulnerable_app.py --format text
"""

import re
import sys
import os
import argparse
import datetime
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

# ── Severity levels ───────────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_COLOR = {
    CRITICAL: "#ff4d4d",
    HIGH:     "#ff8c42",
    MEDIUM:   "#ffd166",
    LOW:      "#60a5fa",
    INFO:     "#94a3b8",
}
SEVERITY_EMOJI = {CRITICAL:"🔴", HIGH:"🟠", MEDIUM:"🟡", LOW:"🔵", INFO:"⚪"}

# ── Vulnerability finding ─────────────────────────────────────────────────────
@dataclass
class Finding:
    vuln_id:      str
    title:        str
    severity:     str
    cwe:          str
    owasp:        str
    line_number:  int
    line_content: str
    description:  str
    impact:       str
    remediation:  str
    secure_code:  str

# ── Detection rules ───────────────────────────────────────────────────────────
RULES = [
    {
        "id": "SEC-001",
        "title": "SQL Injection via String Formatting",
        "severity": CRITICAL,
        "cwe": "CWE-89",
        "owasp": "A03:2021 – Injection",
        "patterns": [
            r'execute\s*\(\s*["\'].*%[s|d].*["\'].*%',
            r'execute\s*\(\s*f["\'].*\{',
            r'execute\s*\(\s*["\'].*\+',
            r'cursor\.execute\s*\(\s*".*\+',
        ],
        "description": "User-controlled input is directly interpolated into a SQL query string without parameterization. An attacker can manipulate query logic to bypass authentication, exfiltrate data, or modify the database.",
        "impact": "Complete database compromise. Authentication bypass using payloads like `' OR '1'='1`. Potential data deletion with DROP TABLE. Data exfiltration via UNION attacks.",
        "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
        "secure_code": 'query = "SELECT * FROM users WHERE username=? AND password=?"\ncursor.execute(query, (username, password_hash))',
    },
    {
        "id": "SEC-002",
        "title": "Cross-Site Scripting (XSS) – Reflected",
        "severity": HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021 – Injection",
        "patterns": [
            r'render_template_string\s*\(\s*f["\']',
            r'return\s+.*request\.(args|form|values)',
            r'Markup\s*\(\s*.*request\.',
        ],
        "description": "User-supplied input is rendered directly into an HTML response without sanitization or escaping. An attacker can inject malicious JavaScript to steal session tokens, redirect users, or perform actions on their behalf.",
        "impact": "Session hijacking via document.cookie theft, credential harvesting through injected forms, malware distribution, defacement.",
        "remediation": "Use Jinja2 templates with auto-escaping (default in Flask). Never use render_template_string with unsanitized f-strings. Use markupsafe.escape() for inline rendering.",
        "secure_code": "# Use templates with auto-escaping:\n# return render_template('search.html', term=term)\n# In template: <h1>Results for: {{ term }}</h1>  {# auto-escaped #}",
    },
    {
        "id": "SEC-003",
        "title": "OS Command Injection",
        "severity": CRITICAL,
        "cwe": "CWE-78",
        "owasp": "A03:2021 – Injection",
        "patterns": [
            r'subprocess\.(check_output|run|call|Popen).*shell\s*=\s*True',
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
        ],
        "description": "User input is passed to a shell command with shell=True. An attacker can append shell metacharacters (;, &&, |, $()) to execute arbitrary OS commands on the server.",
        "impact": "Full server compromise. Arbitrary command execution, data exfiltration, backdoor installation, lateral movement within the network.",
        "remediation": "Use subprocess with shell=False and pass arguments as a list. Validate and whitelist input against a strict allowlist before use.",
        "secure_code": 'import ipaddress\n# Validate input is a real IP/hostname\ntry:\n    ipaddress.ip_address(host)  # raises ValueError if invalid\nexcept ValueError:\n    return "Invalid host", 400\nresult = subprocess.run(["ping", "-c", "1", host],\n                        capture_output=True, timeout=5, shell=False)',
    },
    {
        "id": "SEC-004",
        "title": "Hardcoded Credentials / Secret Keys",
        "severity": HIGH,
        "cwe": "CWE-798",
        "owasp": "A07:2021 – Identification and Authentication Failures",
        "patterns": [
            r'(password|passwd|secret|api_key|apikey|token|key)\s*=\s*["\'][^"\']{3,}["\']',
            r'secret_key\s*=\s*["\'][^"\']+["\']',
        ],
        "description": "Credentials, API keys, or secret keys are hardcoded in source code. When the code is committed to version control or shared, attackers gain permanent access to those secrets.",
        "impact": "Unauthorized access to databases, APIs, and services. Secrets found in public repos are harvested by bots within minutes of exposure.",
        "remediation": "Store secrets in environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager, .env files excluded from git). Use python-decouple or os.environ.",
        "secure_code": 'import os\nfrom decouple import config\n\nDB_PASSWORD = os.environ.get("DB_PASSWORD")  # or config("DB_PASSWORD")\nSECRET_KEY  = os.environ.get("FLASK_SECRET_KEY")\nassert SECRET_KEY, "FLASK_SECRET_KEY must be set"',
    },
    {
        "id": "SEC-005",
        "title": "Insecure Deserialization (Pickle)",
        "severity": CRITICAL,
        "cwe": "CWE-502",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "patterns": [
            r'pickle\.loads?\s*\(',
            r'pickle\.load\s*\(',
        ],
        "description": "pickle.loads() deserializes arbitrary Python objects from untrusted data. A malicious payload can execute arbitrary code during deserialization — before any validation can occur.",
        "impact": "Remote Code Execution (RCE). An attacker crafts a malicious pickle payload that runs any OS command when deserialized.",
        "remediation": "Never deserialize untrusted data with pickle. Use JSON for data exchange. If serialization is necessary, use signing (itsdangerous.URLSafeSerializer) to verify integrity.",
        "secure_code": 'import json\nfrom itsdangerous import URLSafeSerializer\n\n# For session data, use signed JSON:\nserializer = URLSafeSerializer(app.secret_key)\ndata = serializer.loads(token)  # raises BadSignature if tampered',
    },
    {
        "id": "SEC-006",
        "title": "Weak Password Hashing (MD5 / SHA1)",
        "severity": HIGH,
        "cwe": "CWE-327",
        "owasp": "A02:2021 – Cryptographic Failures",
        "patterns": [
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'hashlib\.sha256\s*\(.*password',
        ],
        "description": "MD5 and SHA1 are cryptographically broken and trivially reversible via rainbow tables or brute force. SHA-256 without salting is also insufficient for password storage.",
        "impact": "Database breach → instant password recovery for all users. Credential stuffing attacks across other services where users reuse passwords.",
        "remediation": "Use bcrypt, scrypt, or Argon2 (the OWASP-recommended winner of the Password Hashing Competition). These are slow by design and include built-in salting.",
        "secure_code": 'import bcrypt\n\n# Hash a password:\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))\n\n# Verify:\nbcrypt.checkpw(password.encode(), hashed)  # returns True/False',
    },
    {
        "id": "SEC-007",
        "title": "Path Traversal",
        "severity": HIGH,
        "cwe": "CWE-22",
        "owasp": "A01:2021 – Broken Access Control",
        "patterns": [
            r'os\.path\.join\s*\(.*request\.',
            r'open\s*\(\s*.*request\.',
            r'open\s*\(\s*os\.path\.join',
        ],
        "description": "User-supplied filenames are used directly in file path construction without sanitization. An attacker can use sequences like ../../etc/passwd to traverse outside the intended directory.",
        "impact": "Arbitrary file read including /etc/passwd, /etc/shadow, application source code, and private keys. In write scenarios: arbitrary file write / RCE.",
        "remediation": "Use os.path.realpath() to resolve the path and verify it starts with the allowed base directory. Use pathlib for safer path handling.",
        "secure_code": 'from pathlib import Path\n\nBASE_DIR = Path("uploads").resolve()\n\ndef safe_open(filename: str):\n    requested = (BASE_DIR / filename).resolve()\n    if not str(requested).startswith(str(BASE_DIR)):\n        raise PermissionError("Path traversal detected")\n    return requested.read_text()',
    },
    {
        "id": "SEC-008",
        "title": "Debug Mode Enabled in Production",
        "severity": MEDIUM,
        "cwe": "CWE-215",
        "owasp": "A05:2021 – Security Misconfiguration",
        "patterns": [
            r'app\.run\s*\(.*debug\s*=\s*True',
            r'DEBUG\s*=\s*True',
        ],
        "description": "Flask debug mode exposes an interactive Werkzeug debugger in the browser on any unhandled exception. This provides Python REPL access on the server.",
        "impact": "Full server compromise. The debugger allows arbitrary Python execution in the server's process context without authentication.",
        "remediation": "Set debug=False in production. Use environment variables to control mode. Never deploy with debug=True.",
        "secure_code": 'import os\n\nif __name__ == "__main__":\n    debug = os.environ.get("FLASK_DEBUG", "0") == "1"\n    app.run(debug=debug)',
    },
    {
        "id": "SEC-009",
        "title": "Sensitive Data Exposure via Debug Endpoint",
        "severity": HIGH,
        "cwe": "CWE-200",
        "owasp": "A02:2021 – Cryptographic Failures",
        "patterns": [
            r'os\.environ\b',
            r'return\s+str\s*\(\s*os\.environ',
        ],
        "description": "Exposing environment variables to HTTP responses leaks all secrets, API keys, database credentials, and internal configuration stored in the environment.",
        "impact": "Complete secret exposure. All credentials loaded from environment (database, cloud, third-party APIs) are visible to any HTTP client.",
        "remediation": "Remove all debug endpoints before deployment. Use proper logging (not HTTP responses) for diagnostics. Apply authentication to any diagnostic routes.",
        "secure_code": '# Remove /debug endpoint entirely.\n# For diagnostics in staging, use authenticated admin routes:\n@app.route("/admin/health")\n@require_admin_auth\ndef health_check():\n    return {"status": "ok", "version": APP_VERSION}',
    },
]

# ── Scanner ───────────────────────────────────────────────────────────────────

def scan_file(filepath: str) -> List[Finding]:
    findings: List[Finding] = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    for rule in RULES:
        for pattern in rule["patterns"]:
            for lineno, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Avoid duplicate findings for same rule+line
                    already = any(
                        fi.vuln_id == rule["id"] and fi.line_number == lineno
                        for fi in findings
                    )
                    if not already:
                        findings.append(Finding(
                            vuln_id      = rule["id"],
                            title        = rule["title"],
                            severity     = rule["severity"],
                            cwe          = rule["cwe"],
                            owasp        = rule["owasp"],
                            line_number  = lineno,
                            line_content = line.rstrip(),
                            description  = rule["description"],
                            impact       = rule["impact"],
                            remediation  = rule["remediation"],
                            secure_code  = rule["secure_code"],
                        ))
    return findings


# ── HTML Report ───────────────────────────────────────────────────────────────

def severity_order(s):
    return {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}.get(s, 5)

def generate_html_report(findings: List[Finding], source_file: str) -> str:
    findings.sort(key=lambda f: severity_order(f.severity))
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in [CRITICAL, HIGH, MEDIUM, LOW, INFO]}
    total = len(findings)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cards_html = ""
    for f in findings:
        col = SEVERITY_COLOR[f.severity]
        emoji = SEVERITY_EMOJI[f.severity]
        secure_escaped = f.secure_code.replace("<","&lt;").replace(">","&gt;")
        line_escaped   = f.line_content.replace("<","&lt;").replace(">","&gt;")
        cards_html += f"""
<div class="finding-card" style="border-left:4px solid {col}">
  <div class="finding-header">
    <div>
      <span class="badge" style="background:{col}22;color:{col};border:1px solid {col}44">{emoji} {f.severity}</span>
      <span class="vuln-id">{f.vuln_id}</span>
    </div>
    <div class="finding-title">{f.title}</div>
    <div class="finding-meta">
      <span>📌 Line {f.line_number}</span>
      <span>🔗 {f.cwe}</span>
      <span>📋 {f.owasp}</span>
    </div>
  </div>
  <div class="finding-body">
    <div class="code-line"><span class="ln">{f.line_number}</span><code>{line_escaped}</code></div>
    <div class="finding-section"><strong>Description</strong><p>{f.description}</p></div>
    <div class="finding-section impact"><strong>Impact</strong><p>{f.impact}</p></div>
    <div class="finding-section remedy"><strong>Remediation</strong><p>{f.remediation}</p>
      <pre><code>{secure_escaped}</code></pre>
    </div>
  </div>
</div>"""

    sev_bars = ""
    for sev, col in SEVERITY_COLOR.items():
        cnt = counts.get(sev, 0)
        pct = (cnt / total * 100) if total else 0
        sev_bars += f"""<div class="sev-row">
  <span class="sev-label" style="color:{col}">{sev}</span>
  <div class="sev-bar-bg">
    <div class="sev-bar" style="width:{pct}%;background:{col}"></div>
  </div>
  <span class="sev-count">{cnt}</span>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Code Review Report — {source_file}</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{{--bg:#0a0c10;--surface:#111318;--surface2:#181c24;--border:#232835;
  --text:#e8eaf0;--muted:#6b7280;--accent:#ff4d4d;--safe:#00e5a0;
  --font:'Syne',sans-serif;--mono:'DM Mono',monospace;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--font);padding:40px;}}
h1{{font-size:2rem;font-weight:800;margin-bottom:6px}}
.subtitle{{color:var(--muted);font-size:14px;font-family:var(--mono);margin-bottom:40px}}
.summary-grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:40px;max-width:800px}}
.summary-card{{background:var(--surface);border:1px solid var(--border);padding:24px;border-radius:4px}}
.summary-card h3{{font-size:12px;letter-spacing:2px;color:var(--muted);margin-bottom:16px}}
.total-num{{font-size:3rem;font-weight:800;color:var(--accent);font-family:var(--mono)}}
.sev-row{{display:flex;align-items:center;gap:12px;margin-bottom:10px}}
.sev-label{{font-family:var(--mono);font-size:11px;min-width:70px;letter-spacing:1px}}
.sev-bar-bg{{flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden}}
.sev-bar{{height:100%;border-radius:3px;transition:width 1s ease}}
.sev-count{{font-family:var(--mono);font-size:12px;min-width:20px;text-align:right}}
.findings-list{{display:flex;flex-direction:column;gap:20px;max-width:900px}}
.finding-card{{background:var(--surface);border:1px solid var(--border);border-radius:4px;overflow:hidden}}
.finding-header{{padding:20px 24px;background:var(--surface2);border-bottom:1px solid var(--border)}}
.badge{{font-family:var(--mono);font-size:11px;padding:3px 10px;border-radius:2px;letter-spacing:1px}}
.vuln-id{{font-family:var(--mono);font-size:11px;color:var(--muted);margin-left:10px}}
.finding-title{{font-size:1.1rem;font-weight:700;margin:10px 0 8px}}
.finding-meta{{display:flex;gap:16px;font-family:var(--mono);font-size:11px;color:var(--muted)}}
.finding-body{{padding:24px}}
.code-line{{background:#0d0f13;border:1px solid var(--border);padding:12px 16px;border-radius:3px;
  font-family:var(--mono);font-size:13px;margin-bottom:20px;overflow-x:auto}}
.ln{{color:var(--muted);margin-right:16px;user-select:none}}
.finding-section{{margin-bottom:18px}}
.finding-section strong{{font-size:12px;letter-spacing:1px;color:var(--muted);display:block;margin-bottom:6px}}
.finding-section p{{font-size:14px;line-height:1.7;color:#c8ccd6}}
.impact strong{{color:#ffd16680}}
.remedy strong{{color:#00e5a080}}
pre{{background:#0d0f13;border:1px solid var(--border);padding:16px;
  border-radius:3px;overflow-x:auto;margin-top:12px;font-family:var(--mono);font-size:12px;
  line-height:1.7;color:#a8d8a0}}
footer{{margin-top:60px;padding-top:24px;border-top:1px solid var(--border);
  font-family:var(--mono);font-size:12px;color:var(--muted);text-align:center}}
</style></head><body>
<h1>🔐 Secure Code Review Report</h1>
<div class="subtitle">Target: {source_file} &nbsp;|&nbsp; Generated: {ts} &nbsp;|&nbsp; CodeAlpha Task 3</div>

<div class="summary-grid">
  <div class="summary-card">
    <h3>TOTAL VULNERABILITIES</h3>
    <div class="total-num">{total}</div>
    <p style="color:var(--muted);font-size:13px;margin-top:8px">across {len(set(f.vuln_id for f in findings))} unique issue types</p>
  </div>
  <div class="summary-card">
    <h3>BY SEVERITY</h3>
    {sev_bars}
  </div>
</div>

<div class="findings-list">
{cards_html}
</div>

<footer>
  <p>CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review</p>
  <p style="margin-top:6px">Built by [Your Name] | GitHub: CodeAlpha_SecureCodingReview</p>
</footer>
</body></html>"""


# ── Text Report ───────────────────────────────────────────────────────────────

def generate_text_report(findings: List[Finding], source_file: str) -> str:
    findings.sort(key=lambda f: severity_order(f.severity))
    lines = [
        "=" * 70,
        "  SECURE CODE REVIEW REPORT — CodeAlpha Task 3",
        f"  Target : {source_file}",
        f"  Date   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 70, "",
        f"  Total findings: {len(findings)}", "",
    ]
    for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
        cnt = sum(1 for f in findings if f.severity == sev)
        lines.append(f"  {SEVERITY_EMOJI[sev]} {sev:<10}: {cnt}")
    lines += ["", "─" * 70]

    for f in findings:
        lines += [
            f"\n[{f.vuln_id}] {SEVERITY_EMOJI[f.severity]} {f.severity} — {f.title}",
            f"  Line    : {f.line_number}",
            f"  CWE     : {f.cwe}",
            f"  OWASP   : {f.owasp}",
            f"  Code    : {f.line_content.strip()}",
            f"\n  Description:\n  {f.description}",
            f"\n  Impact:\n  {f.impact}",
            f"\n  Remediation:\n  {f.remediation}",
            f"\n  Secure Example:\n",
        ]
        for sl in f.secure_code.splitlines():
            lines.append(f"    {sl}")
        lines.append("─" * 70)
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Secure Coding Review — CodeAlpha Task 3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Python source file to scan")
    parser.add_argument("--output", "-o", default=None, help="Output file path")
    parser.add_argument("--format", "-f", choices=["html", "text"], default="html",
                        help="Report format (default: html)")
    args = parser.parse_args()

    if not os.path.isfile(args.target):
        sys.exit(f"[ERROR] File not found: {args.target}")

    print(f"[*] Scanning {args.target} ...")
    findings = scan_file(args.target)
    print(f"[*] Found {len(findings)} potential vulnerabilities.")

    if args.format == "html":
        report = generate_html_report(findings, args.target)
        out = args.output or "security_report.html"
    else:
        report = generate_text_report(findings, args.target)
        out = args.output or "security_report.txt"

    with open(out, "w", encoding="utf-8") as fp:
        fp.write(report)
    print(f"[✓] Report saved to: {out}")

    # Summary to stdout
    for sev in [CRITICAL, HIGH, MEDIUM, LOW]:
        cnt = sum(1 for f in findings if f.severity == sev)
        if cnt:
            print(f"  {SEVERITY_EMOJI[sev]} {sev}: {cnt}")

if __name__ == "__main__":
    main()
