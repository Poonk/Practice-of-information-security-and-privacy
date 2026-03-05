# Mini-Lab: Secure-Code Audit — Vulnerable Microblog (Flask + SQLite)

**Course:** ECE574: Practice of Information Security and Privacy  
**Lab type:** Take-home secure-code audit (target: ~4 hours)

## Learning objectives
You will practice auditing and fixing a real (small) web app by:
- finding implementation vulnerabilities that violate security invariants
- patching issues in **input validation**, **authn/authz**, **error handling**, **leakage**, and **TOCTOU-like** patterns
- adding regression tests that prevent reintroducing vulnerabilities
- writing a short audit report mapping **bug → impact → fix → invariant enforced**

## What you get
This repository contains a *deliberately vulnerable* microblog app:
- Python Flask + server-rendered templates
- SQLite database
- Minimal code, intentionally flawed patterns

**Your job:** audit + fix.

## Setup
### 1) Create a virtualenv (recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Run the app
```bash
python app.py
```

Open: http://127.0.0.1:5000

The app auto-creates `app.db` on first run.

## Deliverables
1) **Patched code** (zip or git repo)  
2) **Audit report** (1–2 pages max, PDF/MD): for each issue:
   - vulnerability
   - impact
   - fix summary
   - security invariant enforced
3) **Tests:** at least **4** regression tests in `tests/` that pass on your fixed version.

## Scope: Vulnerabilities to find (at least 6; 8 exist)
Examples include:
- SQL injection in authentication/search
- Broken access control (IDOR) on edit/delete
- Insecure session handling (forgeable identity)
- Missing CSRF protection
- Verbose errors / debug leakage
- Sensitive logging (credentials/tokens)
- Path traversal / unsafe export
- Weak password storage

## Hints (optional)
- Create two users (Alice/Bob). Can Alice delete Bob’s post?
- Try classic SQLi payloads against login/search.
- Look for places where untrusted input is concatenated into a SQL query or file path.
- Inspect cookies — can you forge an identity?

## AI usage note
You may use AI tools to:
- explain concepts, identify risky patterns, and suggest safer APIs
- help write tests and small refactors

You may not:
- paste the entire repository and ask for a full solution patch

If you used AI, include a **2–3 line disclosure** in your report.

## Running tests
```bash
pytest -q
```

> The provided tests are a **skeleton**. You must add at least 4 meaningful regression tests.
