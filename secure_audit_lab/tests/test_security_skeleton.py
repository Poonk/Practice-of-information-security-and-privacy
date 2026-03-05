import pytest
import re
import time
from db import get_conn

@pytest.fixture
def app_client():
    import app as app_module
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    yield client

def test_homepage_loads(app_client):
    r = app_client.get("/")
    assert r.status_code == 200

# TODO (students):
# Add at least 4 regression tests after patching:
# - SQL injection login bypass fails
# - IDOR delete/edit blocked (ownership check)
# - CSRF token required for POST
# - Export path cannot escape data directory


@pytest.fixture
def app_client():
    import app as app_module
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    yield client

def get_csrf(client, url="/register"):
    """Helper function: visits a page and extracts the CSRF token from the HTML."""
    res = client.get(url)
    match = re.search(r'name="csrf_token" value="([^"]+)"', res.text)
    return match.group(1) if match else ""

def test_homepage_loads(app_client):
    r = app_client.get("/")
    assert r.status_code == 200

# ---------------------------------------------------------
# REGRESSION TEST 1: SQL Injection
# ---------------------------------------------------------
def test_sqli_login_bypass_fails(app_client):
    """Ensure SQL injection in the login form does not bypass authentication."""
    token = get_csrf(app_client, "/login")
    
    payload = {
        "username": "admin' OR '1'='1",
        "password": "wrong_password",
        "csrf_token": token
    }
    r = app_client.post("/login", data=payload)
    
    # If SQLi is fixed, we stay on the login page (200 OK) with an error.
    # If it was vulnerable, it would log us in and redirect (302 Found).
    assert r.status_code == 200
    assert b"Invalid" in r.data or b"error" in r.data.lower()

# ---------------------------------------------------------
# REGRESSION TEST 2: CSRF Token Enforcement
# ---------------------------------------------------------
def test_csrf_token_required_for_post(app_client):
    """Ensure state-changing POST requests are rejected if missing a CSRF token."""
    # We send a POST to login WITHOUT the csrf_token field
    r = app_client.post("/login", data={
        "username": "test", 
        "password": "test"
    })
    
    # Should be blocked by our @app.before_request CSRF check!
    assert r.status_code == 403

# ---------------------------------------------------------
# REGRESSION TEST 3: Broken Access Control (IDOR) on Edit
# ---------------------------------------------------------
def test_idor_edit_blocked(app_client):
    """Ensure a user cannot edit a post they do not own."""
    # Generate unique names so the test doesn't crash if run multiple times
    suffix = str(time.time())
    alice = "alice_" + suffix
    bob = "bob_" + suffix
    
    # 1. Register and Login Alice
    token = get_csrf(app_client, "/register")
    app_client.post("/register", data={"username": alice, "password": "pwd", "csrf_token": token})
    token = get_csrf(app_client, "/login")
    app_client.post("/login", data={"username": alice, "password": "pwd", "csrf_token": token})
    
    # 2. Alice creates a post
    token = get_csrf(app_client, "/post/new")
    app_client.post("/post/new", data={"title": "Alice Post", "content": "Private stuff", "csrf_token": token})
    
    # Get the ID of the post Alice just created
    conn = get_conn()
    post_id = conn.execute("SELECT id FROM posts ORDER BY id DESC LIMIT 1").fetchone()[0]
    conn.close()
    
    app_client.get("/logout")
    
    # 3. Register and Login Bob
    token = get_csrf(app_client, "/register")
    app_client.post("/register", data={"username": bob, "password": "pwd", "csrf_token": token})
    token = get_csrf(app_client, "/login")
    app_client.post("/login", data={"username": bob, "password": "pwd", "csrf_token": token})
    
    # 4. Bob tries to edit Alice's post
    token = get_csrf(app_client, "/")
    r = app_client.post(f"/post/{post_id}/edit", data={
        "title": "Hacked",
        "content": "Bob was here",
        "csrf_token": token
    })
    
    # 5. Assert it is blocked by the IDOR ownership check
    assert r.status_code == 403

# ---------------------------------------------------------
# REGRESSION TEST 4: Path Traversal (Export)
# ---------------------------------------------------------
def test_export_path_traversal(app_client):
    """Ensure malicious usernames cannot escape the data directory during export."""
    malicious_user = "../../../hacker_" + str(time.time())
    
    token = get_csrf(app_client, "/register")
    app_client.post("/register", data={"username": malicious_user, "password": "pwd", "csrf_token": token})
    
    token = get_csrf(app_client, "/login")
    app_client.post("/login", data={"username": malicious_user, "password": "pwd", "csrf_token": token})
    
    # They call the export route
    r = app_client.get("/export")
    assert r.status_code == 200
    
    html = r.data.decode('utf-8')
    
    # The vulnerable app would print a file path containing "data/../../../"
    # The patched app strips the ../ so it just says "data/hacker..."
    assert "data/../" not in html