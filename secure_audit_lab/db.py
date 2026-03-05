import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "app.db"

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  is_private INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY(owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  author_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(post_id) REFERENCES posts(id),
  FOREIGN KEY(author_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);
'''

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    return conn

def init_db():
    conn = get_conn()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()

def seed_admin_if_missing():
    # Deliberately weak: plaintext password + simplistic check
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username='admin'")
        row = cur.fetchone()
        if not row:
            cur.execute(
                "INSERT INTO users(username, password, role) VALUES(?, ?, ?)",
                ("admin", "admin123", "admin")
            )
            conn.commit()
    finally:
        conn.close()

def log_event(event: str, detail: str, created_at: str):
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO audit_logs(event, detail, created_at) VALUES(?, ?, ?)",
            (event, detail, created_at),
        )
        conn.commit()
    finally:
        conn.close()
