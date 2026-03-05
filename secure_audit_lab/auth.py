from dataclasses import dataclass
from typing import Optional
from flask import request
from flask import session
from db import get_conn

@dataclass
class User:
    id: int
    username: str
    role: str

def current_user() -> Optional[User]:
    # VULNERABLE SESSION DESIGN:
    # The app trusts a forgeable cookie to determine identity.
    # Cookie format: USER_ID=<int>, e.g., "2"
    # user_cookie = request.cookies.get("USER_ID")
    # if not user_cookie:
    #     return None
    # try:
    #     uid = int(user_cookie)
    # except ValueError:
    #     return None

    # FIX: Use Flask's signed session instead of raw cookie
    uid = session.get("user_id")
    if not uid:
        return None

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, username, role FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
        if not row:
            return None
        return User(id=row[0], username=row[1], role=row[2])
    finally:
        conn.close()

def is_admin(u: Optional[User]) -> bool:
    return bool(u) and u.role == "admin"
