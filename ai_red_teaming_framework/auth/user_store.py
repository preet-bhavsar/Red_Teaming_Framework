"""
user_store.py — local user registry backing the RedLens login page's
Sign Up flow.

The project's original auth was a hardcoded in-memory dict (`_USERS` in
login.py) with no persistence and no way to create new accounts. This
module adds a minimal, real (not simulated) registration system:

  * new accounts are written to `auth/users_db.json`, next to this file
  * passwords are never stored in plaintext — each is salted and hashed
    with PBKDF2-HMAC-SHA256 (200k iterations)
  * `_USERS`'s two built-in demo accounts (admin / analyst) still work
    exactly as before and cannot be overwritten by sign-up

This file only handles account storage/validation. It does not touch
session state, redirects, or anything else in dashboard.py.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Optional

_STORE_PATH = Path(__file__).resolve().parent / "users_db.json"

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_MIN_PASSWORD_LEN = 8

# Reserved so a sign-up can't collide with (or shadow) the built-in demo
# accounts defined in login.py.
RESERVED_USERNAMES = {"admin", "analyst"}


def _load() -> dict:
    if not _STORE_PATH.exists():
        return {}
    try:
        with open(_STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    tmp_path = _STORE_PATH.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, _STORE_PATH)  # atomic on POSIX + Windows


def _hash_password(password: str, salt_hex: Optional[str] = None) -> tuple[str, str]:
    salt_hex = salt_hex or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 200_000
    )
    return salt_hex, digest.hex()


def user_exists(username: str) -> bool:
    return username.strip().lower() in _load()


def validate_new_account(username: str, password: str, confirm: str) -> Optional[str]:
    """Return a human-readable error, or None if the signup input is valid."""
    username = username.strip()

    if not username or not password or not confirm:
        return "All fields are required."
    if not _USERNAME_RE.match(username):
        return "Username must be 3-32 characters (letters, numbers, . _ -)."
    if username.lower() in RESERVED_USERNAMES:
        return "That username is reserved. Please choose another."
    if len(password) < _MIN_PASSWORD_LEN:
        return f"Password must be at least {_MIN_PASSWORD_LEN} characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain both letters and numbers."
    if password != confirm:
        return "Passwords do not match."
    if user_exists(username):
        return "That username is already taken."
    return None


def register_user(username: str, password: str) -> None:
    """Create a new account. Caller must run validate_new_account() first."""
    data = _load()
    salt_hex, hashed = _hash_password(password)
    data[username.strip().lower()] = {"salt": salt_hex, "hash": hashed}
    _save(data)


def verify_user(username: str, password: str) -> bool:
    """Check credentials against the persisted (signed-up) user store."""
    record = _load().get(username.strip().lower())
    if not record:
        return False
    _, hashed = _hash_password(password, record["salt"])
    return secrets.compare_digest(hashed, record["hash"])
