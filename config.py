import os
import secrets


class Config:
    # ── Security ──────────────────────────────────────────────
  
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    # ── Database ──────────────────────────────────────────────

    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_URI = os.environ.get(
        "DATABASE_URI",
        os.path.join(BASE_DIR, "qatar_foundation.db")
    )

    # ── Session ───────────────────────────────────────────────
    # How many days a "Remember Me" session stays alive
    REMEMBER_ME_DAYS = 30

    # ── Password reset ────────────────────────────────────────
    # How many hours before a reset token expires
    RESET_TOKEN_EXPIRY_HOURS = 1

    # ── Flask debug ───────────────────────────────────────────
    DEBUG = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
