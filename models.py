import hashlib
import secrets
from datetime import datetime, timedelta

from config import Config



# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _row_to_dict(row) -> dict:
    return dict(row) if row else None


# ─────────────────────────────────────────────────────────────
#  Admin model
# ─────────────────────────────────────────────────────────────

class Admin:
    TABLE = "admins"

    @staticmethod
    def create_table(conn):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                name     TEXT    NOT NULL,
                email    TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL,
                created  TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.commit()

    # ── Queries ───────────────────────────────────────────────

    @staticmethod
    def find_by_email(conn, email: str) -> dict | None:
        row = conn.execute(
            "SELECT * FROM admins WHERE email = ?", (email.lower().strip(),)
        ).fetchone()
        return _row_to_dict(row)

    @staticmethod
    def find_by_id(conn, admin_id: int) -> dict | None:
        row = conn.execute(
            "SELECT * FROM admins WHERE id = ?", (admin_id,)
        ).fetchone()
        return _row_to_dict(row)

    @staticmethod
    def create(conn, name: str, email: str, password: str) -> dict:
       
        conn.execute(
            "INSERT INTO admins (name, email, password) VALUES (?, ?, ?)",
            (name.strip(), email.lower().strip(), _hash_password(password))
        )
        conn.commit()
        return Admin.find_by_email(conn, email)

    @staticmethod
    def verify_password(conn, email: str, password: str) -> dict | None:
       
        row = conn.execute(
            "SELECT * FROM admins WHERE email = ? AND password = ?",
            (email.lower().strip(), _hash_password(password))
        ).fetchone()
        return _row_to_dict(row)

    @staticmethod
    def update_password(conn, admin_id: int, new_password: str):
        conn.execute(
            "UPDATE admins SET password = ? WHERE id = ?",
            (_hash_password(new_password), admin_id)
        )
        conn.commit()


# ─────────────────────────────────────────────────────────────
#  PasswordResetToken model
# ─────────────────────────────────────────────────────────────

class PasswordResetToken:
    TABLE = "password_reset_tokens"

    @staticmethod
    def create_table(conn):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id   INTEGER NOT NULL REFERENCES admins(id),
                token      TEXT    NOT NULL UNIQUE,
                expires_at TEXT    NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()

    @staticmethod
    def create(conn, admin_id: int) -> str:
        """Generate a new token, store it, and return the token string."""
        token      = secrets.token_urlsafe(32)
        expires_at = (
            datetime.utcnow() + timedelta(hours=Config.RESET_TOKEN_EXPIRY_HOURS)
        ).isoformat()
        conn.execute(
            "INSERT INTO password_reset_tokens (admin_id, token, expires_at) VALUES (?, ?, ?)",
            (admin_id, token, expires_at)
        )
        conn.commit()
        return token

    @staticmethod
    def find_valid(conn, token: str) -> dict | None:
        """Return the token record only if it exists, is unused, and has not expired."""
        row = conn.execute(
            "SELECT * FROM password_reset_tokens WHERE token = ? AND used = 0",
            (token,)
        ).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            return None
        return _row_to_dict(row)

    @staticmethod
    def mark_used(conn, token_id: int):
        conn.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (token_id,)
        )
        conn.commit()


# ─────────────────────────────────────────────────────────────
#  Opportunity model
# ─────────────────────────────────────────────────────────────

class Opportunity:
    TABLE = "opportunities"

    @staticmethod
    def create_table(conn):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS opportunities (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id             INTEGER NOT NULL REFERENCES admins(id),
                name                 TEXT    NOT NULL,
                duration             TEXT    NOT NULL,
                start_date           TEXT    NOT NULL,
                description          TEXT    NOT NULL,
                skills               TEXT    NOT NULL,
                category             TEXT    NOT NULL,
                future_opportunities TEXT    NOT NULL,
                max_applicants       INTEGER,
                created              TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.commit()

    # ── Serialisation ─────────────────────────────────────────

    @staticmethod
    def to_dict(row) -> dict:
        
        d = _row_to_dict(row)
        if d and isinstance(d.get("skills"), str):
            d["skills"] = [s.strip() for s in d["skills"].split(",") if s.strip()]
        return d

    # ── Queries ───────────────────────────────────────────────

    @staticmethod
    def get_all_for_admin(conn, admin_id: int) -> list[dict]:
        rows = conn.execute(
            "SELECT * FROM opportunities WHERE admin_id = ? ORDER BY created DESC",
            (admin_id,)
        ).fetchall()
        return [Opportunity.to_dict(r) for r in rows]

    @staticmethod
    def get_by_id(conn, opp_id: int) -> dict | None:
        row = conn.execute(
            "SELECT * FROM opportunities WHERE id = ?", (opp_id,)
        ).fetchone()
        return Opportunity.to_dict(row) if row else None

    @staticmethod
    def create(conn, admin_id: int, data: dict) -> dict:
        """
        Insert a new opportunity and return the full record.
        `data` must contain: name, duration, start_date, description,
                             skills (string), category, future_opportunities
        Optional: max_applicants
        """
        skills = ",".join(
            s.strip() for s in data["skills"].split(",") if s.strip()
        )
        max_app = data.get("max_applicants")
        if max_app is not None:
            try:
                max_app = int(max_app)
            except (ValueError, TypeError):
                max_app = None

        cursor = conn.execute(
            """INSERT INTO opportunities
               (admin_id, name, duration, start_date, description, skills,
                category, future_opportunities, max_applicants)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                admin_id,
                data["name"].strip(),
                data["duration"].strip(),
                data["start_date"].strip(),
                data["description"].strip(),
                skills,
                data["category"].strip(),
                data["future_opportunities"].strip(),
                max_app,
            )
        )
        conn.commit()
        return Opportunity.get_by_id(conn, cursor.lastrowid)

    @staticmethod
    def update(conn, opp_id: int, data: dict) -> dict:
        """Update an existing opportunity and return the updated record."""
        skills = ",".join(
            s.strip() for s in data["skills"].split(",") if s.strip()
        )
        max_app = data.get("max_applicants")
        if max_app is not None:
            try:
                max_app = int(max_app)
            except (ValueError, TypeError):
                max_app = None

        conn.execute(
            """UPDATE opportunities SET
               name = ?, duration = ?, start_date = ?, description = ?,
               skills = ?, category = ?, future_opportunities = ?, max_applicants = ?
               WHERE id = ?""",
            (
                data["name"].strip(),
                data["duration"].strip(),
                data["start_date"].strip(),
                data["description"].strip(),
                skills,
                data["category"].strip(),
                data["future_opportunities"].strip(),
                max_app,
                opp_id,
            )
        )
        conn.commit()
        return Opportunity.get_by_id(conn, opp_id)

    @staticmethod
    def delete(conn, opp_id: int):
        conn.execute("DELETE FROM opportunities WHERE id = ?", (opp_id,))
        conn.commit()

    @staticmethod
    def belongs_to_admin(conn, opp_id: int, admin_id: int) -> bool:
        """Return True only if this opportunity was created by the given admin."""
        row = conn.execute(
            "SELECT 1 FROM opportunities WHERE id = ? AND admin_id = ?",
            (opp_id, admin_id)
        ).fetchone()
        return row is not None
