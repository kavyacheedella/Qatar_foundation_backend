import sqlite3
from datetime import timedelta
from functools import wraps

from flask import (
    Blueprint, request, jsonify,
    session, current_app, g
)

from config import Config
from models import Admin, Opportunity, PasswordResetToken


routes = Blueprint("routes", __name__)


# Database connection (per-request via Flask g)

def get_db():
   
    if "db" not in g:
        g.db = sqlite3.connect(Config.DATABASE_URI)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@routes.teardown_app_request
def close_db(exception=None):
    
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ─────────────────────────────────────────────────────────────
#  Auth decorator
# ─────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            return jsonify({"error": "Unauthorised. Please log in."}), 401
        return f(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────────────
#  Validation helpers
# ─────────────────────────────────────────────────────────────

def _is_valid_email(email: str) -> bool:
    return "@" in email and "." in email.split("@")[-1]


def _require_fields(data: dict, *fields) -> str | None:
 
    missing = [f for f in fields if not (data.get(f) or "").strip()]
    if missing:
        return f"The following fields are required: {', '.join(missing)}."
    return None


# ─────────────────────────────────────────────────────────────
#  Auth routes
# ─────────────────────────────────────────────────────────────

@routes.post("/api/signup")
def signup():
    data    = request.get_json(force=True) or {}
    name    = (data.get("name")             or "").strip()
    email   = (data.get("email")            or "").strip()
    pw      = (data.get("password")         or "")
    confirm = (data.get("confirm_password") or "")

    # Validate
    if not all([name, email, pw, confirm]):
        return jsonify({"error": "All fields are required."}), 400

    if not _is_valid_email(email):
        return jsonify({"error": "Please enter a valid email address."}), 400

    if len(pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    if pw != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    db = get_db()

    # Check for duplicate email
    if Admin.find_by_email(db, email):
        return jsonify({"error": "An account with this email already exists."}), 409

    Admin.create(db, name, email, pw)
    return jsonify({"message": "Account created successfully."}), 201


@routes.post("/api/login")
def login():
    data        = request.get_json(force=True) or {}
    email       = (data.get("email")    or "").strip()
    password    = (data.get("password") or "")
    remember_me = bool(data.get("remember_me", False))

    db    = get_db()
    admin = Admin.verify_password(db, email, password)

    if not admin:
        return jsonify({"error": "Invalid email or password."}), 401

    # Set session
    session.permanent = remember_me
    if remember_me:
        current_app.permanent_session_lifetime = timedelta(days=Config.REMEMBER_ME_DAYS)

    session["admin_id"]    = admin["id"]
    session["admin_email"] = admin["email"]
    session["admin_name"]  = admin["name"]

    return jsonify({
        "message": "Login successful.",
        "name":    admin["name"],
        "email":   admin["email"],
    })


@routes.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"message": "Signed out successfully."})


@routes.get("/api/me")
def me():

    if "admin_id" not in session:
        return jsonify({"logged_in": False})

    return jsonify({
        "logged_in": True,
        "name":      session["admin_name"],
        "email":     session["admin_email"],
    })


@routes.post("/api/forgot-password")
def forgot_password():
    data  = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()

  
    generic_message = "If this email is registered, a reset link has been sent."

    db    = get_db()
    admin = Admin.find_by_email(db, email)

    if admin:
        token      = PasswordResetToken.create(db, admin["id"])
        reset_link = f"http://localhost:5000/api/reset-password?token={token}"
      
        current_app.logger.info("PASSWORD RESET LINK (%s) → %s", email, reset_link)

    return jsonify({"message": generic_message})


@routes.route("/api/reset-password", methods=["GET", "POST"])
def reset_password():
    db = get_db()

    if request.method == "GET":
        token = request.args.get("token", "")
        row   = PasswordResetToken.find_valid(db, token)
        if not row:
            return "This reset link has expired or is invalid.", 400
        return (
            "<p>Token is valid. Send a POST request to this URL with "
            "{ \"token\": \"...\", \"new_password\": \"...\" } to set a new password.</p>"
        )

    # POST — actually update the password
    data         = request.get_json(force=True) or {}
    token        = (data.get("token")        or "").strip()
    new_password = (data.get("new_password") or "")

    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    row = PasswordResetToken.find_valid(db, token)
    if not row:
        return jsonify({"error": "This reset link has expired or is invalid."}), 400

    Admin.update_password(db, row["admin_id"], new_password)
    PasswordResetToken.mark_used(db, row["id"])

    return jsonify({"message": "Password updated successfully."})


# ─────────────────────────────────────────────────────────────
#  Opportunity routes
# ─────────────────────────────────────────────────────────────

REQUIRED_OPP_FIELDS = (
    "name", "duration", "start_date", "description",
    "skills", "category", "future_opportunities"
)


@routes.get("/api/opportunities")
@login_required
def get_opportunities():
    db   = get_db()
    opps = Opportunity.get_all_for_admin(db, session["admin_id"])
    return jsonify(opps)


@routes.post("/api/opportunities")
@login_required
def create_opportunity():
    data  = request.get_json(force=True) or {}
    error = _require_fields(data, *REQUIRED_OPP_FIELDS)
    if error:
        return jsonify({"error": error}), 400

    db  = get_db()
    opp = Opportunity.create(db, session["admin_id"], data)
    return jsonify(opp), 201


@routes.put("/api/opportunities/<int:opp_id>")
@login_required
def update_opportunity(opp_id):
    db = get_db()

    # Make sure this opportunity belongs to the logged-in admin
    if not Opportunity.belongs_to_admin(db, opp_id, session["admin_id"]):
        return jsonify({"error": "Opportunity not found or access denied."}), 404

    data  = request.get_json(force=True) or {}
    error = _require_fields(data, *REQUIRED_OPP_FIELDS)
    if error:
        return jsonify({"error": error}), 400

    opp = Opportunity.update(db, opp_id, data)
    return jsonify(opp)


@routes.delete("/api/opportunities/<int:opp_id>")
@login_required
def delete_opportunity(opp_id):
    db = get_db()

    if not Opportunity.belongs_to_admin(db, opp_id, session["admin_id"]):
        return jsonify({"error": "Opportunity not found or access denied."}), 404

    Opportunity.delete(db, opp_id)
    return jsonify({"message": "Opportunity deleted successfully."})
