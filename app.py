import sqlite3

from flask import Flask, send_from_directory
from flask_cors import CORS

from .config import Config
from .models import Admin, Opportunity, PasswordResetToken
from routes import routes


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    # ── Load configuration ─────────────────────────────────────
    app.secret_key = Config.SECRET_KEY
    app.debug      = Config.DEBUG
    CORS(app, supports_credentials=True)

    # ── Initialize database tables ────────────────────────────
    _init_db()

    # ── Register all routes ───────────────────────────────────
    app.register_blueprint(routes)

    # ── Serve the frontend HTML ───────────────────────────────
    @app.route("/")
    def index():
     
        return send_from_directory(app.template_folder, "admin.html")

    return app


def _init_db():
    
    conn = sqlite3.connect(Config.DATABASE_URI)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    Admin.create_table(conn)
    PasswordResetToken.create_table(conn)
    Opportunity.create_table(conn)

    conn.close()


# ─────────────────────────────────────────────────────────────
#  Run
# ─────────────────────────────────────────────────────────────
app = create_app()
if __name__ == "__main__":
   
    app.run(port=5000)
