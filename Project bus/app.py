from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, date
import sqlite3
import secrets

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)

DB_PATH = INSTANCE_DIR / "college_buses.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "CHANGE-THIS-TO-A-LONG-RANDOM-SECRET"

REASONS = [
    "Vehicle breakdown",
    "Driver unavailable",
    "Scheduled maintenance",
    "Weather conditions",
    "Route obstruction",
    "College instruction",
    "Other"
]

SAMPLE_ROUTES = [
    ("R01", "Tiruvottiyur", "North Chennai", 13.1592, 80.3000),
    ("R02", "Avadi", "West Chennai", 13.1147, 80.1018),
    ("R03", "Tambaram", "South Chennai", 12.9249, 80.1000),
    ("R04", "Ambattur", "West Chennai", 13.1143, 80.1548),
    ("R05", "Poonamallee", "West Chennai", 13.0480, 80.0950),
    ("R06", "Madhavaram", "North Chennai", 13.1489, 80.2314),
    ("R07", "Perambur", "North Chennai", 13.1185, 80.2326),
    ("R08", "Porur", "West Chennai", 13.0358, 80.1588),
    ("R09", "Velachery", "South Chennai", 12.9750, 80.2212),
    ("R10", "Red Hills", "North Chennai", 13.1860, 80.2000),
    ("R11", "Guindy", "Central Chennai", 13.0067, 80.2206),
    ("R12", "Thirumullaivoyal", "West Chennai", 13.1270, 80.1300)
]


@contextmanager
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    with get_db() as db:

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS routes (
                id TEXT PRIMARY KEY,
                destination TEXT NOT NULL,
                area TEXT NOT NULL,
                lat REAL,
                lon REAL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS cancellations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                route_id TEXT NOT NULL,
                cancel_date TEXT NOT NULL,
                reason TEXT NOT NULL,
                note TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY(route_id) REFERENCES routes(id)
            )
        """)

        admin = db.execute(
            "SELECT id FROM users WHERE username = ?",
            ("admin",)
        ).fetchone()

        if not admin:
            db.execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                ("admin", generate_password_hash("admin123"))
            )

        count = db.execute(
            "SELECT COUNT(*) AS total FROM routes"
        ).fetchone()["total"]

        if count == 0:
            db.executemany("""
                INSERT INTO routes(id, destination, area, lat, lon)
                VALUES (?, ?, ?, ?, ?)
            """, SAMPLE_ROUTES)


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


def valid_csrf():
    return request.form.get("csrf_token") == session.get("csrf_token")


@app.context_processor
def inject_csrf():
    return {"csrf_token": session.get("csrf_token", "")}


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["csrf_token"] = secrets.token_hex(24)

            return redirect(url_for("dashboard"))

        flash("Incorrect username or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():

    if not valid_csrf():
        return "Invalid request token", 400

    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():

    today = date.today().isoformat()

    with get_db() as db:

        total_routes = db.execute(
            "SELECT COUNT(*) AS n FROM routes"
        ).fetchone()["n"]

        cancelled_today = db.execute("""
            SELECT COUNT(DISTINCT route_id) AS n
            FROM cancellations
            WHERE cancel_date = ?
        """, (today,)).fetchone()["n"]

        total_notices = db.execute(
            "SELECT COUNT(*) AS n FROM cancellations"
        ).fetchone()["n"]

        recent = db.execute("""
            SELECT c.id, c.cancel_date, c.reason,
                   r.id AS route_code, r.destination
            FROM cancellations c
            JOIN routes r ON r.id = c.route_id
            ORDER BY c.created_at DESC
            LIMIT 6
        """).fetchall()

        routes = db.execute(
            "SELECT * FROM routes ORDER BY id"
        ).fetchall()

    return render_template(
        "dashboard.html",
        total_routes=total_routes,
        cancelled_today=cancelled_today,
        total_notices=total_notices,
        recent=recent,
        routes=routes
    )


@app.route("/manage", methods=["GET", "POST"])
@login_required
def manage():

    if request.method == "POST":

        if not valid_csrf():
            return "Invalid request token", 400

        route_id = request.form.get("route_id", "")
        cancel_date = request.form.get("cancel_date", "")
        reason = request.form.get("reason", "")
        note = request.form.get("note", "").strip()

        try:
            datetime.strptime(cancel_date, "%Y-%m-%d")
        except ValueError:
            flash("Choose a valid date.", "error")
            return redirect(url_for("manage"))

        if reason not in REASONS:
            flash("Choose a valid reason.", "error")
            return redirect(url_for("manage"))

        if reason == "Other" and not note:
            flash("Please enter an additional note.", "error")
            return redirect(url_for("manage"))

        with get_db() as db:

            route = db.execute(
                "SELECT id FROM routes WHERE id = ?",
                (route_id,)
            ).fetchone()

            if not route:
                flash("Choose a valid bus route.", "error")
                return redirect(url_for("manage"))

            db.execute("""
                INSERT INTO cancellations
                (route_id, cancel_date, reason, note, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                route_id,
                cancel_date,
                reason,
                note,
                datetime.now().isoformat(timespec="seconds")
            ))

        flash("Cancellation notice saved successfully.", "success")
        return redirect(url_for("manage"))

    with get_db() as db:

        routes = db.execute(
            "SELECT * FROM routes ORDER BY id"
        ).fetchall()

        history = db.execute("""
            SELECT c.*, r.destination
            FROM cancellations c
            JOIN routes r ON r.id = c.route_id
            ORDER BY c.cancel_date DESC, c.id DESC
            LIMIT 30
        """).fetchall()

    return render_template(
        "manage.html",
        routes=routes,
        history=history,
        reasons=REASONS
    )


@app.route("/calendar")
@login_required
def calendar_page():
    return render_template("calendar.html")


@app.route("/api/calendar")
@login_required
def calendar_api():

    month = request.args.get("month", "")

    try:
        datetime.strptime(month, "%Y-%m")
    except ValueError:
        return jsonify({"error": "Invalid month"}), 400

    with get_db() as db:
        rows = db.execute("""
            SELECT cancel_date, COUNT(*) AS count
            FROM cancellations
            WHERE substr(cancel_date, 1, 7) = ?
            GROUP BY cancel_date
        """, (month,)).fetchall()

    return jsonify({
        row["cancel_date"]: row["count"]
        for row in rows
    })


@app.route("/api/cancellations/<cancel_date>")
@login_required
def cancellations_for_date(cancel_date):

    try:
        datetime.strptime(cancel_date, "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": "Invalid date"}), 400

    with get_db() as db:
        rows = db.execute("""
            SELECT r.id AS route_code,
                   r.destination,
                   c.reason,
                   c.note
            FROM cancellations c
            JOIN routes r ON r.id = c.route_id
            WHERE c.cancel_date = ?
            ORDER BY r.id
        """, (cancel_date,)).fetchall()

    return jsonify([dict(row) for row in rows])


@app.route("/api/routes")
@login_required
def routes_api():

    with get_db() as db:
        rows = db.execute("""
            SELECT id, destination, area, lat, lon
            FROM routes
            ORDER BY id
        """).fetchall()

    return jsonify([dict(row) for row in rows])


@app.route("/restore/<int:cancellation_id>", methods=["POST"])
@login_required
def restore(cancellation_id):

    if not valid_csrf():
        return "Invalid request token", 400

    with get_db() as db:
        db.execute(
            "DELETE FROM cancellations WHERE id = ?",
            (cancellation_id,)
        )

    flash("Cancellation record removed.", "success")
    return redirect(url_for("manage"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
