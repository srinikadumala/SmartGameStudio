from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

# Secret key for sessions
app.secret_key = "smart-game-studio-secret-key"


# ============================================================
# DATABASE
# ============================================================

DATABASE = os.path.join(
    os.path.dirname(__file__),
    "database",
    "smart_game_studio.db"
)


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():

    # Make sure database folder exists
    os.makedirs(
        os.path.dirname(DATABASE),
        exist_ok=True
    )

    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# HOME / LANDING PAGE
# ============================================================

@app.route("/")
def index():
    """
    Main SmartGame Studio landing page.

    IMPORTANT:
    This is NOT the login page.

    When the user visits:
        http://127.0.0.1:5000/

    Flask will show home.html.
    """

    return render_template("home.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        # ----------------------------------------------------
        # Validate fields
        # ----------------------------------------------------

        if not email or not password:

            flash(
                "Please enter both email and password.",
                "error"
            )

            return render_template("login.html")


        # ----------------------------------------------------
        # Find user
        # ----------------------------------------------------

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        connection.close()


        # ----------------------------------------------------
        # Check password
        # ----------------------------------------------------

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            # Save login information
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]

            # Go to dashboard
            return redirect(
                url_for("dashboard")
            )


        # ----------------------------------------------------
        # Invalid login
        # ----------------------------------------------------

        flash(
            "Invalid email or password.",
            "error"
        )

    return render_template("login.html")


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        # ----------------------------------------------------
        # Check empty fields
        # ----------------------------------------------------

        if (
            not username
            or not email
            or not password
            or not confirm_password
        ):

            flash(
                "Please fill in all fields.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # ----------------------------------------------------
        # Username validation
        # ----------------------------------------------------

        if len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # ----------------------------------------------------
        # Password validation
        # ----------------------------------------------------

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # ----------------------------------------------------
        # Confirm password
        # ----------------------------------------------------

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # ----------------------------------------------------
        # Check existing email
        # ----------------------------------------------------

        connection = get_db()

        existing_user = connection.execute(
            """
            SELECT id
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()


        if existing_user:

            connection.close()

            flash(
                "An account with this email already exists.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # ----------------------------------------------------
        # Hash password
        # ----------------------------------------------------

        password_hash = generate_password_hash(
            password
        )


        # ----------------------------------------------------
        # Create account
        # ----------------------------------------------------

        connection.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password_hash
            )
            VALUES (?, ?, ?)
            """,
            (
                username,
                email,
                password_hash
            )
        )

        connection.commit()
        connection.close()


        # ----------------------------------------------------
        # Registration successful
        # ----------------------------------------------------

        flash(
            "Account created successfully! Please sign in.",
            "success"
        )

        return redirect(
            url_for("login")
        )


    return render_template(
        "register.html"
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    # --------------------------------------------------------
    # User must be logged in
    # --------------------------------------------------------

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    # --------------------------------------------------------
    # Show dashboard
    # --------------------------------------------------------

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        email=session.get("email")
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    # Clear session
    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    # Create database and users table
    init_database()

    # Start Flask
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )