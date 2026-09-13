from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from models import User
import time

bp = Blueprint("auth", __name__)

failed_attempts = {}  # Dictionary to track failed login attempts per username
locked_until = {}  # Dictionary to track lockout time for each username


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.")
            return render_template("register.html")

        if User.get_by_username(username):
            flash("Username already taken.")
            return render_template("register.html")

        # Removed the is_admin field from the registration form, so all new users are created as non-admins by default.

        # Preventing a privilege escalation vulnerability where a user could register as an admin by manipulating the form data via browser developer tools or a custom HTTP request.

        user = User.create(username, email, password, is_admin=False)
        session["user_id"] = user.id
        return redirect(url_for("notes.list_notes"))

    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username in locked_until and time.time() < locked_until[username]:
            flash("Account is locked. Please try again later.")
            return render_template("login.html")

        # No lockout / rate limiting on repeated failed attempts here,
        # so this endpoint can be brute-forced or credential-stuffed
        # without any friction.
        user = User.get_by_username(username)
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["is_admin"] = user.is_admin
            if username in failed_attempts:
                del failed_attempts[username]  # Reset failed attempts on successful login
            if username in locked_until:
                del locked_until[username]  # Remove lockout if it exists
            return redirect(url_for("notes.list_notes"))

        # Track failed login attempts
        if username not in failed_attempts:
            failed_attempts[username] = 0
        failed_attempts[username] += 1

        if failed_attempts[username] > 4:
            locked_until[username] = time.time() + 300  # Lock out for 5 minutes
            flash("Too many failed login attempts. Please try again later.")
            return render_template("login.html")

        flash("Invalid username or password.")
        return render_template("login.html")

    return render_template("login.html")


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
