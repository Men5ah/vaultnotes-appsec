from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from models import User

bp = Blueprint("auth", __name__)


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

        # No lockout / rate limiting on repeated failed attempts here,
        # so this endpoint can be brute-forced or credential-stuffed
        # without any friction.
        user = User.get_by_username(username)
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["is_admin"] = user.is_admin
            return redirect(url_for("notes.list_notes"))

        flash("Invalid username or password.")
        return render_template("login.html")

    return render_template("login.html")


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
