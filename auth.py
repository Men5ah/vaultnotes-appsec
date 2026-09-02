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

        # The form only exposes username/email/password to normal users,
        # but the server trusts *any* field present in the POST body,
        # including one the client isn't supposed to be able to send.
        is_admin = request.form.get("is_admin", "0") == "1"

        user = User.create(username, email, password, is_admin=is_admin)
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
