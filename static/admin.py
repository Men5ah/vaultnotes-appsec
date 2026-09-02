from functools import wraps
from flask import Blueprint, render_template, session, redirect, url_for, flash
from models import User, Note
from notes import current_user

bp = Blueprint("admin", __name__)


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # Trusts a value stashed in the session at login time rather than
        # re-checking the user's current is_admin flag from the database
        # on every request.
        if not session.get("is_admin"):
            flash("Admin access required.")
            return redirect(url_for("notes.list_notes"))
        return view(*args, **kwargs)

    return wrapped


@bp.route("/admin")
@admin_required
def dashboard():
    users = User.get_all()
    notes = Note.get_all()
    return render_template("admin.html", users=users, notes=notes, user=current_user())


@bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.get_by_id(user_id)
    if user:
        user.delete()
    return redirect(url_for("admin.dashboard"))


@bp.route("/admin/notes/<int:note_id>/delete", methods=["POST"])
@admin_required
def delete_note(note_id):
    note = Note.get_by_id(note_id)
    if note:
        note.delete()
    return redirect(url_for("admin.dashboard"))
