import requests
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from models import Note, User

bp = Blueprint("notes", __name__)


def current_user():
    uid = session.get("user_id")
    return User.get_by_id(uid) if uid else None


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


@bp.route("/")
@login_required
def list_notes():
    user = current_user()
    my_notes = Note.get_by_owner(user.id)
    public_notes = Note.get_public_notes()
    return render_template("notes_list.html", user=user, my_notes=my_notes, public_notes=public_notes)


@bp.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    user = current_user()
    if request.method == "POST":
        title = request.form.get("title", "")
        content = request.form.get("content", "")
        is_public = request.form.get("is_public") == "on"
        Note.create(user.id, title, content, is_public)
        return redirect(url_for("notes.list_notes"))
    return render_template("note_form.html", note=None)


@bp.route("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    # Fetches the note by ID with no check that it belongs to the current
    # user (or is public) -- any authenticated user can view any note by
    # guessing/incrementing the ID.
    note = Note.get_by_id(note_id)
    if not note:
        flash("Note not found.")
        return redirect(url_for("notes.list_notes"))
    return render_template("note_detail.html", note=note)


@bp.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):
    # Same issue as view_note -- no ownership check before allowing edits.
    note = Note.get_by_id(note_id)
    if not note:
        flash("Note not found.")
        return redirect(url_for("notes.list_notes"))

    if request.method == "POST":
        note.title = request.form.get("title", "")
        note.content = request.form.get("content", "")
        note.is_public = request.form.get("is_public") == "on"
        note.save()
        return redirect(url_for("notes.view_note", note_id=note.id))

    return render_template("note_form.html", note=note)


@bp.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    # Same issue again -- no ownership/authorization check.
    note = Note.get_by_id(note_id)
    if note:
        note.delete()
    return redirect(url_for("notes.list_notes"))


@bp.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    results = Note.search(query) if query else []
    return render_template("notes_list.html", user=current_user(), my_notes=[], public_notes=results, search_query=query)


@bp.route("/notes/preview", methods=["POST"])
@login_required
def url_preview():
    """
    Fetches a user-supplied URL server-side and returns a short preview
    (used when composing a note that links to something). The server
    performs this fetch with no validation of scheme or destination host,
    so it will happily reach internal/private network addresses or
    non-http(s) schemes.
    """
    url = request.form.get("url", "")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        resp = requests.get(url, timeout=5)
        snippet = resp.text[:500]
        return jsonify({"status": resp.status_code, "snippet": snippet})
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 400
