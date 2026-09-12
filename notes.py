from os import abort
from urllib.parse import urlparse
import socket
import ipaddress

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
    note = Note.get_by_id(note_id)

    if not note:
        flash("Note not found.")
        return redirect(url_for("notes.list_notes"))

    if not (note.is_public or note.owner_id == current_user().id):
        flash("You do not have permission to view this note.")
        return redirect(url_for("notes.list_notes"))

    return render_template("note_detail.html", note=note, user=current_user())


@bp.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):

    note = Note.get_by_id(note_id)

    if not note:
        flash("Note not found.")
        return redirect(url_for("notes.list_notes"))

    if current_user().id != note.owner_id:
        flash("You do not have permission to edit this note.")
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

    note = Note.get_by_id(note_id)
    if not note:
        flash("Note not found.")
        return redirect(url_for("notes.list_notes"))

    if current_user().id != note.owner_id:
        flash("You do not have permission to delete this note.")
        return redirect(url_for("notes.list_notes"))
    
    if note:
        note.delete()
    return redirect(url_for("notes.list_notes"))


@bp.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    results = Note.search(query) if query else []
    return render_template("notes_list.html", user=current_user(), my_notes=[], public_notes=results, search_query=query)


def safe_url(url):
    """
    Check if the URL is safe to fetch. This function checks if the URL is using HTTP or HTTPS,
    and ensures that it does not resolve to a private or loopback IP address.
    """
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        return False

    try:
        ip = socket.gethostbyname(parsed_url.hostname)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False
    except Exception:
        return False

    return True

@bp.route("/notes/preview", methods=["POST"])
@login_required
def url_preview():
    """
    Fetches a user-supplied URL server-side and returns a short preview
    (used when composing a note that links to something). The server
    will only fetch URLs that are considered safe.
    """
    url = request.form.get("url", "")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not safe_url(url):
        return jsonify({"error": "Unsafe URL"}), 400
    try:
        resp = requests.get(url, timeout=5)
        snippet = resp.text[:500]
        return jsonify({"status": resp.status_code, "snippet": snippet})
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 400
