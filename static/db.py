import sqlite3
import os
from flask import g

DB_PATH = os.path.join(os.path.dirname(__file__), "vaultnotes.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    from werkzeug.security import generate_password_hash

    conn = sqlite3.connect(DB_PATH)
    with open(os.path.join(os.path.dirname(__file__), "schema.sql")) as f:
        conn.executescript(f.read())

    # Seed users. NOTE: passwords are hashed here (using werkzeug) for
    # convenience of standing the app up, but see models.py / auth.py --
    # the *login/verification* path has its own issues, documented separately.
    users = [
        ("admin", "admin@vaultnotes.local", "AdminPass123!", 1),
        ("alice", "alice@vaultnotes.local", "AlicePass123!", 0),
        ("bob", "bob@vaultnotes.local", "BobPass123!", 0),
    ]
    for username, email, pw, is_admin in users:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
            (username, email, generate_password_hash(pw), is_admin),
        )

    # Seed notes
    conn.execute(
        "INSERT INTO notes (owner_id, title, content, is_public) VALUES (1, ?, ?, 1)",
        ("Welcome", "Welcome to VaultNotes. This is a public admin note."),
    )
    conn.execute(
        "INSERT INTO notes (owner_id, title, content, is_public) VALUES (2, ?, ?, 0)",
        ("Alice's private thoughts", "Bob owes me $20. Don't tell anyone."),
    )
    conn.execute(
        "INSERT INTO notes (owner_id, title, content, is_public) VALUES (3, ?, ?, 1)",
        ("Bob's public note", "Check out my favorite recipe site!"),
    )
    conn.commit()
    conn.close()
    print(f"Initialized database at {DB_PATH}")
    print("Seed users: admin/AdminPass123!, alice/AlicePass123!, bob/BobPass123!")


if __name__ == "__main__":
    init_db()
