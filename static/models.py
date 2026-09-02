from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db


class User:
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]
        self.password_hash = row["password_hash"]
        self.is_admin = bool(row["is_admin"])
        self.created_at = row["created_at"]

    @staticmethod
    def get_by_id(user_id):
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return User(row) if row else None

    @staticmethod
    def get_by_username(username):
        db = get_db()
        row = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return User(row) if row else None

    @staticmethod
    def get_all():
        db = get_db()
        rows = db.execute("SELECT * FROM users ORDER BY id").fetchall()
        return [User(r) for r in rows]

    @staticmethod
    def create(username, email, password, is_admin=False):
        db = get_db()
        pw_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
            (username, email, pw_hash, int(is_admin)),
        )
        db.commit()
        return User.get_by_username(username)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def delete(self):
        db = get_db()
        db.execute("DELETE FROM notes WHERE owner_id = ?", (self.id,))
        db.execute("DELETE FROM users WHERE id = ?", (self.id,))
        db.commit()


class Note:
    def __init__(self, row):
        self.id = row["id"]
        self.owner_id = row["owner_id"]
        self.title = row["title"]
        self.content = row["content"]
        self.is_public = bool(row["is_public"])
        self.created_at = row["created_at"]

    @staticmethod
    def get_by_id(note_id):
        db = get_db()
        row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
        return Note(row) if row else None

    @staticmethod
    def get_public_notes():
        db = get_db()
        rows = db.execute(
            "SELECT * FROM notes WHERE is_public = 1 ORDER BY created_at DESC"
        ).fetchall()
        return [Note(r) for r in rows]

    @staticmethod
    def get_by_owner(user_id):
        db = get_db()
        rows = db.execute(
            "SELECT * FROM notes WHERE owner_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [Note(r) for r in rows]

    @staticmethod
    def get_all():
        db = get_db()
        rows = db.execute("SELECT * FROM notes ORDER BY created_at DESC").fetchall()
        return [Note(r) for r in rows]

    @staticmethod
    def search(query):
        db = get_db()
        # search across title/content, most-recent first
        sql = (
            "SELECT * FROM notes WHERE (title LIKE '%"
            + query
            + "%' OR content LIKE '%"
            + query
            + "%') ORDER BY created_at DESC"
        )
        rows = db.execute(sql).fetchall()
        return [Note(r) for r in rows]

    @staticmethod
    def create(owner_id, title, content, is_public=False):
        db = get_db()
        db.execute(
            "INSERT INTO notes (owner_id, title, content, is_public) VALUES (?, ?, ?, ?)",
            (owner_id, title, content, int(is_public)),
        )
        db.commit()

    def save(self):
        db = get_db()
        db.execute(
            "UPDATE notes SET title = ?, content = ?, is_public = ? WHERE id = ?",
            (self.title, self.content, int(self.is_public), self.id),
        )
        db.commit()

    def delete(self):
        db = get_db()
        db.execute("DELETE FROM notes WHERE id = ?", (self.id,))
        db.commit()
