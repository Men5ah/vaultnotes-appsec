import os
from flask import Flask
from db import close_db, DB_PATH

def create_app():
    app = Flask(__name__)
    app.secret_key = "dev-secret-key-not-for-production"  # noqa: intentionally weak/static

    app.teardown_appcontext(close_db)

    from auth import bp as auth_bp
    from notes import bp as notes_bp
    from admin import bp as admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(notes_bp)
    app.register_blueprint(admin_bp)

    return app


app = create_app()

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        from db import init_db
        init_db()
    app.run(debug=True, port=5000)
