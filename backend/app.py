"""
VULNERABLE BACKEND APP
======================
This app is INTENTIONALLY broken. Do not deploy it anywhere real.
It exists purely as a target for the WAF project.

Flaws baked in on purpose:
  1. /login   -> raw SQL string concatenation (classic SQL injection)
  2. /search  -> unescaped output into HTML (reflected XSS)
  3. /file    -> unsanitized path join (path traversal)

Run directly on port 5000 (no WAF) to prove the exploits work first
(Phase 1 of the project). Later you'll route traffic through the WAF
proxy instead of hitting this directly.
"""
import sqlite3
import os
from flask import Flask, request, g, render_template_string

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "vulnerable.db")
FILES_DIR = os.path.join(APP_DIR, "public_files")
SECRET_DIR = os.path.join(APP_DIR, "secret_files")

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(FILES_DIR, exist_ok=True)
    os.makedirs(SECRET_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    conn.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("alice", "alice123", "user"),
            ("bob", "hunter2", "user"),
            ("admin", "S3cur3AdminPW!", "admin"),
        ],
    )
    conn.commit()
    conn.close()

    # public files (legitimate use of /file)
    with open(os.path.join(FILES_DIR, "welcome.txt"), "w") as f:
        f.write("Welcome to the vulnerable file viewer demo.\n")
    with open(os.path.join(FILES_DIR, "notes.txt"), "w") as f:
        f.write("Nothing interesting here, move along.\n")

    # a "secret" file OUTSIDE the public_files dir, reachable only via traversal
    with open(os.path.join(SECRET_DIR, "flag.txt"), "w") as f:
        f.write("FLAG{path_traversal_pwned_the_backend}\n")


INDEX_HTML = """
<!doctype html>
<html><head><title>Vulnerable Demo App</title>
<style>body{font-family:sans-serif;max-width:700px;margin:40px auto}
input{padding:6px;margin:4px 0}code{background:#eee;padding:2px 4px}</style>
</head><body>
<h2>Vulnerable Demo App</h2>
<p>This app is deliberately insecure. Use it as a WAF target only.</p>

<h3>1. Login (SQL Injection)</h3>
<form action="/login" method="get">
  Username: <input name="username" value="alice"><br>
  Password: <input name="password" value="alice123"><br>
  <button type="submit">Login</button>
</form>
<p>Try: <code>username=admin'--&password=x</code></p>

<h3>2. Search (Reflected XSS)</h3>
<form action="/search" method="get">
  Query: <input name="q" value="hello"><br>
  <button type="submit">Search</button>
</form>
<p>Try: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p>

<h3>3. File viewer (Path Traversal)</h3>
<form action="/file" method="get">
  Filename: <input name="name" value="welcome.txt"><br>
  <button type="submit">View</button>
</form>
<p>Try: <code>../secret_files/flag.txt</code></p>
</body></html>
"""


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # VULNERABLE: raw string concatenation, classic SQLi
    query = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{password}'"
    db = get_db()
    try:
        cur = db.execute(query)
        row = cur.fetchone()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"SQL error: {e}", "query_used": query}, 500

    if row:
        return {"ok": True, "message": "Login successful", "user_id": row[0],
                "username": row[1], "role": row[2], "query_used": query}
    return {"ok": False, "message": "Invalid credentials", "query_used": query}, 401


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: q is dropped straight into HTML, unescaped
    return render_template_string(
        "<html><body><h3>Search results for: " + q + "</h3><p>No results found.</p></body></html>"
    )


@app.route("/file")
def file_view():
    name = request.args.get("name", "welcome.txt")
    # VULNERABLE: naive join, no path sanitization -> traversal via ../
    path = os.path.join(FILES_DIR, name)
    try:
        with open(path, "r") as f:
            content = f.read()
        return {"ok": True, "path_used": path, "content": content}
    except Exception as e:
        return {"ok": False, "path_used": path, "error": str(e)}, 404


@app.route("/health")
def health():
    return {"status": "up", "service": "vulnerable-backend"}


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    else:
        init_db()  # reset fresh each run for repeatable demos
    print("Vulnerable backend running on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
