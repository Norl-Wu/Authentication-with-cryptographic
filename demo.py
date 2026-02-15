from flask import Flask, render_template, request, redirect, session, url_for
import bcrypt
import sqlite3
import re
import time
import os
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv("SECRET_KEY")
login_attempts = {}

def init_db():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL
            )
        """)
        conn.commit()

init_db()

def is_blocked(ip):
    now = time.time()

    if ip in login_attempts:
        attempts, last_time = login_attempts[ip]

        if now - last_time > 60:
            login_attempts[ip] = [0, now]
            return False

        if attempts >= 5:
            return True

    return False


def record_attempt(ip):
    now = time.time()

    if ip not in login_attempts:
        login_attempts[ip] = [1, now]
    else:
        login_attempts[ip][0] += 1
        login_attempts[ip][1] = now

@app.route('/')
def home():
    if "user" in session:
        return render_template("home.html", username=session["user"])
    return redirect("/login")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            return render_template("register.html", message="All fields required")

        if len(username) > 50:
            return render_template("register.html", message="Username too long")

        if len(password) < 8:
            return render_template("register.html", message="Password must be at least 8 characters")

        if not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
            return render_template("register.html", message="Password must contain 1 uppercase letter and 1 number")

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12))

        try:
            with sqlite3.connect("users.db") as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
                conn.commit()

            return redirect("/login")

        except sqlite3.IntegrityError:
            return render_template("register.html", message="Registration failed")

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr

    if is_blocked(ip):
        return render_template("login.html", message="Too many attempts. Try later.")

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            return render_template("login.html", message="Invalid credentials")

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash FROM users WHERE username=?",
                (username,)
            )
            result = cursor.fetchone()

        if result and bcrypt.checkpw(password.encode("utf-8"), result[0]):
            session["user"] = username
            login_attempts.pop(ip, None)
            return redirect("/")
        else:
            record_attempt(ip)
            return render_template("login.html", message="Invalid credentials")

    return render_template("login.html")


@app.route('/logout')
def logout():
    session.clear()
    return redirect("/login")


if __name__ == '__main__':
    app.run(debug=False)