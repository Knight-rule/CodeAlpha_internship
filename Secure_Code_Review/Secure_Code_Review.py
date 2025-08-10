import sqlite3
import os
import bcrypt
from datetime import datetime

DB_PATH = "users_secure.db"

def initialize_database():
    if not os.path.exists(DB_PATH):
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE users (
                                       id            INTEGER PRIMARY KEY AUTOINCREMENT,
                                       username      TEXT NOT NULL UNIQUE,
                                       password_hash BLOB NOT NULL,
                                       created_at    TEXT NOT NULL
                )
            """)
            default_pw = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                ("admin", default_pw, datetime.utcnow().isoformat())
            )
            conn.commit()
        print("Database initialized with default admin user.\n")

def register_user(username, password):
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    created = datetime.utcnow().isoformat()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, pw_hash, created)
            )
            conn.commit()
        print(f"[+] User '{username}' registered at {created}\n")
    except sqlite3.IntegrityError:
        print(f"[!] Username '{username}' already exists.\n")

def login(username, password):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
    if row and bcrypt.checkpw(password.encode(), row[0]):
        print(f"[+] Welcome back, {username}!\n")
    else:
        print("[!] Invalid username or password.\n")

def list_users():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, created_at FROM users")
        rows = cursor.fetchall()
    if rows:
        print("Registered Users:")
        for uid, user, created in rows:
            print(f"  • {uid}: {user} (since {created})")
        print()
    else:
        print("[!] No users found.\n")

def main():
    initialize_database()
    while True:
        print("Menu:")
        print(" 1. Register")
        print(" 2. Login")
        print(" 3. List Users")
        print(" 4. Exit")
        choice = input("Enter choice: ").strip()

        if choice == '1':
            u = input("Username: ").strip()
            p = input("Password: ").strip()
            register_user(u, p)
        elif choice == '2':
            u = input("Username: ").strip()
            p = input("Password: ").strip()
            login(u, p)
        elif choice == '3':
            list_users()
        elif choice == '4':
            print("Goodbye!")
            break
        else:
            print("[!] Invalid choice, try again.\n")

if __name__ == "__main__":
    main()
