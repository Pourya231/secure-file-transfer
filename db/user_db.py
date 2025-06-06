# db/user_db.py
import sqlite3
from pathlib import Path

DB_PATH = "db/users.db"

def init_db():
    Path("db").mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                role TEXT CHECK(role IN ('admin', 'maintainer', 'guest')),
                public_key_path TEXT
            )
        ''')
        conn.commit()
        print("User database initialized.")

def register_user(username, role, public_key_path):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, role, public_key_path) VALUES (?, ?, ?)",
                           (username, role, public_key_path))
            conn.commit()
            print(f"User '{username}' registered successfully as '{role}'.")
        except sqlite3.IntegrityError:
            print(f"User '{username}' already exists.")

def get_user(username):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

# تست اولیه
if __name__ == "__main__":
    init_db()
    register_user("pourya", "admin", "keys/public_keys/pourya.pem")
    print(get_user("pourya"))
