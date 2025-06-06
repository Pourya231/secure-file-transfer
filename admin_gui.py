import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import os
from db.user_db import get_user, register_user, init_db

DB_PATH = "db/users.db"

class AdminDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Admin Dashboard")
        self.build_ui()
        init_db()
        self.load_users()

    def build_ui(self):
        self.tree = ttk.Treeview(self.root, columns=("Username", "Role"), show="headings")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Role", text="Role")
        self.tree.pack(pady=10)

        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="Username:").grid(row=0, column=0)
        self.username_entry = tk.Entry(frame)
        self.username_entry.grid(row=0, column=1)

        tk.Label(frame, text="Role:").grid(row=0, column=2)
        self.role_entry = tk.Entry(frame)
        self.role_entry.grid(row=0, column=3)

        tk.Button(frame, text="Add User", command=self.add_user).grid(row=0, column=4, padx=5)
        tk.Button(frame, text="Delete User", command=self.delete_user).grid(row=0, column=5, padx=5)

    def load_users(self):
        self.tree.delete(*self.tree.get_children())
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, role FROM users")
            for row in cursor.fetchall():
                self.tree.insert("", tk.END, values=row)

    def add_user(self):
        username = self.username_entry.get().strip()
        role = self.role_entry.get().strip()
        key_path = f"keys/public_keys/{username}.pem"

        if not username or not role:
            messagebox.showwarning("Missing info", "Enter both username and role.")
            return

        if not os.path.exists(key_path):
            messagebox.showerror("Missing key", f"Key file not found for {username}.")
            return

        try:
            register_user(username, role, key_path)
            self.load_users()
            messagebox.showinfo("Success", f"User '{username}' added.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_user(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select user", "No user selected.")
            return

        username = self.tree.item(selected[0])["values"][0]

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()

        self.load_users()
        messagebox.showinfo("Deleted", f"User '{username}' deleted.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdminDashboard(root)
    root.mainloop()
