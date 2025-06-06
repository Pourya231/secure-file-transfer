import socket
import os
import tkinter as tk
from tkinter import filedialog, messagebox, Listbox, ttk
from threading import Thread
from crypto.encryption import generate_symmetric_key, encrypt_file, decrypt_file
from crypto.signature import sign_data, verify_signature
from db.user_db import get_user, register_user, init_db
import sqlite3

HOST = '127.0.0.1'
PORT = 9000
BUFFER_SIZE = 4096
DB_PATH = "db/users.db"

class SecureClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure File Transfer Client")

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((HOST, PORT))

        self.username = tk.StringVar()
        self.role = tk.StringVar()

        self.build_login_ui()

    def build_login_ui(self):
        for widget in self.master.winfo_children():
            widget.destroy()

        tk.Label(self.master, text="Username:").pack()
        tk.Entry(self.master, textvariable=self.username).pack()

        tk.Label(self.master, text="Role (admin/maintainer/guest):").pack()
        tk.Entry(self.master, textvariable=self.role).pack()

        tk.Button(self.master, text="Login", command=self.login).pack()

    def login(self):
        uname = self.username.get()
        role = self.role.get()
        self.client.sendall(f"LOGIN::{uname}::{role}".encode())
        response = self.client.recv(BUFFER_SIZE).decode()
        if response.startswith("LOGIN_SUCCESS"):
            self.build_main_ui()
        else:
            messagebox.showerror("Login Failed", response.split("::")[-1])

    def build_main_ui(self):
        for widget in self.master.winfo_children():
            widget.destroy()

        info_label = tk.Label(self.master, text=f"Logged in as: {self.username.get()} ({self.role.get()})")
        info_label.pack()

        if self.role.get().lower() != "guest":
            tk.Button(self.master, text="Upload File", command=self.upload_file).pack(pady=5)

        if self.role.get().lower() == "admin":
            tk.Button(self.master, text="Admin Panel", command=self.open_admin_panel).pack(pady=5)

        tk.Button(self.master, text="Refresh File List", command=self.list_files).pack(pady=5)

        self.file_listbox = Listbox(self.master, width=50)
        self.file_listbox.pack(pady=5)
        self.file_listbox.bind('<Double-Button-1>', self.download_file)

        # Frame for sending custom message to server
        msg_frame = tk.Frame(self.master)
        msg_frame.pack(pady=10)
        self.message_entry = tk.Entry(msg_frame, width=40)
        self.message_entry.pack(side="left", padx=5)
        tk.Button(msg_frame, text="Send Message", command=self.send_message).pack(side="left")

        self.list_files()

    def upload_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        try:
            filename = os.path.basename(filepath)
            with open(filepath, "rb") as f:
                file_data = f.read()

            key_path = f"keys/private_keys/{self.username.get()}_private.pem"
            if not os.path.exists(key_path):
                messagebox.showerror("Error", "Private key not found!")
                return

            signature = sign_data(file_data, key_path)
            sym_key = generate_symmetric_key()
            nonce, ciphertext, tag = encrypt_file(file_data + signature, sym_key)

            self.client.sendall(f"FILE_UPLOAD::{filename}::".encode())
            payload = sym_key + b"<KEY_END>" + nonce + b"<NONCE_END>" + tag + b"<TAG_END>" + ciphertext + b"<UPLOAD_END>"
            self.client.sendall(payload)

            messagebox.showinfo("Success", f"File '{filename}' uploaded successfully.")

        except Exception as e:
            messagebox.showerror("Upload Failed", str(e))

    def list_files(self):
        try:
            self.client.sendall("LIST_FILES".encode())
            response = b""
            while True:
                chunk = self.client.recv(BUFFER_SIZE)
                if not chunk:
                    break
                response += chunk
                if b"<EOF>" in response:
                    break

            files = response.decode().replace("<EOF>", "").split("\n")
            self.file_listbox.delete(0, tk.END)
            for file in files:
                if file.strip():
                    self.file_listbox.insert(tk.END, file.strip())

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def download_file(self, event):
        try:
            selection = self.file_listbox.curselection()
            if not selection:
                return
            filename = self.file_listbox.get(selection[0])
            self.client.sendall(f"DOWNLOAD::REQUEST::{filename}".encode())

            raw = b""
            while True:
                chunk = self.client.recv(BUFFER_SIZE)
                if not chunk:
                    break
                raw += chunk
                if b"<UPLOAD_END>" in raw:
                    break

            raw = raw.replace(b"<UPLOAD_END>", b"")
            sym_key, rest = raw.split(b"<KEY_END>")
            nonce, rest = rest.split(b"<NONCE_END>")
            tag, ciphertext = rest.split(b"<TAG_END>")

            decrypted = decrypt_file(nonce, ciphertext, tag, sym_key)
            file_data = decrypted[:-256]
            signature = decrypted[-256:]

            key_path = f"keys/public_keys/{self.username.get()}.pem"
            if verify_signature(file_data, signature, key_path):
                user_download_path = os.path.join("downloads", self.username.get())
                os.makedirs(user_download_path, exist_ok=True)
                output_path = os.path.join(user_download_path, filename)
                with open(output_path, "wb") as f:
                    f.write(file_data)
                messagebox.showinfo("Downloaded", f"File downloaded to:\n{output_path}")
            else:
                messagebox.showerror("Invalid Signature", "File signature is not valid.")

        except Exception as e:
            messagebox.showerror("Download Error", str(e))

    def send_message(self):
        msg = self.message_entry.get().strip()
        if not msg:
            messagebox.showwarning("Empty", "Enter a message to send.")
            return
        try:
            self.client.sendall(f"MSG::{msg}".encode())  # 👈 پیشوند اضافه شد
            response = self.client.recv(BUFFER_SIZE).decode()
            messagebox.showinfo("Server Response", response)
        except Exception as e:
            messagebox.showerror("Error", str(e))


    def open_admin_panel(self):
        admin_window = tk.Toplevel(self.master)
        AdminDashboard(admin_window)


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
    app = SecureClientGUI(root)
    root.mainloop()
