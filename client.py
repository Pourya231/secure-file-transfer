import socket
import os
from crypto.encryption import generate_symmetric_key, encrypt_file, decrypt_file
from crypto.signature import sign_data, verify_signature
import tkinter as tk
from tkinter import filedialog

HOST = '127.0.0.1'
PORT = 9000
BUFFER_SIZE = 4096

def browse_file():
    root = tk.Tk()
    root.withdraw()
    filepath = filedialog.askopenfilename()
    return filepath

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print("[+] Connected to server.")

    # ورود اولیه کاربر
    username = input("Enter your username: ")
    role = input("Enter your role (admin / maintainer / guest): ")

    client.sendall(f"LOGIN::{username}::{role}".encode())
    response = client.recv(BUFFER_SIZE).decode()

    if response.startswith("LOGIN_FAIL::"):
        print(f"[!] Login failed: {response.split('::')[1]}")
        client.close()
        return
    elif not response.startswith("LOGIN_SUCCESS::"):
        print("[!] Unexpected response from server.")
        client.close()
        return

    print("[✔️] Logged in successfully.")

    while True:
        message = input(">>> ")

        if message.lower() == "exit":
            break

        elif message.lower() == "list":
            client.sendall("LIST_FILES".encode())
            response = b""
            while True:
                chunk = client.recv(BUFFER_SIZE)
                if not chunk:
                    break
                response += chunk
                if b"<EOF>" in response:
                    break
            files = response.decode().replace("<EOF>", "").split("\n")
            print("[📁] Available files on server:")
            for f in files:
                if f.strip():
                    print("-", f.strip())

        elif message == "UPLOAD":
            filepath = browse_file()
            if not filepath:
                print("[!] No file selected.")
                continue

            try:
                filename = os.path.basename(filepath)
                with open(filepath, "rb") as f:
                    file_data = f.read()

                key_path = f"keys/private_keys/{username}_private.pem"
                signature = sign_data(file_data, key_path)

                sym_key = generate_symmetric_key()
                nonce, ciphertext, tag = encrypt_file(file_data + signature, sym_key)

                client.sendall(f"FILE_UPLOAD::{filename}::".encode())
                client.sendall(sym_key + b"<KEY_END>" + nonce + b"<NONCE_END>" + tag + b"<TAG_END>" + ciphertext)
                print(f"[✔️] File '{filename}' uploaded.")

            except Exception as e:
                print(f"[!] Upload failed: {e}")

        elif message.startswith("DOWNLOAD::"):
            try:
                filename = message.split("::")[1]
                client.sendall(f"DOWNLOAD::REQUEST::{filename}".encode())

                raw = b""
                while True:
                    chunk = client.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    raw += chunk
                    if b"<TAG_END>" in raw:
                        break

                sym_key, rest = raw.split(b"<KEY_END>")
                nonce, rest = rest.split(b"<NONCE_END>")
                tag, ciphertext = rest.split(b"<TAG_END>")

                decrypted = decrypt_file(nonce, ciphertext, tag, sym_key)
                file_data = decrypted[:-256]
                signature = decrypted[-256:]

                key_path = f"keys/public_keys/{filename.split('_')[0]}.pem"
                if verify_signature(file_data, signature, key_path):
                    with open(f"downloaded_{filename}", "wb") as f:
                        f.write(file_data)
                    print(f"[✔️] File '{filename}' downloaded and verified.")
                else:
                    print("[❌] Signature verification failed.")

            except Exception as e:
                print(f"[!] Download failed: {e}")

        elif message.startswith("ADDUSER::"):
            client.sendall(message.encode())
            response = client.recv(BUFFER_SIZE).decode()
            print(response)

        else:
            client.sendall(message.encode())

    client.close()
    print("[*] Disconnected from server.")

if __name__ == "__main__":
    main()
