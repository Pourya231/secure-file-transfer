import socket
import threading
import os
from db.user_db import init_db, get_user
from auth.rbac import is_allowed
from crypto.encryption import decrypt_file, generate_symmetric_key, encrypt_file
from crypto.signature import verify_signature, sign_data

HOST = '127.0.0.1'
PORT = 9000
BUFFER_SIZE = 4096
clients = []

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    try:
        login_data = conn.recv(BUFFER_SIZE).decode()
        if login_data.startswith("LOGIN::"):
            _, username, role = login_data.strip().split("::")
            user_record = get_user(username)

            if not user_record:
                conn.sendall("LOGIN_FAIL::This user does not exist.\n".encode())
                conn.close()
                return

            if user_record[1] != role:
                conn.sendall("LOGIN_FAIL::Role mismatch.\n".encode())
                conn.close()
                return

            conn.sendall("LOGIN_SUCCESS::Welcome!\n".encode())
            print(f"[✔️] {username} logged in as {role}")
        else:
            conn.sendall("ERROR::Invalid login format.\n".encode())
            conn.close()
            return

        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break

            if data.startswith(b"FILE_UPLOAD::"):
                try:
                    filename = data.decode().split("::")[1]
                    print(f"[UPLOAD] Receiving file: {filename}")

                    if not os.path.exists("server_storage"):
                        os.makedirs("server_storage")

                    raw = b""
                    while True:
                        chunk = conn.recv(BUFFER_SIZE)
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

                    public_key_path = user_record[2]
                    if verify_signature(file_data, signature, public_key_path):
                        with open(f"server_storage/{filename}", "wb") as f:
                            f.write(file_data)
                        conn.sendall(f"UPLOAD_SUCCESS::{filename}\n".encode())
                        print(f"[✔️] File '{filename}' uploaded successfully.")
                    else:
                        conn.sendall("UPLOAD_FAIL::Invalid signature\n".encode())
                        print("[❌] Signature verification failed.")
                except Exception as e:
                    print(f"[!] Upload error: {e}")
                    conn.sendall("UPLOAD_FAIL::Server error\n".encode())

            elif data.startswith(b"DOWNLOAD::REQUEST::"):
                try:
                    decoded = data.decode()
                    filename = decoded.split("::")[2]
                    print(f"[DOWNLOAD] {username} requested: {filename}")

                    file_path = os.path.join("server_storage", filename)
                    with open(file_path, "rb") as f:
                        file_data = f.read()

                    signature = sign_data(file_data, f"keys/private_keys/{username}_private.pem")
                    payload = file_data + signature

                    sym_key = generate_symmetric_key()
                    nonce, ciphertext, tag = encrypt_file(payload, sym_key)

                    conn.sendall(
                        sym_key + b"<KEY_END>" +
                        nonce + b"<NONCE_END>" +
                        tag + b"<TAG_END>" +
                        ciphertext + b"<UPLOAD_END>"
                    )
                    print(f"[✔️] Sent file: {filename}")
                except Exception as e:
                    print(f"[!] Download error: {e}")
                    conn.sendall("DOWNLOAD_FAIL::Server error\n".encode())

            elif data == b"LIST_FILES":
                try:
                    files = os.listdir("server_storage")
                    conn.sendall(("\n".join(files) + "<EOF>").encode())
                except:
                    conn.sendall("ERROR::List failed\n".encode())

            elif data.startswith(b"ADDUSER::"):
                if role != "admin":
                    conn.sendall("ERROR::Permission denied\n".encode())
                    continue
                try:
                    _, new_user, new_role = data.decode().split("::")
                    public_key_path = f"keys/public_keys/{new_user}.pem"
                    from db.user_db import register_user
                    if not os.path.exists(public_key_path):
                        conn.sendall("ERROR::Missing public key\n".encode())
                        continue
                    register_user(new_user, new_role, public_key_path)
                    conn.sendall(f"ADDUSER_SUCCESS::{new_user}\n".encode())
                except Exception as e:
                    print(f"[!] Error adding user: {e}")
                    conn.sendall("ADDUSER_FAIL::Server error\n".encode())

            elif data.startswith(b"MSG::"):
                try:
                    message = data.decode().split("::", 1)[1]
                    print(f"[MESSAGE] From {username}: {message}")
                    conn.sendall("MSG_RECEIVED::Message received.\n".encode())
                except Exception as e:
                    print(f"[!] Error receiving message: {e}")
                    conn.sendall("MSG_FAIL::Could not process message.\n".encode())

            else:
                print(f"[{username}@{addr}] Unknown command: {data}")

    except Exception as e:
        print(f"[!] Session error: {e}")
    finally:
        conn.close()
        print(f"[-] Connection from {addr} closed")

def start_server():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[✔️] Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        clients.append(conn)

if __name__ == "__main__":
    start_server()
