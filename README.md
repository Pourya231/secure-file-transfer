# 🔐 Secure File Transfer System

## 🎯 Project Objective
A secure file transfer system that ensures:
- **Encryption in transit and at rest**
- **Digital signatures for data integrity**
- **Role-Based Access Control (RBAC)**

## 🏗️ Project Structure

```
secure_file_transfer/
├── server.py
├── client.py
├── crypto/
│   ├── encryption.py
│   └── signature.py
├── auth/
│   ├── key_manager.py
│   └── rbac.py
├── db/
│   └── user_db.py
├── keys/
│   ├── private_keys/
│   └── public_keys/
├── server_storage/
├── README.md
└── requirements.txt
```

## 🛠️ How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate RSA keys for each user

```python
# Run this in a Python script or terminal
from auth.key_manager import generate_rsa_keys
generate_rsa_keys("alice")
```

### 3. Register user in database

```python
from db.user_db import register_user
register_user("alice", "maintainer", "keys/public_keys/alice.pem")
```

### 4. Start server and client

```bash
python server.py
python client.py
```

## 👤 User Roles

- **admin**: Can upload, download, delete files and manage users
- **maintainer**: Can upload and download files
- **guest**: Can only download files

## 🧪 Commands in Client

- `UPLOAD::filename.txt` → Upload file
- `DOWNLOAD::filename.txt` → Download file
- `ADDUSER::username::role` → Admin adds new user
- `exit` → Disconnect from server

## 📌 Notes

- Each file is digitally signed before upload
- Files are encrypted using AES per session
- Signature verification is enforced on download

## 📫 Final Notes

Ensure `keys/`, `server_storage/`, and database are properly set up before use.
