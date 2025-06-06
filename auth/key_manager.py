# auth/key_manager.py
from Crypto.PublicKey import RSA
from pathlib import Path

def generate_rsa_keys(username, save_path="keys"):
    Path(f"{save_path}/public_keys").mkdir(parents=True, exist_ok=True)
    Path(f"{save_path}/private_keys").mkdir(parents=True, exist_ok=True)

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"{save_path}/private_keys/{username}_private.pem", "wb") as prv_file:
        prv_file.write(private_key)

    with open(f"{save_path}/public_keys/{username}.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print(f"RSA keys generated for user '{username}'.")

# تست:
if __name__ == "__main__":
    generate_rsa_keys("ali")
