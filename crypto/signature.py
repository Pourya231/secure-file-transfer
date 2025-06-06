# crypto/signature.py
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def sign_data(data: bytes, private_key_path: str) -> bytes:
    key = RSA.import_key(open(private_key_path).read())
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(data: bytes, signature: bytes, public_key_path: str) -> bool:
    key = RSA.import_key(open(public_key_path).read())
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
