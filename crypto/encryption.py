# crypto/encryption.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def generate_symmetric_key():
    return get_random_bytes(16)  # AES-128

def encrypt_file(file_data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce, ciphertext, tag

def decrypt_file(nonce, ciphertext, tag, key: bytes):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
