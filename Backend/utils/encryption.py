from cryptography.fernet import Fernet
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app_config import settings


if not settings.master_key:
    raise RuntimeError("MASTER_KEY is required in .env or environment variables.")

MASTER_KEY = settings.master_key_bytes

def generate_key():
    """Generate a new fresh key"""
    return Fernet.generate_key()

def encrypt_code(code_str: str, key: bytes = MASTER_KEY) -> str:
    """Encrypts python source code string"""
    f = Fernet(key)
    # Encode to bytes -> encrypt -> decode to string for transmission
    encrypted = f.encrypt(code_str.encode('utf-8'))
    return encrypted.decode('utf-8')

def decrypt_code(encrypted_str: str, key: bytes = MASTER_KEY) -> str:
    """Decrypts back to python source code"""
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_str.encode('utf-8'))
    return decrypted.decode('utf-8')
