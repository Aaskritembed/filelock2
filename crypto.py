import base64
import secrets
from hashlib import sha256, pbkdf2_hmac
from typing import Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from constants import KEY_SIZE, NONCE_SIZE, PBKDF2_ITERATIONS

# --------------------------
# Encryption/Decryption with AES-GCM
# --------------------------
def derive_key_from_secret(secret: bytes, salt: bytes = b'') -> bytes:
    """
    Derive encryption key from secret using PBKDF2-HMAC-SHA256
    Salt is optional for backward compatibility but recommended
    """
    if salt:
        return pbkdf2_hmac('sha256', secret, salt, PBKDF2_ITERATIONS, dklen=KEY_SIZE)
    else:
        # Fallback for existing archives (less secure)
        return sha256(secret).digest()

def encrypt_bytes(plaintext: bytes, secret: bytes) -> Dict[str, str]:
    """Encrypt plaintext using AES-256-GCM"""
    # Generate random salt for key derivation
    salt = secrets.token_bytes(16)
    key = derive_key_from_secret(secret, salt)
    
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    
    try:
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}")
    
    return {
        "version": "2",  # Version with salt-based KDF
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt_bytes(encobj: Dict[str, str], secret: bytes) -> bytes:
    """Decrypt ciphertext using AES-256-GCM"""
    version = encobj.get("version", "1")
    
    try:
        nonce = base64.b64decode(encobj["nonce"])
        ciphertext = base64.b64decode(encobj["ciphertext"])
    except (KeyError, ValueError) as e:
        raise ValueError(f"Invalid encrypted object format: {e}")
    
    # Use salt if version 2, otherwise fallback to simple SHA256
    if version == "2" and "salt" in encobj:
        salt = base64.b64decode(encobj["salt"])
        key = derive_key_from_secret(secret, salt)
    else:
        key = derive_key_from_secret(secret)
    
    aesgcm = AESGCM(key)
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Decryption failed: invalid key or corrupted data")
    except Exception as e:
        raise RuntimeError(f"Decryption error: {e}")
    
    return plaintext
