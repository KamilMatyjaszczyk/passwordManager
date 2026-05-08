import os
import json
import base64
from typing import Any

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536 # 64 MB
ARGON2_PARALLELLISM = 4
KEY_LENGTH = 32 # 256 BIT KEY

def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def decode(data: bytes) -> str:
    return base64.b64decode(data.encode("utf-8"))

def derive_key(master_password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELLISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )

def encrypt(data: dict[str, Any], master_password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)

    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encryptedVault = {
        "version": 1, 
        "kdf": "argon2id",
        "cipher": "aes-256-gcm",
        "salt": encode(salt),
        "nonce": encode(nonce),
        "ciphertext": encode(ciphertext),
    }

    return json.dumps(encryptedVault, indent=2).encode("utf-8")

def decrypt(encrypted_data: bytes, master_password: str) -> dict[str, Any]:
    vault = json.loads(encrypted_data.decode("utf-8"))

    salt = decode(vault["salt"])
    nonce = decode(vault["nonce"])
    ciphertext = decode(vault["ciphertext"])

    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return json.loads(plaintext.decode("utf-8"))
