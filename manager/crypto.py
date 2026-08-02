import os
import json
import base64
import binascii
from typing import Any

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536 # 64 MB
ARGON2_PARALLELLISM = 4
KEY_LENGTH = 32 # 256 BIT KEY
KEY_MATERIAL_DOMAIN = b"password-manager-vault-key-v2"
PANIC_KEY_MATERIAL_DOMAIN = b"password-manager-panic-key-v2"
PANIC_VERIFIER = b"panic-delete-v2"
VAULT_VERSION = 2
KDF_NAME = "argon2id"
CIPHER_NAME = "aes-256-gcm"
KEY_MATERIAL_NAME = "master-password+keyfile"
MAX_ENCRYPTED_VAULT_BYTES = 32 * 1024 * 1024
MAX_CIPHERTEXT_BYTES = 24 * 1024 * 1024
ENVELOPE_REQUIRED_FIELDS = {
    "version",
    "kdf",
    "cipher",
    "key_material",
    "ciphertext",
}
ENVELOPE_OPTIONAL_FIELDS = {"panic"}
KDF_FIELDS = {
    "name",
    "time_cost",
    "memory_cost_kib",
    "parallelism",
    "salt",
}
CIPHER_FIELDS = {"name", "nonce"}
PANIC_FIELDS = {"salt", "nonce", "ciphertext"}

def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"), validate=True)


def rejectDuplicateJsonKeys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}.")

        result[key] = value

    return result


def loadJson(data: bytes, context: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=rejectDuplicateJsonKeys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{context} is not valid UTF-8 JSON.") from error


def requireJsonObject(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be a JSON object.")

    return value


def validateFields(
    value: dict[str, Any],
    requiredFields: set[str],
    optionalFields: set[str],
    context: str,
) -> None:
    actualFields = set(value)
    missingFields = requiredFields - actualFields
    unknownFields = actualFields - requiredFields - optionalFields

    if missingFields:
        fields = ", ".join(sorted(missingFields))
        raise ValueError(f"{context} is missing fields: {fields}.")

    if unknownFields:
        fields = ", ".join(sorted(unknownFields))
        raise ValueError(f"{context} has unknown fields: {fields}.")


def decodeField(
    value: Any,
    field: str,
    *,
    expectedLength: int | None = None,
    maximumLength: int | None = None,
) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be Base64 text.")

    try:
        decoded = decode(value)
    except (binascii.Error, UnicodeEncodeError) as error:
        raise ValueError(f"{field} is not valid Base64.") from error

    if expectedLength is not None and len(decoded) != expectedLength:
        raise ValueError(
            f"{field} must decode to exactly {expectedLength} bytes."
        )

    if maximumLength is not None and len(decoded) > maximumLength:
        raise ValueError(
            f"{field} exceeds the {maximumLength} byte limit."
        )

    return decoded


def parseEncryptedVault(encryptedData: bytes) -> dict[str, Any]:
    if len(encryptedData) > MAX_ENCRYPTED_VAULT_BYTES:
        raise ValueError(
            f"Encrypted vault exceeds the {MAX_ENCRYPTED_VAULT_BYTES} byte limit."
        )

    vault = requireJsonObject(
        loadJson(encryptedData, "Encrypted vault"),
        "Encrypted vault",
    )
    validateFields(
        vault,
        ENVELOPE_REQUIRED_FIELDS,
        ENVELOPE_OPTIONAL_FIELDS,
        "Encrypted vault",
    )
    return vault


def get_vault_version(encryptedData: bytes) -> int:
    vault = parseEncryptedVault(encryptedData)
    version = vault.get("version")

    if type(version) is not int:
        raise ValueError("Vault version is missing or invalid.")

    return version


def build_authenticated_metadata(
    salt: bytes,
    nonce: bytes,
    panicBlock: dict[str, str] | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "version": VAULT_VERSION,
        "kdf": {
            "name": KDF_NAME,
            "time_cost": ARGON2_TIME_COST,
            "memory_cost_kib": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELLISM,
            "salt": encode(salt),
        },
        "cipher": {
            "name": CIPHER_NAME,
            "nonce": encode(nonce),
        },
        "key_material": KEY_MATERIAL_NAME,
    }

    if panicBlock is not None:
        metadata["panic"] = panicBlock

    return metadata


def encode_authenticated_metadata(metadata: dict[str, Any]) -> bytes:
    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def validatePanicBlock(panicBlock: Any) -> dict[str, str]:
    if not isinstance(panicBlock, dict):
        raise ValueError("Vault panic metadata must be an object.")

    validateFields(panicBlock, PANIC_FIELDS, set(), "Vault panic metadata")
    decodeField(panicBlock["salt"], "Panic salt", expectedLength=16)
    decodeField(panicBlock["nonce"], "Panic nonce", expectedLength=12)
    decodeField(
        panicBlock["ciphertext"],
        "Panic ciphertext",
        expectedLength=len(PANIC_VERIFIER) + 16,
    )
    return panicBlock


def parse_v2_metadata(
    vault: dict[str, Any],
) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    version = vault.get("version")
    kdf = vault.get("kdf")
    cipher = vault.get("cipher")

    if type(version) is not int or version != VAULT_VERSION:
        raise ValueError(f"Unsupported vault version: {version}.")

    if not isinstance(kdf, dict) or not isinstance(cipher, dict):
        raise ValueError("Vault metadata is invalid.")

    validateFields(kdf, KDF_FIELDS, set(), "Vault KDF metadata")
    validateFields(cipher, CIPHER_FIELDS, set(), "Vault cipher metadata")

    expectedKdf = {
        "name": KDF_NAME,
        "time_cost": ARGON2_TIME_COST,
        "memory_cost_kib": ARGON2_MEMORY_COST,
        "parallelism": ARGON2_PARALLELLISM,
    }

    for field, expectedValue in expectedKdf.items():
        if kdf.get(field) != expectedValue:
            raise ValueError(f"Unsupported vault KDF setting: {field}.")

    if cipher.get("name") != CIPHER_NAME:
        raise ValueError("Unsupported vault cipher.")

    if vault.get("key_material") != KEY_MATERIAL_NAME:
        raise ValueError("Unsupported vault key material.")

    metadata = {
        field: value
        for field, value in vault.items()
        if field != "ciphertext"
    }
    salt = decodeField(kdf["salt"], "Vault salt", expectedLength=16)
    nonce = decodeField(cipher["nonce"], "Vault nonce", expectedLength=12)
    ciphertext = decodeField(
        vault["ciphertext"],
        "Vault ciphertext",
        maximumLength=MAX_CIPHERTEXT_BYTES,
    )

    if len(ciphertext) < 16:
        raise ValueError("Vault ciphertext is too short.")

    if "panic" in vault:
        validatePanicBlock(vault["panic"])

    return metadata, salt, nonce, ciphertext

def build_key_material(passwordValue: str, keyfileData: bytes, domain: bytes) -> bytes:
    password = passwordValue.encode("utf-8")

    return b"".join(
        [
            domain,
            len(password).to_bytes(4, "big"),
            password,
            len(keyfileData).to_bytes(4, "big"),
            keyfileData,
        ]
    )

def derive_key(
    passwordValue: str,
    keyfileData: bytes,
    salt: bytes,
    domain: bytes = KEY_MATERIAL_DOMAIN,
) -> bytes:
    return hash_secret_raw(
        secret=build_key_material(passwordValue, keyfileData, domain),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELLISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )

def create_panic_block(panic_password: str, keyfileData: bytes) -> dict[str, str]:
    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = derive_key(panic_password, keyfileData, salt, PANIC_KEY_MATERIAL_DOMAIN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, PANIC_VERIFIER, None)

    return {
        "salt": encode(salt),
        "nonce": encode(nonce),
        "ciphertext": encode(ciphertext),
    }

def is_panic_password(
    encryptedData: bytes,
    passwordValue: str,
    keyfileData: bytes,
) -> bool:
    vault = parseEncryptedVault(encryptedData)
    parse_v2_metadata(vault)
    panicBlock = vault.get("panic")

    if panicBlock is None:
        return False

    validatedPanicBlock = validatePanicBlock(panicBlock)
    salt = decodeField(validatedPanicBlock["salt"], "Panic salt", expectedLength=16)
    nonce = decodeField(validatedPanicBlock["nonce"], "Panic nonce", expectedLength=12)
    ciphertext = decodeField(
        validatedPanicBlock["ciphertext"],
        "Panic ciphertext",
        expectedLength=len(PANIC_VERIFIER) + 16,
    )

    key = derive_key(passwordValue, keyfileData, salt, PANIC_KEY_MATERIAL_DOMAIN)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        return False

    return plaintext == PANIC_VERIFIER

def get_panic_block(encryptedData: bytes) -> dict[str, str] | None:
    vault = parseEncryptedVault(encryptedData)
    parse_v2_metadata(vault)
    panicBlock = vault.get("panic")

    if panicBlock is None:
        return None

    return validatePanicBlock(panicBlock)

def encrypt(
    data: dict[str, Any],
    master_password: str,
    keyfileData: bytes,
    panicBlock: dict[str, str] | None = None,
) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = derive_key(master_password, keyfileData, salt)
    aesgcm = AESGCM(key)

    if panicBlock is not None:
        validatePanicBlock(panicBlock)

    plaintext = json.dumps(data, allow_nan=False).encode("utf-8")
    encryptedVault = build_authenticated_metadata(salt, nonce, panicBlock)
    authenticatedMetadata = encode_authenticated_metadata(encryptedVault)
    ciphertext = aesgcm.encrypt(nonce, plaintext, authenticatedMetadata)
    encryptedVault["ciphertext"] = encode(ciphertext)

    return json.dumps(encryptedVault, indent=2).encode("utf-8")


def decrypt(encryptedData: bytes, master_password: str, keyfileData: bytes) -> dict[str, Any]:
    vault = parseEncryptedVault(encryptedData)
    metadata, salt, nonce, ciphertext = parse_v2_metadata(vault)

    key = derive_key(master_password, keyfileData, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        encode_authenticated_metadata(metadata),
    )

    return requireJsonObject(loadJson(plaintext, "Decrypted vault"), "Decrypted vault")
