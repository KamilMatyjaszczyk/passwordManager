import base64
import json

import pytest
from cryptography.exceptions import InvalidTag

from manager.crypto import (
    VAULT_VERSION,
    create_panic_block,
    decrypt,
    encrypt,
    is_panic_password,
)


KEYFILE_DATA = b"test-keyfile-data"
PANIC_PASSWORD = "panic-password"


def test_encrypt_decrypt_round_trip() -> None:
    vault = {
        "entries": [
            {
                "title": "GitHub",
                "username": "test@example.com",
                "password": "supersecret",
            }
        ]
    }

    encrypted = encrypt(vault, "my-master-password", KEYFILE_DATA)
    decrypted = decrypt(encrypted, "my-master-password", KEYFILE_DATA)

    assert decrypted == vault


def test_encrypt_creates_v2_vault_with_structured_metadata() -> None:
    encrypted = encrypt({"entries": []}, "correct-password", KEYFILE_DATA)
    envelope = json.loads(encrypted.decode("utf-8"))

    assert envelope["version"] == VAULT_VERSION
    assert envelope["kdf"] == {
        "name": "argon2id",
        "time_cost": 3,
        "memory_cost_kib": 65536,
        "parallelism": 4,
        "salt": envelope["kdf"]["salt"],
    }
    assert envelope["cipher"]["name"] == "aes-256-gcm"
    assert envelope["key_material"] == "master-password+keyfile"


def test_decrypt_rejects_unknown_metadata_field() -> None:
    encrypted = encrypt({"entries": []}, "correct-password", KEYFILE_DATA)
    envelope = json.loads(encrypted.decode("utf-8"))
    envelope["unexpected_metadata"] = "tampered"
    tampered = json.dumps(envelope).encode("utf-8")

    with pytest.raises(ValueError, match="unknown fields"):
        decrypt(tampered, "correct-password", KEYFILE_DATA)


def test_decrypt_rejects_panic_metadata_change() -> None:
    panic_block = create_panic_block(PANIC_PASSWORD, KEYFILE_DATA)
    encrypted = encrypt(
        {"entries": []},
        "correct-password",
        KEYFILE_DATA,
        panic_block,
    )
    envelope = json.loads(encrypted.decode("utf-8"))
    panic_ciphertext = bytearray(
        base64.b64decode(envelope["panic"]["ciphertext"])
    )
    panic_ciphertext[0] ^= 1
    envelope["panic"]["ciphertext"] = base64.b64encode(
        panic_ciphertext
    ).decode("utf-8")
    tampered = json.dumps(envelope).encode("utf-8")

    with pytest.raises(InvalidTag):
        decrypt(tampered, "correct-password", KEYFILE_DATA)


def test_decrypt_rejects_duplicate_json_fields() -> None:
    encrypted = encrypt({"entries": []}, "correct-password", KEYFILE_DATA)
    duplicated = encrypted.replace(
        b'"version": 2,',
        b'"version": 2, "version": 2,',
        1,
    )

    with pytest.raises(ValueError, match="Duplicate JSON field"):
        decrypt(duplicated, "correct-password", KEYFILE_DATA)


def test_decrypt_rejects_v1_format() -> None:
    encrypted = encrypt({"entries": []}, "correct-password", KEYFILE_DATA)
    envelope = json.loads(encrypted.decode("utf-8"))
    envelope["version"] = 1

    with pytest.raises(ValueError, match="Unsupported vault version"):
        decrypt(
            json.dumps(envelope).encode("utf-8"),
            "correct-password",
            KEYFILE_DATA,
        )


def test_decrypt_rejects_wrong_password() -> None:
    encrypted = encrypt({"entries": []}, "correct-password", KEYFILE_DATA)

    with pytest.raises(InvalidTag):
        decrypt(encrypted, "wrong-password", KEYFILE_DATA)


def test_decrypt_rejects_wrong_keyfile() -> None:
    encrypted = encrypt({"entries": []}, "correct-password", KEYFILE_DATA)

    with pytest.raises(InvalidTag):
        decrypt(encrypted, "correct-password", b"wrong-keyfile-data")


def test_panic_password_is_detected() -> None:
    panic_block = create_panic_block(PANIC_PASSWORD, KEYFILE_DATA)
    encrypted = encrypt(
        {"entries": []},
        "correct-password",
        KEYFILE_DATA,
        panic_block,
    )

    assert is_panic_password(encrypted, PANIC_PASSWORD, KEYFILE_DATA) is True
    assert is_panic_password(encrypted, "wrong-password", KEYFILE_DATA) is False
    assert is_panic_password(encrypted, PANIC_PASSWORD, b"wrong-keyfile") is False
