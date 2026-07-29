import pytest
from cryptography.exceptions import InvalidTag

from manager.crypto import decrypt, encrypt


KEYFILE_DATA = b"test-keyfile-data"


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


def test_decrypt_rejects_wrong_password() -> None:
    encrypted = encrypt({"entries": []}, "correct-password", KEYFILE_DATA)

    with pytest.raises(InvalidTag):
        decrypt(encrypted, "wrong-password", KEYFILE_DATA)


def test_decrypt_rejects_wrong_keyfile() -> None:
    encrypted = encrypt({"entries": []}, "correct-password", KEYFILE_DATA)

    with pytest.raises(InvalidTag):
        decrypt(encrypted, "correct-password", b"wrong-keyfile-data")
