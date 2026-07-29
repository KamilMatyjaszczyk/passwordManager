from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from manager.keyfile import createKeyfile
from manager.vault import (
    addEntry,
    createVault,
    deleteEntry,
    getEntry,
    listEntries,
)


MASTER_PASSWORD = "test-master-password"


def test_vault_entry_lifecycle(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path))

    addEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        title="GitHub",
        username="test@example.com",
        password="supersecret",
        url="https://github.com",
        notes="Test account",
    )

    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == ["GitHub"]

    entry = getEntry(str(vault_path), MASTER_PASSWORD, str(keyfile_path), "github")

    assert entry is not None
    assert entry["title"] == "GitHub"
    assert entry["username"] == "test@example.com"
    assert entry["password"] == "supersecret"
    assert entry["url"] == "https://github.com"
    assert entry["notes"] == "Test account"

    assert deleteEntry(str(vault_path), MASTER_PASSWORD, str(keyfile_path), "GitHub") is True
    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == []


def test_delete_entry_returns_false_when_title_is_missing(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path))

    assert deleteEntry(str(vault_path), MASTER_PASSWORD, str(keyfile_path), "Missing") is False


def test_vault_rejects_wrong_keyfile(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"
    wrong_keyfile_path = tmp_path / "wrong.key"

    createKeyfile(str(keyfile_path))
    createKeyfile(str(wrong_keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path))

    with pytest.raises(InvalidTag):
        listEntries(str(vault_path), MASTER_PASSWORD, str(wrong_keyfile_path))
