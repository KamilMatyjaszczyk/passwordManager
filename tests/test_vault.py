import threading
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from manager.crypto import create_panic_block, encrypt
from manager.keyfile import createKeyfile, readKeyfile
from manager import secure_file as secure_file_module
from manager import vault as vault_module
from manager.vault import (
    AmbiguousEntryError,
    addEntry,
    changeMasterPassword,
    changePanicPassword,
    createVault,
    deleteEntry,
    deleteVault,
    getEntry,
    isMasterPassword,
    isPanicPassword,
    listEntrySummaries,
    listEntries,
    loadVault,
    updateEntry,
)
from manager.vault_schema import MAX_TITLE_LENGTH, VaultValidationError


MASTER_PASSWORD = "test-master-password"
PANIC_PASSWORD = "panic-delete-password"
NEW_PANIC_PASSWORD = "new-panic-delete-password"


def test_create_vault_allows_matching_master_and_panic_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), MASTER_PASSWORD)

    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == []
    assert isMasterPassword(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) is True
    assert isPanicPassword(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) is True


def test_vault_entry_lifecycle(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

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
    assert len(entry["id"]) == 32
    assert entry["title"] == "GitHub"
    assert entry["username"] == "test@example.com"
    assert entry["password"] == "supersecret"
    assert entry["url"] == "https://github.com"
    assert entry["notes"] == "Test account"

    assert deleteEntry(str(vault_path), MASTER_PASSWORD, str(keyfile_path), "GitHub") is True
    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == []


def test_duplicate_titles_require_entry_id(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    first_id = addEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        title="Email",
        username="first@example.com",
        password="first-secret",
    )
    second_id = addEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        title="Email",
        username="second@example.com",
        password="second-secret",
    )

    assert first_id != second_id

    with pytest.raises(AmbiguousEntryError, match="Multiple entries"):
        getEntry(str(vault_path), MASTER_PASSWORD, str(keyfile_path), "Email")

    first_entry = getEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        first_id[:8],
    )
    assert first_entry is not None
    assert first_entry["username"] == "first@example.com"

    assert deleteEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        second_id[:8],
    ) is True
    assert listEntries(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
    ) == ["Email"]


def test_entry_ids_remain_stable_after_update(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)
    entry_id = addEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        title="GitHub",
        username="old@example.com",
        password="secret",
    )

    assert updateEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        entry_id[:8],
        username="new@example.com",
    ) is True

    summaries = listEntrySummaries(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
    )
    assert summaries == [
        {
            "id": entry_id,
            "title": "GitHub",
            "username": "new@example.com",
        }
    ]


def test_concurrent_adds_do_not_overwrite_each_other(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"
    startBarrier = threading.Barrier(3)
    errors = []
    originalLoadVault = vault_module.loadVault

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    def slowLoadVault(*args, **kwargs):
        vaultData = originalLoadVault(*args, **kwargs)
        time.sleep(0.1)
        return vaultData

    def addAccount(title: str) -> None:
        try:
            startBarrier.wait()
            addEntry(
                str(vault_path),
                MASTER_PASSWORD,
                str(keyfile_path),
                title=title,
                username=f"{title.lower()}@example.com",
                password="secret",
            )
        except Exception as error:
            errors.append(error)

    monkeypatch.setattr(vault_module, "loadVault", slowLoadVault)
    threads = [
        threading.Thread(target=addAccount, args=("First",)),
        threading.Thread(target=addAccount, args=("Second",)),
    ]

    for thread in threads:
        thread.start()

    startBarrier.wait()

    for thread in threads:
        thread.join(10)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert sorted(
        listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path))
    ) == ["First", "Second"]


def test_delete_entry_returns_false_when_title_is_missing(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    assert deleteEntry(str(vault_path), MASTER_PASSWORD, str(keyfile_path), "Missing") is False


def test_add_rejects_invalid_entry_without_changing_vault(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)
    original_data = vault_path.read_bytes()

    with pytest.raises(VaultValidationError, match="character limit"):
        addEntry(
            str(vault_path),
            MASTER_PASSWORD,
            str(keyfile_path),
            title="a" * (MAX_TITLE_LENGTH + 1),
            username="test@example.com",
            password="secret",
        )

    assert vault_path.read_bytes() == original_data
    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == []


def test_load_rejects_cryptographically_valid_invalid_schema(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    keyfile_data = readKeyfile(str(keyfile_path))
    panic_block = create_panic_block(PANIC_PASSWORD, keyfile_data)
    invalid_vault = {
        "schema_version": 2,
        "entries": [
            {
                "id": "0123456789abcdef0123456789abcdef",
                "title": "GitHub",
                "username": "test@example.com",
                "password": "secret",
                "url": "https://github.com",
            }
        ],
    }
    vault_path.write_bytes(
        encrypt(
            invalid_vault,
            MASTER_PASSWORD,
            keyfile_data,
            panic_block,
        )
    )

    with pytest.raises(VaultValidationError, match="missing fields: notes"):
        loadVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path))


def test_load_rejects_vault_without_panic_metadata(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    keyfile_data = readKeyfile(str(keyfile_path))
    vault_path.write_bytes(
        encrypt(
            {
                "schema_version": 2,
                "entries": [],
            },
            MASTER_PASSWORD,
            keyfile_data,
        )
    )

    with pytest.raises(VaultValidationError, match="panic metadata is missing"):
        loadVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path))


def test_failed_atomic_save_keeps_existing_vault(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    originalData = vault_path.read_bytes()

    def fail_replace(source: Path, destination: Path) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(secure_file_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        addEntry(
            str(vault_path),
            MASTER_PASSWORD,
            str(keyfile_path),
            title="GitHub",
            username="test@example.com",
            password="supersecret",
        )

    assert vault_path.read_bytes() == originalData
    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == []
    assert not list(tmp_path.glob(f".{vault_path.name}.*.tmp"))


def test_vault_rejects_wrong_keyfile(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"
    wrong_keyfile_path = tmp_path / "wrong.key"

    createKeyfile(str(keyfile_path))
    createKeyfile(str(wrong_keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    with pytest.raises(InvalidTag):
        listEntries(str(vault_path), MASTER_PASSWORD, str(wrong_keyfile_path))


def test_panic_delete_preserves_keyfile(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    assert isPanicPassword(str(vault_path), PANIC_PASSWORD, str(keyfile_path)) is True
    assert isPanicPassword(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) is False

    deleteVault(str(vault_path))

    assert not vault_path.exists()
    assert keyfile_path.exists()


def test_create_vault_rejects_empty_master_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))

    with pytest.raises(ValueError, match="cannot be empty"):
        createVault(str(vault_path), "", str(keyfile_path), PANIC_PASSWORD)

    assert not vault_path.exists()


def test_create_vault_rejects_empty_panic_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))

    with pytest.raises(ValueError, match="Panic password cannot be empty"):
        createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), "")

    assert not vault_path.exists()


def test_change_master_password_rejects_empty_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    with pytest.raises(ValueError, match="cannot be empty"):
        changeMasterPassword(
            str(vault_path),
            MASTER_PASSWORD,
            str(keyfile_path),
            "",
        )

    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == []


def test_update_entry_changes_selected_fields(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    addEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        title="GitHub",
        username="old@example.com",
        password="old-secret",
        url="https://github.com",
        notes="Old note",
    )

    updated = updateEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        "github",
        username="new@example.com",
        password="new-secret",
    )

    assert updated is True

    entry = getEntry(str(vault_path), MASTER_PASSWORD, str(keyfile_path), "GitHub")

    assert entry is not None
    assert entry["title"] == "GitHub"
    assert entry["username"] == "new@example.com"
    assert entry["password"] == "new-secret"
    assert entry["url"] == "https://github.com"
    assert entry["notes"] == "Old note"


def test_update_entry_returns_false_when_title_is_missing(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    assert (
        updateEntry(
            str(vault_path),
            MASTER_PASSWORD,
            str(keyfile_path),
            "Missing",
            username="new@example.com",
        )
        is False
    )


def test_change_master_password_reencrypts_vault(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"
    new_master_password = "new-master-password"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)
    addEntry(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        title="GitHub",
        username="test@example.com",
        password="supersecret",
    )

    changeMasterPassword(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        new_master_password,
    )

    with pytest.raises(InvalidTag):
        listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path))

    assert listEntries(str(vault_path), new_master_password, str(keyfile_path)) == ["GitHub"]
    assert isPanicPassword(str(vault_path), PANIC_PASSWORD, str(keyfile_path)) is True


def test_change_master_password_allows_panic_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    changeMasterPassword(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        PANIC_PASSWORD,
    )

    with pytest.raises(InvalidTag):
        listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path))

    assert listEntries(str(vault_path), PANIC_PASSWORD, str(keyfile_path)) == []
    assert isPanicPassword(str(vault_path), PANIC_PASSWORD, str(keyfile_path)) is True


def test_change_panic_password_updates_panic_verifier(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    changePanicPassword(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        NEW_PANIC_PASSWORD,
    )

    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == []
    assert isPanicPassword(str(vault_path), PANIC_PASSWORD, str(keyfile_path)) is False
    assert isPanicPassword(str(vault_path), NEW_PANIC_PASSWORD, str(keyfile_path)) is True


def test_change_panic_password_rejects_empty_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    with pytest.raises(ValueError, match="Panic password cannot be empty"):
        changePanicPassword(
            str(vault_path),
            MASTER_PASSWORD,
            str(keyfile_path),
            "",
        )

    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == []
    assert isPanicPassword(str(vault_path), PANIC_PASSWORD, str(keyfile_path)) is True


def test_change_panic_password_allows_master_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test_vault.enc"
    keyfile_path = tmp_path / "vault.key"

    createKeyfile(str(keyfile_path))
    createVault(str(vault_path), MASTER_PASSWORD, str(keyfile_path), PANIC_PASSWORD)

    changePanicPassword(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        MASTER_PASSWORD,
    )

    assert listEntries(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) == []
    assert isPanicPassword(str(vault_path), MASTER_PASSWORD, str(keyfile_path)) is True
