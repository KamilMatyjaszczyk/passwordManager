import copy

import pytest

from manager import vault_schema
from manager.vault_schema import (
    MAX_TITLE_LENGTH,
    VaultValidationError,
    validateVaultData,
)


ENTRY_ID = "0123456789abcdef0123456789abcdef"
VALID_ENTRY = {
    "id": ENTRY_ID,
    "title": "GitHub",
    "username": "test@example.com",
    "password": "secret",
    "url": "https://github.com",
    "notes": "Test account",
}


def buildVault(entry: dict | None = None) -> dict:
    return {
        "schema_version": 2,
        "entries": [] if entry is None else [entry],
    }


def test_valid_vault_schema_is_accepted() -> None:
    validateVaultData(buildVault(copy.deepcopy(VALID_ENTRY)))


def test_vault_rejects_missing_root_field() -> None:
    vault = {"schema_version": 2}

    with pytest.raises(VaultValidationError, match="missing fields: entries"):
        validateVaultData(vault)


def test_vault_rejects_unknown_entry_field() -> None:
    entry = copy.deepcopy(VALID_ENTRY)
    entry["extra"] = "unexpected"

    with pytest.raises(VaultValidationError, match="unknown fields: extra"):
        validateVaultData(buildVault(entry))


def test_vault_rejects_boolean_schema_version() -> None:
    vault = buildVault()
    vault["schema_version"] = True

    with pytest.raises(VaultValidationError, match="must be an integer"):
        validateVaultData(vault)


def test_vault_rejects_entries_with_wrong_type() -> None:
    vault = {
        "schema_version": 2,
        "entries": {},
    }

    with pytest.raises(VaultValidationError, match="must be a list"):
        validateVaultData(vault)


def test_vault_rejects_invalid_entry_id() -> None:
    entry = copy.deepcopy(VALID_ENTRY)
    entry["id"] = ENTRY_ID.upper()

    with pytest.raises(VaultValidationError, match="lowercase hexadecimal"):
        validateVaultData(buildVault(entry))


def test_vault_rejects_duplicate_entry_ids() -> None:
    vault = {
        "schema_version": 2,
        "entries": [
            copy.deepcopy(VALID_ENTRY),
            {
                **copy.deepcopy(VALID_ENTRY),
                "title": "GitLab",
            },
        ],
    }

    with pytest.raises(VaultValidationError, match="Duplicate entry ID"):
        validateVaultData(vault)


def test_vault_rejects_too_many_entries(monkeypatch) -> None:
    monkeypatch.setattr(vault_schema, "MAX_ENTRIES", 1)
    second_entry = {
        **copy.deepcopy(VALID_ENTRY),
        "id": "fedcba9876543210fedcba9876543210",
    }
    vault = {
        "schema_version": 2,
        "entries": [copy.deepcopy(VALID_ENTRY), second_entry],
    }

    with pytest.raises(VaultValidationError, match="more than 1 entries"):
        validateVaultData(vault)


def test_vault_rejects_empty_password() -> None:
    entry = copy.deepcopy(VALID_ENTRY)
    entry["password"] = ""

    with pytest.raises(VaultValidationError, match="password cannot be empty"):
        validateVaultData(buildVault(entry))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", 123),
        ("username", None),
        ("password", ["secret"]),
        ("url", {"value": "https://example.com"}),
        ("notes", b"notes"),
    ],
)
def test_vault_rejects_non_text_entry_fields(field, value) -> None:
    entry = copy.deepcopy(VALID_ENTRY)
    entry[field] = value

    with pytest.raises(VaultValidationError, match=f"{field} must be text"):
        validateVaultData(buildVault(entry))


def test_vault_rejects_oversized_title() -> None:
    entry = copy.deepcopy(VALID_ENTRY)
    entry["title"] = "a" * (MAX_TITLE_LENGTH + 1)

    with pytest.raises(VaultValidationError, match="character limit"):
        validateVaultData(buildVault(entry))


def test_vault_rejects_terminal_control_sequence() -> None:
    entry = copy.deepcopy(VALID_ENTRY)
    entry["title"] = "GitHub\x1b[2J"

    with pytest.raises(VaultValidationError, match="control characters"):
        validateVaultData(buildVault(entry))


def test_vault_allows_multiline_notes() -> None:
    entry = copy.deepcopy(VALID_ENTRY)
    entry["notes"] = "First line\nSecond line\tIndented"

    validateVaultData(buildVault(entry))
