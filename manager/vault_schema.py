import re
import unicodedata
from typing import Any


SCHEMA_VERSION = 2
MAX_ENTRIES = 10_000
MAX_TITLE_LENGTH = 256
MAX_USERNAME_LENGTH = 1_024
MAX_PASSWORD_LENGTH = 16_384
MAX_URL_LENGTH = 4_096
MAX_NOTES_LENGTH = 262_144
ENTRY_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
VAULT_FIELDS = {"schema_version", "entries"}
ENTRY_FIELDS = {"id", "title", "username", "password", "url", "notes"}


class VaultValidationError(ValueError):
    pass


def validateExactFields(
    value: dict[str, Any],
    expectedFields: set[str],
    context: str,
) -> None:
    actualFields = set(value)
    missingFields = expectedFields - actualFields
    unknownFields = actualFields - expectedFields

    if missingFields:
        fields = ", ".join(sorted(missingFields))
        raise VaultValidationError(f"{context} is missing fields: {fields}.")

    if unknownFields:
        fields = ", ".join(sorted(unknownFields))
        raise VaultValidationError(f"{context} has unknown fields: {fields}.")


def containsUnsafeControlCharacters(value: str, allowMultiline: bool) -> bool:
    allowedControls = {"\n", "\t"} if allowMultiline else set()

    return any(
        character not in allowedControls
        and unicodedata.category(character) == "Cc"
        for character in value
    )


def validateTextField(
    entry: dict[str, Any],
    field: str,
    maximumLength: int,
    *,
    allowEmpty: bool = True,
    allowMultiline: bool = False,
) -> None:
    value = entry[field]

    if not isinstance(value, str):
        raise VaultValidationError(f"Entry {field} must be text.")

    if not allowEmpty and not value.strip():
        raise VaultValidationError(f"Entry {field} cannot be empty.")

    if len(value) > maximumLength:
        raise VaultValidationError(
            f"Entry {field} exceeds the {maximumLength} character limit."
        )

    if containsUnsafeControlCharacters(value, allowMultiline):
        raise VaultValidationError(
            f"Entry {field} contains unsafe control characters."
        )


def validateEntry(entry: Any, usedIds: set[str]) -> None:
    if not isinstance(entry, dict):
        raise VaultValidationError("Every vault entry must be an object.")

    validateExactFields(entry, ENTRY_FIELDS, "Vault entry")
    entryId = entry["id"]

    if not isinstance(entryId, str) or ENTRY_ID_PATTERN.fullmatch(entryId) is None:
        raise VaultValidationError(
            "Entry ID must contain exactly 32 lowercase hexadecimal characters."
        )

    if entryId in usedIds:
        raise VaultValidationError(f"Duplicate entry ID detected: {entryId}.")

    usedIds.add(entryId)
    validateTextField(
        entry,
        "title",
        MAX_TITLE_LENGTH,
        allowEmpty=False,
    )
    validateTextField(entry, "username", MAX_USERNAME_LENGTH)
    validateTextField(
        entry,
        "password",
        MAX_PASSWORD_LENGTH,
        allowEmpty=False,
    )
    validateTextField(entry, "url", MAX_URL_LENGTH)
    validateTextField(
        entry,
        "notes",
        MAX_NOTES_LENGTH,
        allowMultiline=True,
    )


def validateVaultData(vaultData: Any) -> None:
    if not isinstance(vaultData, dict):
        raise VaultValidationError("Decrypted vault must be an object.")

    validateExactFields(vaultData, VAULT_FIELDS, "Vault")

    if type(vaultData["schema_version"]) is not int:
        raise VaultValidationError("Vault schema version must be an integer.")

    if vaultData["schema_version"] != SCHEMA_VERSION:
        raise VaultValidationError(
            f"Unsupported vault schema version: {vaultData['schema_version']}."
        )

    entries = vaultData["entries"]

    if not isinstance(entries, list):
        raise VaultValidationError("Vault entries must be a list.")

    if len(entries) > MAX_ENTRIES:
        raise VaultValidationError(
            f"Vault contains more than {MAX_ENTRIES} entries."
        )

    usedIds: set[str] = set()

    for entry in entries:
        validateEntry(entry, usedIds)
