from pathlib import Path

from manager.vault import (
    createVault,
    addEntry,
    listEntries,
    getEntry,
    deleteEntry,
)


VAULT_PATH = "test_vault.enc"
MASTER_PASSWORD = "test-master-password"


def main() -> None:
    test_vault = Path(VAULT_PATH)

    # Sletter gammel test-vault slik at testen kan kjøres flere ganger
    if test_vault.exists():
        test_vault.unlink()

    print("Creating vault...")
    createVault(VAULT_PATH, MASTER_PASSWORD)

    print("Adding entry...")
    addEntry(
        VAULT_PATH,
        MASTER_PASSWORD,
        title="GitHub",
        username="test@example.com",
        password="supersecret",
        url="https://github.com",
        notes="Test account",
    )

    print("Listing entries...")
    entries = listEntries(VAULT_PATH, MASTER_PASSWORD)
    print(entries)

    assert "GitHub" in entries

    print("Getting entry...")
    entry = getEntry(VAULT_PATH, MASTER_PASSWORD, "GitHub")
    print(entry)

    assert entry is not None
    assert entry["title"] == "GitHub"
    assert entry["username"] == "test@example.com"
    assert entry["password"] == "supersecret"
    assert entry["url"] == "https://github.com"
    assert entry["notes"] == "Test account"

    print("Deleting entry...")
    deleted = deleteEntry(VAULT_PATH, MASTER_PASSWORD, "GitHub")
    print("Deleted:", deleted)

    assert deleted is True

    print("Listing entries after delete...")
    entries_after_delete = listEntries(VAULT_PATH, MASTER_PASSWORD)
    print(entries_after_delete)

    assert entries_after_delete == []

    print("Vault test passed!")


if __name__ == "__main__":
    main()