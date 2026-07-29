from getpass import getpass
from pathlib import Path

from manager.keyfile import createKeyfile
from manager.vault import (
    createVault,
    listEntries,
    addEntry,
    getEntry,
    deleteEntry,
)


VAULT_PATH = "vault.enc"


def showMenu() -> None:
    print()
    print("Password Manager")
    print("1. Create vault")
    print("2. List entries")
    print("3. Add entry")
    print("4. Get entry")
    print("5. Delete entry")
    print("6. Exit")


def createVaultMenu() -> None:
    keyfile_path = input("Keyfile path: ")
    master_password = getpass("Create master password: ")

    try:
        if not Path(keyfile_path).exists():
            createKeyfile(keyfile_path)
            print("Keyfile created.")

        createVault(VAULT_PATH, master_password, keyfile_path)
        print("Vault created.")
    except FileExistsError:
        print("Vault already exists.")
    except FileNotFoundError:
        print("Keyfile path not found. Check that the USB path exists.")


def listEntriesMenu() -> None:
    keyfile_path = input("Keyfile path: ")
    master_password = getpass("Master password: ")

    try:
        entries = listEntries(VAULT_PATH, master_password, keyfile_path)

        if not entries:
            print("No entries found.")
            return

        print("Entries:")
        for entry in entries:
            print(f"- {entry}")

    except FileNotFoundError:
        print("Vault does not exist. Create one first.")
    except Exception:
        print("Could not unlock vault. Wrong password or corrupted vault.")


def addEntryMenu() -> None:
    keyfile_path = input("Keyfile path: ")
    master_password = getpass("Master password: ")

    title = input("Title: ")
    username = input("Username: ")
    password = getpass("Password to save: ")
    url = input("URL: ")
    notes = input("Notes: ")

    try:
        addEntry(
            VAULT_PATH,
            master_password,
            keyfile_path,
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
        )

        print("Entry saved.")

    except FileNotFoundError:
        print("Vault does not exist. Create one first.")
    except Exception:
        print("Could not unlock vault. Wrong password or corrupted vault.")


def getEntryMenu() -> None:
    keyfile_path = input("Keyfile path: ")
    master_password = getpass("Master password: ")
    title = input("Title to search for: ")

    try:
        entry = getEntry(VAULT_PATH, master_password, keyfile_path, title)

        if entry is None:
            print("Entry not found.")
            return

        print()
        print(f"Title: {entry['title']}")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")
        print(f"URL: {entry['url']}")
        print(f"Notes: {entry['notes']}")

    except FileNotFoundError:
        print("Vault does not exist. Create one first.")
    except Exception:
        print("Could not unlock vault. Wrong password or corrupted vault.")


def deleteEntryMenu() -> None:
    keyfile_path = input("Keyfile path: ")
    master_password = getpass("Master password: ")
    title = input("Title to delete: ")

    try:
        deleted = deleteEntry(VAULT_PATH, master_password, keyfile_path, title)

        if deleted:
            print("Entry deleted.")
        else:
            print("Entry not found.")

    except FileNotFoundError:
        print("Vault does not exist. Create one first.")
    except Exception:
        print("Could not unlock vault. Wrong password or corrupted vault.")


def main() -> None:
    while True:
        showMenu()
        choice = input("Choose an option: ")

        if choice == "1":
            createVaultMenu()
        elif choice == "2":
            listEntriesMenu()
        elif choice == "3":
            addEntryMenu()
        elif choice == "4":
            getEntryMenu()
        elif choice == "5":
            deleteEntryMenu()
        elif choice == "6":
            print("Goodbye.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
