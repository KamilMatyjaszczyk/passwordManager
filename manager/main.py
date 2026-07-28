from getpass import getpass

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
    master_password = getpass("Create master password: ")

    try:
        createVault(VAULT_PATH, master_password)
        print("Vault created.")
    except FileExistsError:
        print("Vault already exists.")


def listEntriesMenu() -> None:
    master_password = getpass("Master password: ")

    try:
        entries = listEntries(VAULT_PATH, master_password)

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
    master_password = getpass("Master password: ")
    title = input("Title to search for: ")

    try:
        entry = getEntry(VAULT_PATH, master_password, title)

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
    master_password = getpass("Master password: ")
    title = input("Title to delete: ")

    try:
        deleted = deleteEntry(VAULT_PATH, master_password, title)

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