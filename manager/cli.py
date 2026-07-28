import argparse
import secrets
import string
from getpass import getpass

from cryptography.exceptions import InvalidTag

from manager.vault import (
    createVault,
    addEntry,
    listEntries,
    getEntry,
    deleteEntry,
)


DEFAULT_VAULT_PATH = "vault.enc"


def ask_master_password() -> str:
    return getpass("Master password: ")


def handle_init(args: argparse.Namespace) -> None:
    master_password = getpass("Create master password: ")
    confirm_password = getpass("Confirm master password: ")

    if master_password != confirm_password:
        print("Passwords do not match.")
        return

    try:
        createVault(args.vault, master_password)
        print(f"Vault created: {args.vault}")
    except FileExistsError:
        print(f"Vault already exists: {args.vault}")


def handle_add(args: argparse.Namespace) -> None:
    master_password = ask_master_password()

    title = input("Title: ")
    username = input("Username: ")
    password = getpass("Password to save: ")
    url = input("URL: ")
    notes = input("Notes: ")

    try:
        addEntry(
            args.vault,
            master_password,
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
        )
        print("Entry saved.")
    except FileNotFoundError:
        print("Vault does not exist. Run init first.")
    except InvalidTag:
        print("Wrong master password.")
    except Exception as error:
        print(f"Something went wrong: {error}")


def handle_list(args: argparse.Namespace) -> None:
    master_password = ask_master_password()

    try:
        entries = listEntries(args.vault, master_password)

        if not entries:
            print("No entries found.")
            return

        print("Entries:")
        for entry in entries:
            print(f"- {entry}")

    except FileNotFoundError:
        print("Vault does not exist. Run init first.")
    except InvalidTag:
        print("Wrong master password.")
    except Exception as error:
        print(f"Something went wrong: {error}")


def handle_get(args: argparse.Namespace) -> None:
    master_password = ask_master_password()

    try:
        entry = getEntry(args.vault, master_password, args.title)

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
        print("Vault does not exist. Run init first.")
    except InvalidTag:
        print("Wrong master password.")
    except Exception as error:
        print(f"Something went wrong: {error}")


def handle_delete(args: argparse.Namespace) -> None:
    master_password = ask_master_password()

    try:
        deleted = deleteEntry(args.vault, master_password, args.title)

        if deleted:
            print("Entry deleted.")
        else:
            print("Entry not found.")

    except FileNotFoundError:
        print("Vault does not exist. Run init first.")
    except InvalidTag:
        print("Wrong master password.")
    except Exception as error:
        print(f"Something went wrong: {error}")


def generate_password(length: int) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation

    password = "".join(
        secrets.choice(characters)
        for _ in range(length)
    )

    return password


def handle_generate(args: argparse.Namespace) -> None:
    if args.length < 8:
        print("Password length should be at least 8.")
        return

    password = generate_password(args.length)
    print(password)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local encrypted password manager"
    )

    parser.add_argument(
        "--vault",
        default=DEFAULT_VAULT_PATH,
        help="Path to the encrypted vault file",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    init_parser = subparsers.add_parser(
        "init",
        help="Create a new vault",
    )
    init_parser.set_defaults(func=handle_init)

    add_parser = subparsers.add_parser(
        "add",
        help="Add a new entry",
    )
    add_parser.set_defaults(func=handle_add)

    list_parser = subparsers.add_parser(
        "list",
        help="List all entries",
    )
    list_parser.set_defaults(func=handle_list)

    get_parser = subparsers.add_parser(
        "get",
        help="Get one entry",
    )
    get_parser.add_argument("title", help="Entry title")
    get_parser.set_defaults(func=handle_get)

    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete one entry",
    )
    delete_parser.add_argument("title", help="Entry title")
    delete_parser.set_defaults(func=handle_delete)

    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate a strong password",
    )
    generate_parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=20,
        help="Password length",
    )
    generate_parser.set_defaults(func=handle_generate)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()