import argparse
import os
import secrets
import string
import sys
import textwrap
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidTag

from manager import __version__
from manager.autotype import (
    DEFAULT_TYPE_DELAY_SECONDS,
    MAX_TYPE_DELAY_SECONDS,
    AutoTypeCancelledError,
    AutoTypeError,
    typeCredential,
)
from manager.attempts import (
    AttemptStateError,
    formatLockRemaining,
    getLockRemaining,
    recordFailedAttempt,
    resetAttempts,
)
from manager.clipboard import DEFAULT_CLEAR_SECONDS, copyToClipboard
from manager.config import (
    ConfigError,
    deleteConfig,
    loadConfig,
    normalizePath,
    saveConfig,
)
from manager.file_lock import VaultBusyError, vaultFileLock
from manager.keyfile import createKeyfile
from manager.keyfile_location import KeyfileLocationError, validateKeyfileLocation
from manager.secure_file import UnsafeFileError
from manager.vault import (
    AmbiguousEntryError,
    addEntry,
    changeMasterPassword,
    changePanicPassword,
    createVault,
    deleteVault,
    deleteEntry,
    getEntry,
    isMasterPassword,
    isPanicPassword,
    listEntrySummaries,
    updateEntry,
    validateNewMasterPassword,
    validateNewPanicPassword,
)
from manager.vault_schema import VaultValidationError


DEFAULT_VAULT_PATH = "vault.enc"
DEFAULT_KEYFILE_NAME = "vault.key"
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


class PanicDeleteError(RuntimeError):
    pass


def print_success(
    message: str,
    details: list[tuple[str, str]] | None = None,
) -> None:
    print(f"[OK] {message}")

    for label, value in details or []:
        print(f"  {label}: {value}")


def print_error(message: str, hint: str | None = None) -> None:
    print(f"[ERROR] {message}", file=sys.stderr)

    if hint is not None:
        print(f"[HINT] {hint}", file=sys.stderr)


def print_missing_vault_or_keyfile() -> None:
    print_error(
        "Vault or keyfile was not found.",
        "Reconnect the USB device, or run 'pm relink-keyfile PATH'.",
    )


def print_command_error(error: Exception) -> None:
    print_error(
        f"Command could not be completed: {error}",
        "Check the paths and file state, then try again.",
    )


def print_entry(entry: dict[str, str], showPassword: bool) -> None:
    print("ENTRY")
    print(f"  ID: {entry['id']}")
    print(f"  Title: {entry['title']}")
    print(f"  Username: {entry['username'] or '-'}")
    print(
        f"  Password: {entry['password']}"
        if showPassword
        else "  Password: [hidden]"
    )
    print(f"  URL: {entry['url'] or '-'}")
    print(f"  Notes: {entry['notes'] or '-'}")


def ask_master_password() -> str:
    return getpass("Master password: ")


def empty_to_none(value: str) -> str | None:
    if value == "":
        return None

    return value


def resolve_vault(args: argparse.Namespace) -> str:
    if args.vault is not None:
        return normalizePath(args.vault)

    config = loadConfig()
    return normalizePath(config.get("vault_path", DEFAULT_VAULT_PATH))


def normalize_init_keyfile_path(value: str) -> str:
    path = Path(normalizePath(value))

    if path.is_dir():
        path = path / DEFAULT_KEYFILE_NAME

    return str(path)


def ask_init_path(label: str, default: str | None = None) -> str | None:
    prompt = f"{label} [{default}]: " if default is not None else f"{label}: "

    try:
        value = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print_error("Initialization was cancelled.")
        return None

    if value:
        return value

    if default is not None:
        return default

    print_error(f"{label} cannot be empty.")
    return None


def validate_init_keyfile_path(keyfilePath: str) -> None:
    validateKeyfileLocation(keyfilePath)
    path = Path(keyfilePath)

    if path.exists():
        return

    parent = path.parent

    if not parent.is_dir():
        raise KeyfileLocationError("Keyfile parent path does not exist.")

    if not os.access(parent, os.W_OK):
        raise KeyfileLocationError("USB destination is read-only.")


def resolve_init_paths(
    args: argparse.Namespace,
) -> tuple[str, str] | None:
    config = loadConfig()
    vaultValue = args.vault

    if vaultValue is None:
        defaultVault = normalizePath(
            config.get("vault_path", DEFAULT_VAULT_PATH)
        )
        vaultValue = ask_init_path("Vault path", defaultVault)

        if vaultValue is None:
            return None

    keyfileValue = args.keyfile or getattr(args, "usb_path", None)

    if keyfileValue is None:
        defaultKeyfile = config.get("keyfile_path")
        keyfileValue = ask_init_path(
            "USB device or keyfile path",
            defaultKeyfile,
        )

        if keyfileValue is None:
            return None

    vaultPath = normalizePath(vaultValue)
    keyfilePath = normalize_init_keyfile_path(keyfileValue)

    try:
        validate_init_keyfile_path(keyfilePath)
    except KeyfileLocationError as error:
        print_error(
            f"Invalid keyfile location: {error}",
            "Connect a writable removable USB device and try again.",
        )
        return None

    return vaultPath, keyfilePath


def require_keyfile(args: argparse.Namespace) -> str | None:
    if args.keyfile is not None:
        keyfilePath = args.keyfile
    else:
        config = loadConfig()
        keyfilePath = config.get("keyfile_path")

        if keyfilePath is None:
            print_error(
                "No keyfile is configured.",
                "Use '--keyfile PATH' or run 'pm relink-keyfile PATH'.",
            )
            return None

    keyfilePath = normalizePath(keyfilePath)

    try:
        validateKeyfileLocation(keyfilePath)
    except KeyfileLocationError as error:
        print_error(f"Invalid keyfile location: {error}")
        return None

    return keyfilePath


def print_lock_message(seconds: int) -> None:
    print_error(
        f"Vault is temporarily locked. "
        f"Try again in {formatLockRemaining(seconds)}."
    )


def delete_panic_data(vaultPath: str) -> None:
    try:
        with vaultFileLock(vaultPath):
            deleteVault(vaultPath)
            deleteConfig()
            resetAttempts()
    except Exception as error:
        raise PanicDeleteError("Panic deletion did not complete.") from error


def handle_panic_attempt(
    vaultPath: str,
    keyfilePath: str,
    passwordValue: str,
) -> bool:
    try:
        panicMatched = isPanicPassword(vaultPath, passwordValue, keyfilePath)
    except Exception:
        return False

    if not panicMatched:
        return False

    try:
        delete_panic_data(vaultPath)
    except PanicDeleteError:
        # Keep panic behavior indistinguishable from an ordinary unlock failure.
        pass

    print_error("Could not unlock vault.")
    return True


def handle_locked_attempt(vaultPath: str, keyfilePath: str, passwordValue: str) -> bool:
    try:
        remainingSeconds = getLockRemaining(vaultPath, keyfilePath)
    except (AttemptStateError, UnsafeFileError):
        try:
            if handle_panic_attempt(vaultPath, keyfilePath, passwordValue):
                return True
        except Exception:
            pass

        print_error(
            "Failed-attempt state could not be verified.",
            "Check that the vault, USB keyfile, and attempts.enc belong together.",
        )
        return True

    if remainingSeconds <= 0:
        return False

    try:
        if (
            not isMasterPassword(vaultPath, passwordValue, keyfilePath)
            and handle_panic_attempt(vaultPath, keyfilePath, passwordValue)
        ):
            return True
    except Exception:
        pass

    print_lock_message(remainingSeconds)
    return True


def handle_unlock_failure(vaultPath: str, keyfilePath: str, passwordValue: str) -> int:
    if handle_panic_attempt(vaultPath, keyfilePath, passwordValue):
        return EXIT_ERROR

    try:
        remainingSeconds = recordFailedAttempt(vaultPath, keyfilePath)
    except (AttemptStateError, UnsafeFileError):
        print_error(
            "Failed-attempt state could not be verified.",
            "Check that the vault, USB keyfile, and attempts.enc belong together.",
        )
        return EXIT_ERROR

    if remainingSeconds > 0:
        print_lock_message(remainingSeconds)
    else:
        print_error("Could not unlock vault.")

    return EXIT_ERROR


def handle_vault_validation_error(error: VaultValidationError) -> int:
    resetAttempts()
    print_error(
        f"Vault validation failed: {error}",
        "The vault was not modified.",
    )
    return EXIT_ERROR


def handle_init(args: argparse.Namespace) -> int:
    resolvedPaths = resolve_init_paths(args)

    if resolvedPaths is None:
        return EXIT_ERROR

    vaultPath, keyfilePath = resolvedPaths

    master_password = getpass("Create master password: ")
    confirm_password = getpass("Confirm master password: ")

    if master_password != confirm_password:
        print_error("Master passwords do not match.")
        return EXIT_USAGE

    try:
        validateNewMasterPassword(master_password)
    except ValueError as error:
        print_error(str(error))
        return EXIT_USAGE

    panic_password = getpass("Create panic delete password: ")
    confirm_panic_password = getpass("Confirm panic delete password: ")

    if panic_password != confirm_panic_password:
        print_error("Panic passwords do not match.")
        return EXIT_USAGE

    try:
        validateNewPanicPassword(panic_password)
    except ValueError as error:
        print_error(str(error))
        return EXIT_USAGE

    try:
        keyfileCreated = False

        if not Path(keyfilePath).exists():
            createKeyfile(keyfilePath)
            keyfileCreated = True

        createVault(vaultPath, master_password, keyfilePath, panic_password)
        saveConfig(vaultPath, keyfilePath)
        resetAttempts()
        details = [
            ("Vault", vaultPath),
            ("Keyfile", keyfilePath),
            ("Configuration", "saved for future commands"),
        ]

        if keyfileCreated:
            details.append(("Keyfile status", "created"))

        print_success("Vault created and ready.", details)
        return EXIT_OK
    except VaultBusyError as error:
        print_error(str(error))
        return EXIT_ERROR
    except FileExistsError:
        print_error(
            f"Vault already exists: {vaultPath}",
            "Choose another path or use the existing vault.",
        )
        return EXIT_ERROR
    except FileNotFoundError:
        print_error(
            "Keyfile path was not found.",
            "Connect the USB device and verify its path.",
        )
        return EXIT_ERROR
    except OSError as error:
        print_error(
            f"Vault or keyfile could not be created: {error}",
            "Check that both destinations exist and are writable.",
        )
        return EXIT_ERROR
    except ValueError as error:
        print_error(str(error))
        return EXIT_ERROR


def handle_generate_keyfile(args: argparse.Namespace) -> int:
    keyfilePath = normalizePath(args.path)

    try:
        validateKeyfileLocation(keyfilePath)
        createKeyfile(keyfilePath)
        print_success(
            "Keyfile created.",
            [
                ("Path", keyfilePath),
                ("Next", "Use this path with 'pm --keyfile PATH init'"),
            ],
        )
        return EXIT_OK
    except KeyfileLocationError as error:
        print_error(f"Invalid keyfile location: {error}")
        return EXIT_USAGE
    except FileExistsError:
        print_error(
            f"Keyfile already exists: {keyfilePath}",
            "The existing file was not overwritten.",
        )
        return EXIT_ERROR
    except FileNotFoundError:
        print_error(
            "Keyfile parent path was not found.",
            "Connect the USB device and verify its path.",
        )
        return EXIT_ERROR


def handle_relink_keyfile(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = normalizePath(args.path)

    try:
        validateKeyfileLocation(keyfilePath)
    except KeyfileLocationError as error:
        print_error(f"Invalid keyfile location: {error}")
        return EXIT_USAGE

    master_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, master_password):
        return EXIT_ERROR

    try:
        if not isMasterPassword(vaultPath, master_password, keyfilePath):
            return handle_unlock_failure(vaultPath, keyfilePath, master_password)

        saveConfig(vaultPath, keyfilePath)
        resetAttempts()
        print_success(
            "Keyfile location updated.",
            [
                ("Vault", vaultPath),
                ("Keyfile", keyfilePath),
            ],
        )
        return EXIT_OK
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def handle_add(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = require_keyfile(args)
    if keyfilePath is None:
        return EXIT_ERROR

    master_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, master_password):
        return EXIT_ERROR

    try:
        if not isMasterPassword(vaultPath, master_password, keyfilePath):
            return handle_unlock_failure(vaultPath, keyfilePath, master_password)

        resetAttempts()
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR

    title = input("Title: ")
    username = input("Username: ")
    password = getpass("Password to save: ")
    url = input("URL: ")
    notes = input("Notes: ")

    try:
        entryId = addEntry(
            vaultPath,
            master_password,
            keyfilePath,
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
        )
        print_success(
            "Entry saved.",
            [
                ("Title", title),
                ("ID", entryId[:8]),
            ],
        )
        return EXIT_OK
    except VaultBusyError as error:
        print_error(str(error))
        return EXIT_ERROR
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except InvalidTag:
        return handle_unlock_failure(vaultPath, keyfilePath, master_password)
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def handle_list(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = require_keyfile(args)
    if keyfilePath is None:
        return EXIT_ERROR

    master_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, master_password):
        return EXIT_ERROR

    try:
        entries = listEntrySummaries(vaultPath, master_password, keyfilePath)
        resetAttempts()

        if not entries:
            print("ENTRIES (0)")
            print("  The vault is empty. Add an entry with 'pm add'.")
            return EXIT_OK

        print(f"ENTRIES ({len(entries)})")
        for index, entry in enumerate(entries, start=1):
            print(f"  {index}. {entry['title']}")
            print(f"     ID: {entry['id'][:8]}")
            print(f"     Username: {entry['username'] or '-'}")

        return EXIT_OK
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except InvalidTag:
        return handle_unlock_failure(vaultPath, keyfilePath, master_password)
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def handle_get(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = require_keyfile(args)
    if keyfilePath is None:
        return EXIT_ERROR

    master_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, master_password):
        return EXIT_ERROR

    try:
        entry = getEntry(vaultPath, master_password, keyfilePath, args.selector)
        resetAttempts()

        if entry is None:
            print_error(
                f"No entry matched '{args.selector}'.",
                "Run 'pm list' to see available titles and IDs.",
            )
            return EXIT_ERROR

        print_entry(entry, args.show_password)

        return EXIT_OK
    except AmbiguousEntryError as error:
        resetAttempts()
        print_error(str(error), "Run 'pm list' and use a longer entry ID.")
        return EXIT_ERROR
    except VaultBusyError as error:
        print_error(str(error))
        return EXIT_ERROR
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except InvalidTag:
        return handle_unlock_failure(vaultPath, keyfilePath, master_password)
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def handle_copy(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = require_keyfile(args)
    if keyfilePath is None:
        return EXIT_ERROR

    master_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, master_password):
        return EXIT_ERROR

    try:
        entry = getEntry(vaultPath, master_password, keyfilePath, args.selector)
        resetAttempts()

        if entry is None:
            print_error(
                f"No entry matched '{args.selector}'.",
                "Run 'pm list' to see available titles and IDs.",
            )
            return EXIT_ERROR

        copyResult = copyToClipboard(entry["password"])

        if copyResult:
            historyProtection = (
                "requested"
                if getattr(copyResult, "historyProtection", False)
                else "unavailable; timed clear only"
            )
            print_success(
                "Password copied to the clipboard.",
                [
                    ("Entry", entry["title"]),
                    ("Automatic clear", f"{DEFAULT_CLEAR_SECONDS} seconds"),
                    ("History protection", historyProtection),
                ],
            )
            return EXIT_OK
        else:
            print_error(
                "Password could not be copied securely.",
                "Install a supported clipboard tool or use "
                "'pm get SELECTOR --show-password'.",
            )
            return EXIT_ERROR

    except AmbiguousEntryError as error:
        resetAttempts()
        print_error(str(error), "Run 'pm list' and use a longer entry ID.")
        return EXIT_ERROR
    except VaultBusyError as error:
        print_error(str(error))
        return EXIT_ERROR
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except InvalidTag:
        return handle_unlock_failure(vaultPath, keyfilePath, master_password)
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def handle_type(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = require_keyfile(args)
    if keyfilePath is None:
        return EXIT_ERROR

    master_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, master_password):
        return EXIT_ERROR

    try:
        entry = getEntry(vaultPath, master_password, keyfilePath, args.selector)
        resetAttempts()

        if entry is None:
            print_error(
                f"No entry matched '{args.selector}'.",
                "Run 'pm list' to see available titles and IDs.",
            )
            return EXIT_ERROR

        mode = "password"

        if args.username:
            mode = "username"
        elif args.login:
            mode = "login"

        typeResult = typeCredential(
            entry["username"],
            entry["password"],
            mode,
            args.delay,
        )
        typedValue = {
            "password": "Password",
            "username": "Username",
            "login": "Username and password",
        }[mode]
        print_success(
            f"{typedValue} typed.",
            [
                ("Entry", entry["title"]),
                ("Backend", typeResult.backendName),
                ("Enter key", "not pressed"),
            ],
        )
        return EXIT_OK
    except AutoTypeCancelledError:
        print_error("Auto-type was cancelled. Nothing was typed.")
        return EXIT_ERROR
    except AutoTypeError as error:
        print_error(
            f"Auto-type could not be completed: {error}",
            "Keep the target field focused and check desktop permissions.",
        )
        return EXIT_ERROR
    except AmbiguousEntryError as error:
        resetAttempts()
        print_error(str(error), "Run 'pm list' and use a longer entry ID.")
        return EXIT_ERROR
    except VaultBusyError as error:
        print_error(str(error))
        return EXIT_ERROR
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except InvalidTag:
        return handle_unlock_failure(vaultPath, keyfilePath, master_password)
    except KeyboardInterrupt:
        print_error("Auto-type was cancelled. Nothing more was typed.")
        return EXIT_ERROR
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def handle_edit(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = require_keyfile(args)
    if keyfilePath is None:
        return EXIT_ERROR

    master_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, master_password):
        return EXIT_ERROR

    try:
        entry = getEntry(vaultPath, master_password, keyfilePath, args.selector)

        if entry is None:
            resetAttempts()
            print_error(
                f"No entry matched '{args.selector}'.",
                "Run 'pm list' to see available titles and IDs.",
            )
            return EXIT_ERROR

        newTitle = input(f"Title [{entry['title']}]: ")
        username = input(f"Username [{entry['username']}]: ")
        password = getpass("Password [leave blank to keep]: ")
        url = input(f"URL [{entry['url']}]: ")
        notes = input(f"Notes [{entry['notes']}]: ")

        updated = updateEntry(
            vaultPath,
            master_password,
            keyfilePath,
            args.selector,
            newTitle=empty_to_none(newTitle),
            username=empty_to_none(username),
            password=empty_to_none(password),
            url=empty_to_none(url),
            notes=empty_to_none(notes),
        )
        resetAttempts()

        if updated:
            print_success(
                "Entry updated.",
                [
                    ("Title", newTitle or entry["title"]),
                    ("ID", entry["id"][:8]),
                ],
            )
            return EXIT_OK
        else:
            print_error(f"No entry matched '{args.selector}'.")
            return EXIT_ERROR

    except AmbiguousEntryError as error:
        resetAttempts()
        print_error(str(error), "Run 'pm list' and use a longer entry ID.")
        return EXIT_ERROR
    except VaultBusyError as error:
        print_error(str(error))
        return EXIT_ERROR
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except InvalidTag:
        return handle_unlock_failure(vaultPath, keyfilePath, master_password)
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def handle_delete(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = require_keyfile(args)
    if keyfilePath is None:
        return EXIT_ERROR

    master_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, master_password):
        return EXIT_ERROR

    try:
        deleted = deleteEntry(vaultPath, master_password, keyfilePath, args.selector)
        resetAttempts()

        if deleted:
            print_success(
                "Entry deleted.",
                [("Selector", args.selector)],
            )
            return EXIT_OK
        else:
            print_error(
                f"No entry matched '{args.selector}'.",
                "Run 'pm list' to see available titles and IDs.",
            )
            return EXIT_ERROR

    except AmbiguousEntryError as error:
        resetAttempts()
        print_error(str(error), "Run 'pm list' and use a longer entry ID.")
        return EXIT_ERROR
    except VaultBusyError as error:
        print_error(str(error))
        return EXIT_ERROR
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except InvalidTag:
        return handle_unlock_failure(vaultPath, keyfilePath, master_password)
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def handle_change_master_password(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = require_keyfile(args)
    if keyfilePath is None:
        return EXIT_ERROR

    old_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, old_password):
        return EXIT_ERROR

    new_password = getpass("New master password: ")
    confirm_password = getpass("Confirm new master password: ")

    if new_password != confirm_password:
        print_error("New master passwords do not match.")
        return EXIT_USAGE

    try:
        validateNewMasterPassword(new_password)
    except ValueError as error:
        print_error(str(error))
        return EXIT_USAGE

    if new_password == old_password:
        print_error("New master password must be different.")
        return EXIT_USAGE

    try:
        changeMasterPassword(vaultPath, old_password, keyfilePath, new_password)
        resetAttempts()
        print_success("Master password changed.")
        return EXIT_OK

    except VaultBusyError as error:
        print_error(str(error))
        return EXIT_ERROR
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except ValueError as error:
        print_error(str(error))
        return EXIT_ERROR
    except InvalidTag:
        return handle_unlock_failure(vaultPath, keyfilePath, old_password)
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def handle_change_panic_password(args: argparse.Namespace) -> int:
    vaultPath = resolve_vault(args)
    keyfilePath = require_keyfile(args)
    if keyfilePath is None:
        return EXIT_ERROR

    master_password = ask_master_password()

    if handle_locked_attempt(vaultPath, keyfilePath, master_password):
        return EXIT_ERROR

    new_panic_password = getpass("New panic delete password: ")
    confirm_password = getpass("Confirm new panic delete password: ")

    if new_panic_password != confirm_password:
        print_error("New panic passwords do not match.")
        return EXIT_USAGE

    try:
        validateNewPanicPassword(new_panic_password)
    except ValueError as error:
        print_error(str(error))
        return EXIT_USAGE

    try:
        changePanicPassword(vaultPath, master_password, keyfilePath, new_panic_password)
        resetAttempts()
        print_success("Panic password changed.")
        return EXIT_OK

    except VaultBusyError as error:
        print_error(str(error))
        return EXIT_ERROR
    except VaultValidationError as error:
        return handle_vault_validation_error(error)
    except FileNotFoundError:
        print_missing_vault_or_keyfile()
        return EXIT_ERROR
    except ValueError as error:
        print_error(str(error))
        return EXIT_ERROR
    except InvalidTag:
        return handle_unlock_failure(vaultPath, keyfilePath, master_password)
    except Exception as error:
        print_command_error(error)
        return EXIT_ERROR


def generate_password(length: int) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation

    password = "".join(
        secrets.choice(characters)
        for _ in range(length)
    )

    return password


def handle_generate(args: argparse.Namespace) -> int:
    if args.length < 8:
        print_error(
            "Password length must be at least 8 characters.",
            "Example: pm generate --length 24",
        )
        return EXIT_USAGE

    password = generate_password(args.length)
    print(password)
    return EXIT_OK


class CliHelpFormatter(argparse.HelpFormatter):
    def _fill_text(self, text: str, width: int, indent: str) -> str:
        formattedLines = []

        for line in text.splitlines():
            if line == "":
                formattedLines.append("")
            elif line.startswith("  "):
                formattedLines.append(f"{indent}{line}")
            else:
                formattedLines.append(
                    textwrap.fill(
                        line,
                        width,
                        initial_indent=indent,
                        subsequent_indent=indent,
                    )
                )

        return "\n".join(formattedLines)


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print_error(message, "Run 'pm --help' to see commands and examples.")
        raise SystemExit(EXIT_USAGE)


def build_parser() -> argparse.ArgumentParser:
    parser = CliArgumentParser(
        prog="pm",
        description=(
            "Local password manager protected by a master password and "
            "a keyfile stored on a removable device."
        ),
        epilog=(
            "Quick start:\n"
            "  pm init\n"
            "  pm add\n"
            "  pm list\n\n"
            "Use 'pm COMMAND --help' for command-specific guidance."
        ),
        formatter_class=CliHelpFormatter,
    )

    parser.add_argument(
        "--vault",
        default=None,
        metavar="PATH",
        help="override the configured encrypted vault path",
    )
    parser.add_argument(
        "--keyfile",
        metavar="PATH",
        help="override the configured USB keyfile path",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="COMMAND",
    )

    init_parser = subparsers.add_parser(
        "init",
        help="create and configure a new encrypted vault",
        description=(
            "Create an encrypted vault protected by a new master password and "
            "panic password. Missing paths are requested interactively. A USB "
            "directory is stored as USB_DIRECTORY/vault.key."
        ),
        epilog=(
            "Examples:\n"
            "  pm init\n"
            "  pm init /media/USB\n"
            "  pm --vault /secure/vault.enc "
            "--keyfile /media/USB/vault.key init\n"
            "  pm init --vault /secure/vault.enc "
            "--keyfile /media/USB/vault.key"
        ),
        formatter_class=CliHelpFormatter,
    )
    init_parser.add_argument(
        "usb_path",
        nargs="?",
        metavar="USB_PATH",
        help="optional USB directory or complete keyfile path",
    )
    init_parser.add_argument(
        "--vault",
        default=argparse.SUPPRESS,
        metavar="PATH",
        help="encrypted vault destination",
    )
    init_parser.add_argument(
        "--keyfile",
        default=argparse.SUPPRESS,
        metavar="PATH",
        help="USB directory or complete keyfile path",
    )
    init_parser.set_defaults(func=handle_init)

    keyfile_parser = subparsers.add_parser(
        "generate-keyfile",
        help="create a random keyfile on a removable device",
        description=(
            "Create a new random keyfile. The destination must be on a "
            "removable device and an existing file is never overwritten."
        ),
        epilog="Example:\n  pm generate-keyfile /media/USB/vault.key",
        formatter_class=CliHelpFormatter,
    )
    keyfile_parser.add_argument(
        "path",
        metavar="PATH",
        help="destination for the new keyfile",
    )
    keyfile_parser.set_defaults(func=handle_generate_keyfile)

    relink_keyfile_parser = subparsers.add_parser(
        "relink-keyfile",
        help="save a new path to the existing keyfile",
        description=(
            "Update the configured keyfile path after moving it or changing "
            "USB mount points. The selected file must be the same keyfile "
            "that encrypts the vault."
        ),
        epilog="Example:\n  pm relink-keyfile /media/NEW_USB/vault.key",
        formatter_class=CliHelpFormatter,
    )
    relink_keyfile_parser.add_argument(
        "path",
        metavar="PATH",
        help="new path to the existing keyfile",
    )
    relink_keyfile_parser.set_defaults(func=handle_relink_keyfile)

    add_parser = subparsers.add_parser(
        "add",
        help="add a credential to the vault",
        description="Unlock the vault, collect the credential fields, and save them.",
        epilog="Example:\n  pm add",
        formatter_class=CliHelpFormatter,
    )
    add_parser.set_defaults(func=handle_add)

    list_parser = subparsers.add_parser(
        "list",
        help="list entry titles, IDs, and usernames",
        description=(
            "List non-secret summary fields for every entry. Passwords are "
            "never included."
        ),
        epilog="Example:\n  pm list",
        formatter_class=CliHelpFormatter,
    )
    list_parser.set_defaults(func=handle_list)

    get_parser = subparsers.add_parser(
        "get",
        help="show one entry with its password hidden",
        description=(
            "Show one entry selected by exact title, full ID, or an ID prefix "
            "of at least eight characters. The password is hidden by default."
        ),
        epilog=(
            "Examples:\n"
            "  pm get GitHub\n"
            "  pm get 8f30a12b --show-password"
        ),
        formatter_class=CliHelpFormatter,
    )
    get_parser.add_argument(
        "selector",
        metavar="SELECTOR",
        help="entry title, full ID, or ID prefix",
    )
    get_parser.add_argument(
        "--show-password",
        action="store_true",
        help="print the password in the terminal",
    )
    get_parser.set_defaults(func=handle_get)

    copy_parser = subparsers.add_parser(
        "copy",
        help="copy an entry password to the clipboard",
        description=(
            "Copy a password without printing it. The clipboard is cleared "
            f"after {DEFAULT_CLEAR_SECONDS} seconds if it is unchanged."
        ),
        epilog="Example:\n  pm copy GitHub",
        formatter_class=CliHelpFormatter,
    )
    copy_parser.add_argument(
        "selector",
        metavar="SELECTOR",
        help="entry title, full ID, or ID prefix",
    )
    copy_parser.set_defaults(func=handle_copy)

    type_parser = subparsers.add_parser(
        "type",
        help="type a credential into the focused application",
        description=(
            "Unlock one entry and type it as simulated keyboard input without "
            "using the clipboard. Password is the default. Enter is never "
            "pressed automatically."
        ),
        epilog=(
            "Examples:\n"
            "  pm type GitHub\n"
            "  pm type GitHub --username\n"
            "  pm type GitHub --login --delay 5"
        ),
        formatter_class=CliHelpFormatter,
    )
    type_parser.add_argument(
        "selector",
        metavar="SELECTOR",
        help="entry title, full ID, or ID prefix",
    )
    type_mode = type_parser.add_mutually_exclusive_group()
    type_mode.add_argument(
        "--username",
        action="store_true",
        help="type only the username instead of the password",
    )
    type_mode.add_argument(
        "--login",
        action="store_true",
        help="type username, Tab, and password without pressing Enter",
    )
    type_parser.add_argument(
        "--delay",
        type=int,
        default=DEFAULT_TYPE_DELAY_SECONDS,
        choices=range(0, MAX_TYPE_DELAY_SECONDS + 1),
        metavar="SECONDS",
        help=(
            f"seconds to wait before typing (default: "
            f"{DEFAULT_TYPE_DELAY_SECONDS}, maximum: "
            f"{MAX_TYPE_DELAY_SECONDS})"
        ),
    )
    type_parser.set_defaults(func=handle_type)

    edit_parser = subparsers.add_parser(
        "edit",
        help="edit an existing credential",
        description=(
            "Update one entry. Leave a prompt blank to keep its current value."
        ),
        epilog="Example:\n  pm edit GitHub",
        formatter_class=CliHelpFormatter,
    )
    edit_parser.add_argument(
        "selector",
        metavar="SELECTOR",
        help="entry title, full ID, or ID prefix",
    )
    edit_parser.set_defaults(func=handle_edit)

    delete_parser = subparsers.add_parser(
        "delete",
        help="delete one credential from the vault",
        description=(
            "Permanently delete one selected entry. This does not delete the "
            "vault itself."
        ),
        epilog="Example:\n  pm delete GitHub",
        formatter_class=CliHelpFormatter,
    )
    delete_parser.add_argument(
        "selector",
        metavar="SELECTOR",
        help="entry title, full ID, or ID prefix",
    )
    delete_parser.set_defaults(func=handle_delete)

    change_master_parser = subparsers.add_parser(
        "change-master-password",
        help="replace the vault master password",
        description=(
            "Re-encrypt the vault with a new master password. The USB keyfile "
            "does not change."
        ),
        epilog="Example:\n  pm change-master-password",
        formatter_class=CliHelpFormatter,
    )
    change_master_parser.set_defaults(func=handle_change_master_password)

    change_panic_parser = subparsers.add_parser(
        "change-panic-password",
        help="replace the panic delete password",
        description=(
            "Set a new panic password. Entering this password during an unlock "
            "attempt deletes the local vault, configuration, and attempt state."
        ),
        epilog="Example:\n  pm change-panic-password",
        formatter_class=CliHelpFormatter,
    )
    change_panic_parser.set_defaults(func=handle_change_panic_password)

    generate_parser = subparsers.add_parser(
        "generate",
        help="print a randomly generated password",
        description=(
            "Generate a random password and print only the password, making "
            "the command suitable for scripts."
        ),
        epilog="Example:\n  pm generate --length 24",
        formatter_class=CliHelpFormatter,
    )
    generate_parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=20,
        metavar="NUMBER",
        help="password length (default: 20, minimum: 8)",
    )
    generate_parser.set_defaults(func=handle_generate)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        return args.func(args)
    except ConfigError as error:
        print_error(
            f"Configuration could not be read: {error}",
            "Repair or remove the configuration file, then run the command again.",
        )
        return EXIT_USAGE
    except (EOFError, KeyboardInterrupt):
        print_error("Command cancelled.")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
