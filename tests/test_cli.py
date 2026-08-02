import argparse
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from manager import cli
from manager.autotype import (
    AutoTypeCancelledError,
    AutoTypeError,
    AutoTypeResult,
)
from manager.attempts import getAttemptsPath, recordFailedAttempt
from manager.clipboard import ClipboardCopyResult
from manager.config import getConfigPath, saveConfig
from manager.keyfile import createKeyfile
from manager.keyfile_location import KeyfileLocationError
from manager.vault import createVault


def test_require_keyfile_validates_explicit_keyfile(
    tmp_path: Path,
    monkeypatch,
) -> None:
    validated_paths = []
    keyfilePath = str(tmp_path / "usb" / "vault.key")
    args = argparse.Namespace(keyfile=keyfilePath)

    def fake_validate(path: str) -> None:
        validated_paths.append(path)

    monkeypatch.setattr(cli, "validateKeyfileLocation", fake_validate)

    assert cli.require_keyfile(args) == keyfilePath
    assert validated_paths == [keyfilePath]


def test_require_keyfile_rejects_invalid_explicit_keyfile(
    monkeypatch,
    capsys,
) -> None:
    args = argparse.Namespace(keyfile="/home/kamil/vault.key")

    def fake_validate(path: str) -> None:
        raise KeyfileLocationError("Keyfile cannot be stored inside your home directory.")

    monkeypatch.setattr(cli, "validateKeyfileLocation", fake_validate)

    assert cli.require_keyfile(args) is None
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "[ERROR] Invalid keyfile location" in captured.err


def test_require_keyfile_validates_config_keyfile(
    tmp_path: Path,
    monkeypatch,
) -> None:
    validated_paths = []
    keyfilePath = str(tmp_path / "usb" / "vault.key")
    args = argparse.Namespace(keyfile=None)

    monkeypatch.setattr(
        cli,
        "loadConfig",
        lambda: {"keyfile_path": keyfilePath},
    )

    def fake_validate(path: str) -> None:
        validated_paths.append(path)

    monkeypatch.setattr(cli, "validateKeyfileLocation", fake_validate)

    assert cli.require_keyfile(args) == keyfilePath
    assert validated_paths == [keyfilePath]


def test_resolve_vault_returns_absolute_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "loadConfig", lambda: {"vault_path": "vault.enc"})
    args = argparse.Namespace(vault=None)

    assert cli.resolve_vault(args) == str(tmp_path / "vault.enc")


def test_init_paths_are_requested_and_usb_directory_gets_default_filename(
    tmp_path: Path,
    monkeypatch,
) -> None:
    usbDirectory = tmp_path / "usb"
    usbDirectory.mkdir()
    answers = iter(["", str(usbDirectory)])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "loadConfig", lambda: {})
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    monkeypatch.setattr(cli, "validateKeyfileLocation", lambda path: None)
    args = argparse.Namespace(vault=None, keyfile=None, usb_path=None)

    assert cli.resolve_init_paths(args) == (
        str(tmp_path / "vault.enc"),
        str(usbDirectory / "vault.key"),
    )


def test_init_rejects_read_only_usb_before_password_prompts(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    usbDirectory = tmp_path / "usb"
    usbDirectory.mkdir()
    keyfilePath = usbDirectory / "vault.key"
    monkeypatch.setattr(cli, "loadConfig", lambda: {})
    monkeypatch.setattr(cli, "validateKeyfileLocation", lambda path: None)
    monkeypatch.setattr(cli.os, "access", lambda path, mode: False)
    args = argparse.Namespace(
        vault=str(tmp_path / "vault.enc"),
        keyfile=str(keyfilePath),
        usb_path=None,
    )

    assert cli.resolve_init_paths(args) is None
    captured = capsys.readouterr()
    assert "[ERROR] Invalid keyfile location: USB destination is read-only." in (
        captured.err
    )


def test_init_parser_accepts_paths_after_command_and_usb_directory() -> None:
    parser = cli.build_parser()
    optionArgs = parser.parse_args(
        [
            "init",
            "--vault",
            "/secure/vault.enc",
            "--keyfile",
            "/media/USB/vault.key",
        ]
    )
    directoryArgs = parser.parse_args(["init", "/media/USB"])

    assert optionArgs.vault == "/secure/vault.enc"
    assert optionArgs.keyfile == "/media/USB/vault.key"
    assert directoryArgs.usb_path == "/media/USB"


def test_relink_keyfile_validates_unlock_and_saves_absolute_paths(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    vault_path = tmp_path / "vault.enc"
    keyfile_path = tmp_path / "usb" / "vault.key"
    validated = []
    saved = []
    args = argparse.Namespace(
        vault=str(vault_path),
        keyfile=None,
        path=str(keyfile_path),
    )

    monkeypatch.setattr(
        cli,
        "validateKeyfileLocation",
        lambda path: validated.append(path),
    )
    monkeypatch.setattr(cli, "ask_master_password", lambda: "master")
    monkeypatch.setattr(cli, "handle_locked_attempt", lambda *args: False)
    monkeypatch.setattr(cli, "isMasterPassword", lambda *args: True)
    monkeypatch.setattr(
        cli,
        "saveConfig",
        lambda vault, keyfile: saved.append((vault, keyfile)),
    )
    monkeypatch.setattr(cli, "resetAttempts", lambda: None)

    cli.handle_relink_keyfile(args)

    assert validated == [str(keyfile_path)]
    assert saved == [(str(vault_path), str(keyfile_path))]
    assert "Keyfile location updated" in capsys.readouterr().out


def test_locked_attempt_does_not_trigger_panic_when_password_is_master(
    monkeypatch,
    capsys,
) -> None:
    deleted = []

    monkeypatch.setattr(cli, "getLockRemaining", lambda vault, keyfile: 60)
    monkeypatch.setattr(cli, "isMasterPassword", lambda vault, password, keyfile: True)
    monkeypatch.setattr(cli, "isPanicPassword", lambda vault, password, keyfile: True)
    monkeypatch.setattr(
        cli,
        "delete_panic_data",
        lambda vault: deleted.append(vault),
    )

    assert cli.handle_locked_attempt("vault.enc", "/media/kamil/USB/vault.key", "same") is True
    assert deleted == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "[ERROR] Vault is temporarily locked. Try again in 1 minute.\n"
    )


def test_unsafe_attempt_state_blocks_without_traceback(
    monkeypatch,
    capsys,
) -> None:
    def rejectAttempts(vault: str, keyfile: str) -> int:
        raise cli.UnsafeFileError("unsafe attempts path")

    monkeypatch.setattr(cli, "getLockRemaining", rejectAttempts)
    monkeypatch.setattr(cli, "handle_panic_attempt", lambda *args: False)

    assert cli.handle_locked_attempt(
        "vault.enc",
        "/media/kamil/USB/vault.key",
        "master",
    ) is True
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "[ERROR] Failed-attempt state could not be verified." in captured.err


def test_panic_cleanup_deletes_vault_config_and_attempts(monkeypatch) -> None:
    calls = []

    @contextmanager
    def fake_lock(vault_path: str):
        calls.append(("lock", vault_path))
        yield

    monkeypatch.setattr(cli, "vaultFileLock", fake_lock)
    monkeypatch.setattr(
        cli,
        "deleteVault",
        lambda vault_path: calls.append(("vault", vault_path)),
    )
    monkeypatch.setattr(
        cli,
        "deleteConfig",
        lambda: calls.append(("config",)),
    )
    monkeypatch.setattr(
        cli,
        "resetAttempts",
        lambda: calls.append(("attempts",)),
    )

    cli.delete_panic_data("vault.enc")

    assert calls == [
        ("lock", "vault.enc"),
        ("vault", "vault.enc"),
        ("config",),
        ("attempts",),
    ]


def test_panic_cleanup_reports_internal_failure(monkeypatch) -> None:
    @contextmanager
    def fake_lock(vault_path: str):
        yield

    monkeypatch.setattr(cli, "vaultFileLock", fake_lock)
    monkeypatch.setattr(
        cli,
        "deleteVault",
        lambda vault_path: (_ for _ in ()).throw(PermissionError("denied")),
    )

    with pytest.raises(cli.PanicDeleteError):
        cli.delete_panic_data("vault.enc")


def test_failed_panic_delete_is_not_recorded_as_wrong_attempt(
    monkeypatch,
    capsys,
) -> None:
    recorded = []
    monkeypatch.setattr(cli, "isPanicPassword", lambda *args: True)
    monkeypatch.setattr(
        cli,
        "delete_panic_data",
        lambda vault_path: (_ for _ in ()).throw(cli.PanicDeleteError("failed")),
    )
    monkeypatch.setattr(
        cli,
        "recordFailedAttempt",
        lambda vault, keyfile: recorded.append((vault, keyfile)),
    )

    cli.handle_unlock_failure("vault.enc", "/media/kamil/USB/vault.key", "panic")

    assert recorded == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "[ERROR] Could not unlock vault.\n"


def test_panic_attempt_deletes_local_state_and_preserves_keyfile(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    vault_path = tmp_path / "vault.enc"
    keyfile_path = tmp_path / "vault.key"
    config_directory = tmp_path / "config"
    master_password = "master"
    panic_password = "panic"
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(config_directory))

    createKeyfile(str(keyfile_path))
    createVault(
        str(vault_path),
        master_password,
        str(keyfile_path),
        panic_password,
    )
    saveConfig(str(vault_path), str(keyfile_path))
    recordFailedAttempt(str(vault_path), str(keyfile_path))

    cli.handle_unlock_failure(
        str(vault_path),
        str(keyfile_path),
        panic_password,
    )

    assert not vault_path.exists()
    assert not getConfigPath().exists()
    assert not getAttemptsPath().exists()
    assert keyfile_path.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "[ERROR] Could not unlock vault.\n"


def test_add_rejects_wrong_master_before_collecting_entry_data(
    tmp_path: Path,
    monkeypatch,
) -> None:
    args = argparse.Namespace(
        vault=str(tmp_path / "vault.enc"),
        keyfile=str(tmp_path / "vault.key"),
    )
    failures = []

    monkeypatch.setattr(cli, "require_keyfile", lambda args: args.keyfile)
    monkeypatch.setattr(cli, "ask_master_password", lambda: "wrong")
    monkeypatch.setattr(cli, "handle_locked_attempt", lambda *args: False)
    monkeypatch.setattr(cli, "isMasterPassword", lambda *args: False)
    monkeypatch.setattr(
        cli,
        "handle_unlock_failure",
        lambda *args: failures.append(args),
    )

    def unexpectedPrompt(*args):
        raise AssertionError("Entry data was requested before authentication.")

    monkeypatch.setattr("builtins.input", unexpectedPrompt)
    monkeypatch.setattr(cli, "getpass", unexpectedPrompt)

    cli.handle_add(args)

    assert len(failures) == 1


def test_add_authenticates_before_collecting_and_saving_entry(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    args = argparse.Namespace(
        vault=str(tmp_path / "vault.enc"),
        keyfile=str(tmp_path / "vault.key"),
    )
    calls = []
    answers = iter(["GitHub", "user@example.com", "https://github.com", "note"])

    monkeypatch.setattr(cli, "require_keyfile", lambda args: args.keyfile)
    monkeypatch.setattr(cli, "ask_master_password", lambda: "master")
    monkeypatch.setattr(cli, "handle_locked_attempt", lambda *args: False)
    monkeypatch.setattr(
        cli,
        "isMasterPassword",
        lambda *args: calls.append("authenticate") or True,
    )
    monkeypatch.setattr(
        cli,
        "resetAttempts",
        lambda: calls.append("reset-attempts"),
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: calls.append(f"input:{prompt}") or next(answers),
    )
    monkeypatch.setattr(
        cli,
        "getpass",
        lambda prompt: calls.append(f"input:{prompt}") or "secret",
    )
    monkeypatch.setattr(
        cli,
        "addEntry",
        lambda *args, **kwargs: calls.append("save") or "0123456789abcdef",
    )

    cli.handle_add(args)

    assert calls[:3] == [
        "authenticate",
        "reset-attempts",
        "input:Title: ",
    ]
    assert calls[-1] == "save"
    assert capsys.readouterr().out == (
        "[OK] Entry saved.\n"
        "  Title: GitHub\n"
        "  ID: 01234567\n"
    )


@pytest.mark.parametrize(
    ("show_password", "password_is_visible"),
    [
        (False, False),
        (True, True),
    ],
)
def test_get_only_shows_password_when_requested(
    monkeypatch,
    capsys,
    show_password: bool,
    password_is_visible: bool,
) -> None:
    entry = {
        "id": "0123456789abcdef0123456789abcdef",
        "title": "GitHub",
        "username": "test@example.com",
        "password": "supersecret",
        "url": "https://github.com",
        "notes": "Test account",
    }
    args = argparse.Namespace(
        vault="vault.enc",
        keyfile="/media/kamil/USB/vault.key",
        selector="GitHub",
        show_password=show_password,
    )

    monkeypatch.setattr(cli, "require_keyfile", lambda args: args.keyfile)
    monkeypatch.setattr(cli, "ask_master_password", lambda: "master-password")
    monkeypatch.setattr(cli, "handle_locked_attempt", lambda *args: False)
    monkeypatch.setattr(cli, "getEntry", lambda *args: entry)
    monkeypatch.setattr(cli, "resetAttempts", lambda: None)

    cli.handle_get(args)
    output = capsys.readouterr().out

    assert ("supersecret" in output) is password_is_visible

    if show_password:
        assert "Password: supersecret" in output
    else:
        assert "Password: [hidden]" in output


@pytest.mark.parametrize(
    ("historyProtection", "expectedStatus"),
    [
        (True, "requested"),
        (False, "unavailable; timed clear only"),
    ],
)
def test_copy_reports_clipboard_history_protection(
    monkeypatch,
    capsys,
    historyProtection: bool,
    expectedStatus: str,
) -> None:
    entry = {
        "id": "0123456789abcdef0123456789abcdef",
        "title": "GitHub",
        "username": "test@example.com",
        "password": "supersecret",
        "url": "https://github.com",
        "notes": "",
    }
    args = argparse.Namespace(
        vault="vault.enc",
        keyfile="/media/kamil/USB/vault.key",
        selector="GitHub",
    )

    monkeypatch.setattr(cli, "require_keyfile", lambda args: args.keyfile)
    monkeypatch.setattr(cli, "ask_master_password", lambda: "master-password")
    monkeypatch.setattr(cli, "handle_locked_attempt", lambda *args: False)
    monkeypatch.setattr(cli, "getEntry", lambda *args: entry)
    monkeypatch.setattr(cli, "resetAttempts", lambda: None)
    monkeypatch.setattr(
        cli,
        "copyToClipboard",
        lambda text: ClipboardCopyResult(
            True,
            historyProtection,
            "test",
        ),
    )

    assert cli.handle_copy(args) == cli.EXIT_OK
    assert (
        f"History protection: {expectedStatus}"
        in capsys.readouterr().out
    )


@pytest.mark.parametrize(
    ("username", "login", "expectedMode", "expectedLabel"),
    [
        (False, False, "password", "Password typed."),
        (True, False, "username", "Username typed."),
        (False, True, "login", "Username and password typed."),
    ],
)
def test_type_unlocks_and_types_selected_fields(
    monkeypatch,
    capsys,
    username: bool,
    login: bool,
    expectedMode: str,
    expectedLabel: str,
) -> None:
    entry = {
        "id": "0123456789abcdef0123456789abcdef",
        "title": "GitHub",
        "username": "test@example.com",
        "password": "supersecret",
        "url": "https://github.com",
        "notes": "",
    }
    args = argparse.Namespace(
        vault="vault.enc",
        keyfile="/media/kamil/USB/vault.key",
        selector="GitHub",
        username=username,
        login=login,
        delay=4,
    )
    typed = []

    monkeypatch.setattr(cli, "require_keyfile", lambda args: args.keyfile)
    monkeypatch.setattr(cli, "ask_master_password", lambda: "master-password")
    monkeypatch.setattr(cli, "handle_locked_attempt", lambda *args: False)
    monkeypatch.setattr(cli, "getEntry", lambda *args: entry)
    monkeypatch.setattr(cli, "resetAttempts", lambda: None)
    monkeypatch.setattr(
        cli,
        "typeCredential",
        lambda user, password, mode, delay: (
            typed.append((user, password, mode, delay))
            or AutoTypeResult("test")
        ),
    )

    assert cli.handle_type(args) == cli.EXIT_OK
    assert typed == [
        ("test@example.com", "supersecret", expectedMode, 4),
    ]
    output = capsys.readouterr().out
    assert expectedLabel in output
    assert "Enter key: not pressed" in output
    assert "supersecret" not in output


@pytest.mark.parametrize(
    ("error", "expectedMessage"),
    [
        (
            AutoTypeCancelledError("cancelled"),
            "Auto-type was cancelled. Nothing was typed.",
        ),
        (
            AutoTypeError("permission denied"),
            "Auto-type could not be completed: permission denied",
        ),
    ],
)
def test_type_reports_backend_errors(
    monkeypatch,
    capsys,
    error: AutoTypeError,
    expectedMessage: str,
) -> None:
    entry = {
        "id": "0123456789abcdef0123456789abcdef",
        "title": "GitHub",
        "username": "test@example.com",
        "password": "supersecret",
        "url": "",
        "notes": "",
    }
    args = argparse.Namespace(
        vault="vault.enc",
        keyfile="/media/kamil/USB/vault.key",
        selector="GitHub",
        username=False,
        login=False,
        delay=3,
    )

    monkeypatch.setattr(cli, "require_keyfile", lambda args: args.keyfile)
    monkeypatch.setattr(cli, "ask_master_password", lambda: "master-password")
    monkeypatch.setattr(cli, "handle_locked_attempt", lambda *args: False)
    monkeypatch.setattr(cli, "getEntry", lambda *args: entry)
    monkeypatch.setattr(cli, "resetAttempts", lambda: None)
    monkeypatch.setattr(
        cli,
        "typeCredential",
        lambda *args: (_ for _ in ()).throw(error),
    )

    assert cli.handle_type(args) == cli.EXIT_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert expectedMessage in captured.err
    assert "supersecret" not in captured.err


def test_get_parser_defaults_to_hidden_password() -> None:
    parser = cli.build_parser()

    hidden_args = parser.parse_args(["get", "GitHub"])
    visible_args = parser.parse_args(["get", "GitHub", "--show-password"])

    assert hidden_args.show_password is False
    assert visible_args.show_password is True


def test_type_parser_defaults_to_password_and_three_second_delay() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["type", "GitHub"])

    assert args.func is cli.handle_type
    assert args.username is False
    assert args.login is False
    assert args.delay == 3


def test_type_parser_accepts_login_and_delay() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["type", "GitHub", "--login", "--delay", "5"])

    assert args.login is True
    assert args.delay == 5


def test_type_parser_rejects_conflicting_modes() -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exitInfo:
        parser.parse_args(["type", "GitHub", "--username", "--login"])

    assert exitInfo.value.code == cli.EXIT_USAGE


def test_relink_keyfile_parser_accepts_new_path() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["relink-keyfile", "/media/kamil/USB/vault.key"])

    assert args.path == "/media/kamil/USB/vault.key"
    assert args.func is cli.handle_relink_keyfile


def test_global_help_explains_security_model_and_quick_start(capsys) -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exitInfo:
        parser.parse_args(["--help"])

    assert exitInfo.value.code == 0
    output = capsys.readouterr().out
    assert output.startswith("usage: pm ")
    assert "master password" in output
    assert "removable device" in output
    assert "Quick start:" in output
    assert "pm COMMAND --help" in output


def test_command_help_explains_password_visibility(capsys) -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exitInfo:
        parser.parse_args(["get", "--help"])

    assert exitInfo.value.code == 0
    output = capsys.readouterr().out
    assert "The password is hidden by default." in output
    assert "--show-password" in output
    assert "pm get GitHub" in output


def test_version_uses_package_version(capsys) -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exitInfo:
        parser.parse_args(["--version"])

    assert exitInfo.value.code == 0
    assert capsys.readouterr().out == f"pm {cli.__version__}\n"


def test_usage_error_has_actionable_hint(capsys) -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exitInfo:
        parser.parse_args(["get"])

    assert exitInfo.value.code == cli.EXIT_USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("usage: pm get ")
    assert "[ERROR] the following arguments are required: SELECTOR" in captured.err
    assert "[HINT] Run 'pm --help'" in captured.err


def test_main_reports_invalid_config_without_traceback(
    monkeypatch,
    capsys,
) -> None:
    def failConfigLoad():
        raise cli.ConfigError("Config has unknown fields: extra.")

    monkeypatch.setattr(cli, "loadConfig", failConfigLoad)
    monkeypatch.setattr(sys, "argv", ["pm", "list"])

    assert cli.main() == cli.EXIT_USAGE
    assert capsys.readouterr().err == (
        "[ERROR] Configuration could not be read: "
        "Config has unknown fields: extra.\n"
        "[HINT] Repair or remove the configuration file, "
        "then run the command again.\n"
    )


def test_main_handles_keyboard_interrupt_without_traceback(
    monkeypatch,
    capsys,
) -> None:
    def cancelGenerate(length: int) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "generate_password", cancelGenerate)
    monkeypatch.setattr(sys, "argv", ["pm", "generate"])

    assert cli.main() == cli.EXIT_ERROR
    assert capsys.readouterr().err == "[ERROR] Command cancelled.\n"


def test_legacy_main_delegates_to_cli() -> None:
    from manager import main

    assert main.main is cli.main
