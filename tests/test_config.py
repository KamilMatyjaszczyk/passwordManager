from pathlib import Path

import pytest

from manager.config import (
    CONFIG_VERSION,
    ConfigError,
    deleteConfig,
    getConfigDirectory,
    getConfigPath,
    loadConfig,
    saveConfig,
)


def test_load_config_returns_empty_dict_when_config_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path))

    assert loadConfig() == {}


def test_save_and_load_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path))
    working_directory = tmp_path / "working"
    working_directory.mkdir()
    monkeypatch.chdir(working_directory)

    saveConfig("vault.enc", "../usb/vault.key")

    assert getConfigPath() == tmp_path / "config.json"
    assert loadConfig() == {
        "version": CONFIG_VERSION,
        "vault_path": str(working_directory / "vault.enc"),
        "keyfile_path": str(tmp_path / "usb" / "vault.key"),
    }


def test_load_config_accepts_strict_legacy_format(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    getConfigPath().write_text(
        '{"vault_path":"vault.enc","keyfile_path":"vault.key"}',
        encoding="utf-8",
    )

    assert loadConfig() == {
        "version": CONFIG_VERSION,
        "vault_path": str(tmp_path / "vault.enc"),
        "keyfile_path": str(tmp_path / "vault.key"),
    }


@pytest.mark.parametrize(
    "contents",
    [
        "[]",
        '{"version":1,"vault_path":7,"keyfile_path":"key"}',
        '{"version":1,"vault_path":"","keyfile_path":"key"}',
        '{"version":2,"vault_path":"vault","keyfile_path":"key"}',
        '{"version":1,"vault_path":"vault","keyfile_path":"key","extra":true}',
        '{"version":1,"vault_path":"first","vault_path":"second","keyfile_path":"key"}',
        "{not-json}",
    ],
)
def test_load_config_rejects_invalid_schema(
    tmp_path: Path,
    monkeypatch,
    contents: str,
) -> None:
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path))
    getConfigPath().write_text(contents, encoding="utf-8")

    with pytest.raises(ConfigError):
        loadConfig()


def test_delete_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path))

    saveConfig("vault.enc", "/media/kamil/USB/vault.key")
    deleteConfig()

    assert loadConfig() == {}


def test_linux_config_directory_uses_xdg_config_home(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("PASSWORD_MANAGER_CONFIG_DIR", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr("manager.config.sys.platform", "linux")

    assert getConfigDirectory() == tmp_path / "password-manager"


def test_macos_config_directory_uses_application_support(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("PASSWORD_MANAGER_CONFIG_DIR", raising=False)
    monkeypatch.setattr("manager.config.sys.platform", "darwin")
    monkeypatch.setattr("manager.config.Path.home", lambda: tmp_path)

    assert (
        getConfigDirectory()
        == tmp_path / "Library" / "Application Support" / "PasswordManager"
    )


def test_windows_config_directory_uses_appdata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("PASSWORD_MANAGER_CONFIG_DIR", raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setattr("manager.config.sys.platform", "win32")

    assert getConfigDirectory() == tmp_path / "PasswordManager"
