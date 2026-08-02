import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from manager.attempts import getAttemptsPath, recordFailedAttempt
from manager.config import getConfigPath, loadConfig, saveConfig
from manager.file_lock import getVaultLockPath
from manager.keyfile import createKeyfile, readKeyfile
from manager.secure_file import (
    UnsafeFileError,
    applyWindowsAcl,
    atomicWritePrivateFile,
    deletePrivateFile,
    secureReadBytes,
)
from manager.vault import createVault


MASTER_PASSWORD = "test-master-password"
PANIC_PASSWORD = "test-panic-password"


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes are not Windows ACLs")
def test_sensitive_files_have_private_posix_permissions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_directory = tmp_path / "config"
    keyfile_path = tmp_path / "vault.key"
    vault_path = tmp_path / "vault.enc"
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(config_directory))

    createKeyfile(str(keyfile_path))
    createVault(
        str(vault_path),
        MASTER_PASSWORD,
        str(keyfile_path),
        PANIC_PASSWORD,
    )
    saveConfig(str(vault_path), str(keyfile_path))
    recordFailedAttempt(
        str(vault_path),
        str(keyfile_path),
        datetime(2026, 7, 29, 12, 0, tzinfo=UTC),
    )

    sensitive_paths = [
        keyfile_path,
        vault_path,
        getVaultLockPath(str(vault_path)),
        getConfigPath(),
        getAttemptsPath(),
    ]

    for path in sensitive_paths:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    assert stat.S_IMODE(config_directory.stat().st_mode) == 0o700


def test_secure_read_rejects_symbolic_link(tmp_path: Path) -> None:
    target_path = tmp_path / "target"
    link_path = tmp_path / "linked"
    target_path.write_bytes(b"secret")
    link_path.symlink_to(target_path)

    with pytest.raises(UnsafeFileError, match="symbolic link"):
        secureReadBytes(link_path)


def test_secure_read_rejects_oversized_file(tmp_path: Path) -> None:
    test_path = tmp_path / "oversized"
    test_path.write_bytes(b"12345")

    with pytest.raises(UnsafeFileError, match="byte limit"):
        secureReadBytes(test_path, maximumBytes=4)


def test_atomic_write_does_not_replace_symbolic_link_target(tmp_path: Path) -> None:
    target_path = tmp_path / "target"
    link_path = tmp_path / "linked"
    target_path.write_bytes(b"original")
    link_path.symlink_to(target_path)

    with pytest.raises(UnsafeFileError, match="symbolic link"):
        atomicWritePrivateFile(link_path, b"replacement")

    assert target_path.read_bytes() == b"original"
    assert link_path.is_symlink()


def test_private_file_deletion_is_verified_and_syncs_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "secret"
    synced = []
    path.write_bytes(b"secret")
    monkeypatch.setattr(
        "manager.secure_file.fsyncDirectory",
        lambda directory: synced.append(directory),
    )

    deletePrivateFile(path)

    assert not path.exists()
    assert synced == [tmp_path]


def test_keyfile_read_rejects_symbolic_link(tmp_path: Path) -> None:
    target_path = tmp_path / "target.key"
    link_path = tmp_path / "linked.key"
    createKeyfile(str(target_path))
    link_path.symlink_to(target_path)

    with pytest.raises(UnsafeFileError, match="symbolic link"):
        readKeyfile(str(link_path))


def test_config_read_rejects_symbolic_link(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_directory = tmp_path / "config"
    target_path = tmp_path / "target-config.json"
    config_directory.mkdir()
    target_path.write_text("{}", encoding="utf-8")
    get_config_path = config_directory / "config.json"
    get_config_path.symlink_to(target_path)
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(config_directory))

    with pytest.raises(UnsafeFileError, match="symbolic link"):
        loadConfig()

    assert target_path.read_text(encoding="utf-8") == "{}"


def test_config_directory_rejects_symbolic_link(
    tmp_path: Path,
    monkeypatch,
) -> None:
    real_directory = tmp_path / "real-config"
    linked_directory = tmp_path / "linked-config"
    real_directory.mkdir()
    linked_directory.symlink_to(real_directory, target_is_directory=True)
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(linked_directory))

    with pytest.raises(UnsafeFileError, match="symbolic link"):
        loadConfig()


def test_windows_acl_grants_only_user_and_system(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = []
    test_path = tmp_path / "vault.enc"

    monkeypatch.setattr(
        "manager.secure_file.getWindowsUserSid",
        lambda: "S-1-5-21-1234",
    )
    monkeypatch.setattr(
        "manager.secure_file.subprocess.run",
        lambda command, **kwargs: calls.append((command, kwargs)),
    )

    applyWindowsAcl(test_path)

    assert calls == [
        (
            [
                "icacls.exe",
                str(test_path),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-21-1234:(F)",
                "*S-1-5-18:(F)",
            ],
            {
                "check": True,
                "capture_output": True,
                "text": True,
            },
        )
    ]
