import multiprocessing
import os
import stat
from pathlib import Path

import pytest

from manager.file_lock import (
    VaultBusyError,
    getVaultLockPath,
    vaultFileLock,
)
from manager.secure_file import UnsafeFileError


def holdVaultLock(
    vaultPath: str,
    lockAcquired,
    releaseLock,
) -> None:
    with vaultFileLock(vaultPath):
        lockAcquired.set()
        releaseLock.wait(5)


def acquireLockAndExit(vaultPath: str, lockAcquired) -> None:
    with vaultFileLock(vaultPath):
        lockAcquired.set()
        os._exit(0)


def test_vault_lock_is_reentrant(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault.enc"

    with vaultFileLock(str(vault_path)):
        with vaultFileLock(str(vault_path), timeoutSeconds=0):
            pass


def test_vault_lock_blocks_another_process(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault.enc"
    processContext = multiprocessing.get_context("spawn")
    lockAcquired = processContext.Event()
    releaseLock = processContext.Event()
    process = processContext.Process(
        target=holdVaultLock,
        args=(str(vault_path), lockAcquired, releaseLock),
    )
    process.start()

    try:
        assert lockAcquired.wait(5)

        with pytest.raises(VaultBusyError, match="another process"):
            with vaultFileLock(str(vault_path), timeoutSeconds=0.1):
                pass
    finally:
        releaseLock.set()
        process.join(5)

        if process.is_alive():
            process.terminate()
            process.join(5)

    assert process.exitcode == 0

    with vaultFileLock(str(vault_path), timeoutSeconds=0.1):
        pass


def test_operating_system_releases_lock_after_process_exit(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "vault.enc"
    processContext = multiprocessing.get_context("spawn")
    lockAcquired = processContext.Event()
    process = processContext.Process(
        target=acquireLockAndExit,
        args=(str(vault_path), lockAcquired),
    )
    process.start()

    assert lockAcquired.wait(5)
    process.join(5)
    assert process.exitcode == 0

    with vaultFileLock(str(vault_path), timeoutSeconds=0.5):
        pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes are not Windows ACLs")
def test_vault_lock_file_has_private_permissions(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault.enc"

    with vaultFileLock(str(vault_path)):
        lock_path = getVaultLockPath(str(vault_path))
        assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_vault_lock_rejects_symbolic_link(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault.enc"
    lock_path = getVaultLockPath(str(vault_path))
    target_path = tmp_path / "lock-target"
    target_path.write_bytes(b"")
    lock_path.symlink_to(target_path)

    with pytest.raises(UnsafeFileError, match="symbolic link"):
        with vaultFileLock(str(vault_path)):
            pass
