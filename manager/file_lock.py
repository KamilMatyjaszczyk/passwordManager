import errno
import os
import stat
import threading
import time
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Callable, Concatenate, Iterator, ParamSpec, TypeVar

from manager.secure_file import (
    PRIVATE_FILE_MODE,
    ensurePrivatePermissions,
    isLinkOrReparsePoint,
    rejectLink,
)


DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
LOCK_POLL_INTERVAL_SECONDS = 0.05
BUSY_ERROR_NUMBERS = {
    errno.EACCES,
    errno.EAGAIN,
    getattr(errno, "EDEADLK", errno.EAGAIN),
}
P = ParamSpec("P")
R = TypeVar("R")
_registryGuard = threading.Lock()
_localLocks: dict[str, threading.RLock] = {}
_threadState = threading.local()


class VaultBusyError(TimeoutError):
    pass


def getVaultLockPath(vaultPath: str) -> Path:
    absoluteVaultPath = Path(
        os.path.abspath(os.path.expanduser(vaultPath))
    )
    return absoluteVaultPath.with_name(f".{absoluteVaultPath.name}.lock")


def getLocalLock(lockKey: str) -> threading.RLock:
    with _registryGuard:
        lock = _localLocks.get(lockKey)

        if lock is None:
            lock = threading.RLock()
            _localLocks[lockKey] = lock

        return lock


def openLockFile(lockPath: Path) -> int:
    rejectLink(lockPath)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fileDescriptor = os.open(lockPath, flags, PRIVATE_FILE_MODE)

    try:
        fileStat = os.fstat(fileDescriptor)

        if not stat.S_ISREG(fileStat.st_mode):
            raise ValueError(f"Vault lock is not a regular file: {lockPath}")

        pathStat = os.lstat(lockPath)

        if (
            isLinkOrReparsePoint(lockPath)
            or pathStat.st_dev != fileStat.st_dev
            or pathStat.st_ino != fileStat.st_ino
        ):
            raise ValueError(f"Vault lock changed while opening: {lockPath}")

        if os.name == "nt":
            ensurePrivatePermissions(lockPath)

            if fileStat.st_size < 1:
                os.lseek(fileDescriptor, 0, os.SEEK_SET)
                os.write(fileDescriptor, b"\0")
                os.fsync(fileDescriptor)
        else:
            os.fchmod(fileDescriptor, PRIVATE_FILE_MODE)

        return fileDescriptor
    except Exception:
        os.close(fileDescriptor)
        raise


def tryAcquireOperatingSystemLock(fileDescriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fileDescriptor, 0, os.SEEK_SET)
        msvcrt.locking(fileDescriptor, msvcrt.LK_NBLCK, 1)
        return

    import fcntl

    fcntl.flock(fileDescriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def releaseOperatingSystemLock(fileDescriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fileDescriptor, 0, os.SEEK_SET)
        msvcrt.locking(fileDescriptor, msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(fileDescriptor, fcntl.LOCK_UN)


def acquireOperatingSystemLock(
    fileDescriptor: int,
    deadline: float,
    vaultPath: str,
) -> None:
    while True:
        try:
            tryAcquireOperatingSystemLock(fileDescriptor)
            return
        except OSError as error:
            if error.errno not in BUSY_ERROR_NUMBERS:
                raise

            if time.monotonic() >= deadline:
                raise VaultBusyError(
                    f"Vault is currently in use by another process: {vaultPath}"
                ) from error

            remainingSeconds = deadline - time.monotonic()
            time.sleep(min(LOCK_POLL_INTERVAL_SECONDS, remainingSeconds))


@contextmanager
def vaultFileLock(
    vaultPath: str,
    timeoutSeconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> Iterator[None]:
    if timeoutSeconds < 0:
        raise ValueError("Vault lock timeout cannot be negative.")

    lockPath = getVaultLockPath(vaultPath)
    lockKey = os.path.normcase(str(lockPath))
    localLock = getLocalLock(lockKey)
    deadline = time.monotonic() + timeoutSeconds
    localAcquired = localLock.acquire(timeout=timeoutSeconds)

    if not localAcquired:
        raise VaultBusyError(
            f"Vault is currently in use by another thread: {vaultPath}"
        )

    heldLocks = getattr(_threadState, "heldLocks", None)

    if heldLocks is None:
        heldLocks = {}
        _threadState.heldLocks = heldLocks

    if lockKey in heldLocks:
        heldLocks[lockKey] += 1

        try:
            yield
        finally:
            heldLocks[lockKey] -= 1
            localLock.release()

        return

    fileDescriptor = None
    operatingSystemLockAcquired = False

    try:
        fileDescriptor = openLockFile(lockPath)
        acquireOperatingSystemLock(fileDescriptor, deadline, vaultPath)
        operatingSystemLockAcquired = True
        heldLocks[lockKey] = 1
        yield
    finally:
        heldLocks.pop(lockKey, None)

        try:
            if fileDescriptor is not None and operatingSystemLockAcquired:
                releaseOperatingSystemLock(fileDescriptor)
        finally:
            if fileDescriptor is not None:
                os.close(fileDescriptor)

            localLock.release()


def withVaultLock(
    function: Callable[Concatenate[str, P], R],
) -> Callable[Concatenate[str, P], R]:
    @wraps(function)
    def lockedFunction(vaultPath: str, *args: P.args, **kwargs: P.kwargs) -> R:
        with vaultFileLock(vaultPath):
            return function(vaultPath, *args, **kwargs)

    return lockedFunction
