import csv
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Callable


PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
READ_CHUNK_SIZE = 64 * 1024


class UnsafeFileError(ValueError):
    pass


def isLinkOrReparsePoint(path: Path) -> bool:
    try:
        fileStat = os.lstat(path)
    except FileNotFoundError:
        return False

    if stat.S_ISLNK(fileStat.st_mode):
        return True

    reparseFlag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    fileAttributes = getattr(fileStat, "st_file_attributes", 0)
    return bool(reparseFlag and fileAttributes & reparseFlag)


def rejectLink(path: Path) -> None:
    if isLinkOrReparsePoint(path):
        raise UnsafeFileError(f"Refusing to use a symbolic link: {path}")


def getWindowsUserSid() -> str:
    result = subprocess.run(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = list(csv.reader(result.stdout.splitlines()))

    if not rows or len(rows[0]) < 2:
        raise PermissionError("Could not determine the current Windows user SID.")

    sid = rows[0][1].strip()

    if not sid.startswith("S-"):
        raise PermissionError("The current Windows user SID is invalid.")

    return sid


def applyWindowsAcl(path: Path, isDirectory: bool = False) -> None:
    sid = getWindowsUserSid()
    permission = "(OI)(CI)(F)" if isDirectory else "(F)"
    subprocess.run(
        [
            "icacls.exe",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:{permission}",
            f"*S-1-5-18:{permission}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def ensurePrivatePermissions(
    path: Path,
    *,
    required: bool = True,
    isDirectory: bool = False,
) -> bool:
    rejectLink(path)

    try:
        if os.name == "nt":
            applyWindowsAcl(path, isDirectory)
        else:
            mode = PRIVATE_DIRECTORY_MODE if isDirectory else PRIVATE_FILE_MODE
            os.chmod(path, mode)
            actualMode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)

            if actualMode & 0o077:
                raise PermissionError(
                    f"Private permissions are not supported for: {path}"
                )
    except (OSError, PermissionError, subprocess.CalledProcessError):
        if required:
            raise PermissionError(f"Could not secure file permissions: {path}")

        return False

    return True


def ensurePrivateDirectory(path: Path) -> None:
    path.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
    ensurePrivatePermissions(path, isDirectory=True)


def secureReadBytes(path: Path, maximumBytes: int | None = None) -> bytes:
    rejectLink(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fileDescriptor = os.open(path, flags)

    try:
        fileStat = os.fstat(fileDescriptor)

        if not stat.S_ISREG(fileStat.st_mode):
            raise UnsafeFileError(f"Sensitive path is not a regular file: {path}")

        if maximumBytes is not None and fileStat.st_size > maximumBytes:
            raise UnsafeFileError(
                f"Sensitive file exceeds the {maximumBytes} byte limit: {path}"
            )

        pathStat = os.lstat(path)

        if (
            isLinkOrReparsePoint(path)
            or pathStat.st_dev != fileStat.st_dev
            or pathStat.st_ino != fileStat.st_ino
        ):
            raise UnsafeFileError(f"Sensitive file changed while opening: {path}")

        chunks = []

        while True:
            chunk = os.read(fileDescriptor, READ_CHUNK_SIZE)

            if not chunk:
                break

            chunks.append(chunk)

        return b"".join(chunks)
    finally:
        os.close(fileDescriptor)


def secureReadText(path: Path, maximumBytes: int | None = None) -> str:
    return secureReadBytes(path, maximumBytes).decode("utf-8")


def createPrivateFile(
    path: Path,
    data: bytes,
    *,
    permissionsRequired: bool = True,
) -> None:
    rejectLink(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fileDescriptor = os.open(path, flags, PRIVATE_FILE_MODE)

    try:
        if os.name == "nt":
            ensurePrivatePermissions(path, required=permissionsRequired)
        else:
            os.fchmod(fileDescriptor, PRIVATE_FILE_MODE)

        with os.fdopen(fileDescriptor, "wb", closefd=False) as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    except Exception:
        os.close(fileDescriptor)

        try:
            path.unlink()
        except FileNotFoundError:
            pass

        raise
    else:
        os.close(fileDescriptor)

    ensurePrivatePermissions(path, required=permissionsRequired)


def fsyncDirectory(path: Path) -> None:
    try:
        directoryDescriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return

    try:
        os.fsync(directoryDescriptor)
    finally:
        os.close(directoryDescriptor)


def deletePrivateFile(path: Path) -> None:
    if path.exists() or isLinkOrReparsePoint(path):
        path.unlink()
        fsyncDirectory(path.parent)

    if path.exists() or isLinkOrReparsePoint(path):
        raise OSError(f"Sensitive file still exists after deletion: {path}")


def atomicWritePrivateFile(
    path: Path,
    data: bytes,
    verifier: Callable[[Path], None] | None = None,
) -> None:
    rejectLink(path)
    fileDescriptor, tempName = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tempPath = Path(tempName)

    try:
        if os.name == "nt":
            ensurePrivatePermissions(tempPath)
        else:
            os.fchmod(fileDescriptor, PRIVATE_FILE_MODE)

        with os.fdopen(fileDescriptor, "wb", closefd=False) as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())

        os.close(fileDescriptor)
        ensurePrivatePermissions(tempPath)

        if verifier is not None:
            verifier(tempPath)

        rejectLink(path)
        os.replace(tempPath, path)
        ensurePrivatePermissions(path)
        fsyncDirectory(path.parent)
    except Exception:
        try:
            os.close(fileDescriptor)
        except OSError:
            pass

        try:
            tempPath.unlink()
        except FileNotFoundError:
            pass

        raise
