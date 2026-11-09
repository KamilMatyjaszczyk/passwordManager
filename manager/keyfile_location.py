import os
import platform
import plistlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from manager.secure_file import UnsafeFileError, rejectLink


class KeyfileLocationError(ValueError):
    pass


@dataclass(frozen=True)
class MountInfo:
    mountPoint: Path
    deviceId: int
    majorMinor: str


def getExistingPath(path: Path) -> Path:
    currentPath = path.expanduser()

    while not currentPath.exists():
        parent = currentPath.parent

        if parent == currentPath:
            raise KeyfileLocationError("Keyfile parent path does not exist.")

        currentPath = parent

    return currentPath.resolve()


def isRelativeTo(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False

    return True


def loadMounts() -> list[MountInfo]:
    mounts = []

    with open("/proc/self/mountinfo", encoding="utf-8") as mountInfo:
        for line in mountInfo:
            parts = line.split()
            separatorIndex = parts.index("-")
            mountPoint = Path(parts[4].replace("\\040", " ")).resolve()
            majorMinor = parts[2]
            try:
                deviceId = os.stat(mountPoint).st_dev
            except (FileNotFoundError, PermissionError):
                continue

            mounts.append(MountInfo(mountPoint, deviceId, majorMinor))

    return mounts


def findMount(path: Path, mounts: Iterable[MountInfo]) -> MountInfo | None:
    matches = [
        mount
        for mount in mounts
        if path == mount.mountPoint or isRelativeTo(path, mount.mountPoint)
    ]

    if not matches:
        return None

    return max(matches, key=lambda mount: len(mount.mountPoint.parts))


def isRemovableDevice(majorMinor: str) -> bool:
    devicePath = Path("/sys/dev/block") / majorMinor

    if not devicePath.exists():
        return False

    for path in [devicePath.resolve(), *devicePath.resolve().parents]:
        removablePath = path / "removable"

        if removablePath.exists():
            return removablePath.read_text(encoding="utf-8").strip() == "1"

    return False


def isWindowsRemovable(path: Path) -> bool:
    import ctypes

    driveRoot = path.anchor

    if not driveRoot:
        return False

    driveRemovable = 2
    return ctypes.windll.kernel32.GetDriveTypeW(driveRoot) == driveRemovable


def isMacRemovable(path: Path) -> bool:
    try:
        result = subprocess.run(
            ["diskutil", "info", "-plist", str(path)],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False

    diskInfo = plistlib.loads(result.stdout)
    return bool(diskInfo.get("Removable") or diskInfo.get("RemovableMedia"))


def validatePlatformRemovable(
    existingPath: Path,
    mounts: Iterable[MountInfo] | None,
    removableChecker: Callable[[str], bool],
    systemName: str,
) -> None:
    if systemName == "Linux":
        mountInfo = findMount(existingPath, mounts or loadMounts())

        if mountInfo is None:
            raise KeyfileLocationError("Could not determine keyfile mount point.")

        if not removableChecker(mountInfo.majorMinor):
            raise KeyfileLocationError("Keyfile must be stored on a removable device.")

        return

    if systemName == "Windows":
        if not isWindowsRemovable(existingPath):
            raise KeyfileLocationError("Keyfile must be stored on a removable device.")

        return

    if systemName == "Darwin":
        if not isMacRemovable(existingPath):
            raise KeyfileLocationError("Keyfile must be stored on a removable device.")

        return

    raise KeyfileLocationError(
        f"Removable device validation is not supported on {systemName}."
    )


def validateKeyfileLocation(
    keyfilePath: str,
    mounts: Iterable[MountInfo] | None = None,
    removableChecker: Callable[[str], bool] = isRemovableDevice,
    homePath: Path | None = None,
    systemName: str | None = None,
) -> None:
    path = Path(keyfilePath).expanduser()

    try:
        rejectLink(path)
    except UnsafeFileError as error:
        raise KeyfileLocationError("Keyfile cannot be a symbolic link.") from error

    existingPath = getExistingPath(path)
    resolvedHome = (homePath or Path.home()).expanduser().resolve()
    resolvedSystemName = systemName or platform.system()
    homeDevice = os.stat(resolvedHome).st_dev
    mountInfo = findMount(existingPath, mounts) if mounts is not None else None
    keyfileDevice = mountInfo.deviceId if mountInfo is not None else os.stat(existingPath).st_dev

    if isRelativeTo(existingPath, resolvedHome):
        raise KeyfileLocationError("Keyfile cannot be stored inside your home directory.")

    if keyfileDevice == homeDevice:
        raise KeyfileLocationError("Keyfile cannot be stored on the same filesystem as your home directory.")

    validatePlatformRemovable(
        existingPath,
        mounts,
        removableChecker,
        resolvedSystemName,
    )
