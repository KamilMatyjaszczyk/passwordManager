import os
from pathlib import Path

import pytest

from manager.keyfile_location import (
    KeyfileLocationError,
    MountInfo,
    validatePlatformRemovable,
    validateKeyfileLocation,
)


def test_validate_keyfile_location_accepts_removable_device_outside_home(
    tmp_path: Path,
) -> None:
    home_path = tmp_path / "home"
    usb_path = tmp_path / "usb"
    home_path.mkdir()
    usb_path.mkdir()

    validateKeyfileLocation(
        str(usb_path / "vault.key"),
        mounts=[MountInfo(usb_path.resolve(), os.stat(home_path).st_dev + 1, "8:1")],
        removableChecker=lambda major_minor: major_minor == "8:1",
        homePath=home_path,
        systemName="Linux",
    )


def test_validate_keyfile_location_rejects_home_directory(
    tmp_path: Path,
) -> None:
    home_path = tmp_path / "home"
    home_path.mkdir()

    with pytest.raises(KeyfileLocationError, match="home directory"):
        validateKeyfileLocation(
            str(home_path / "vault.key"),
            mounts=[MountInfo(home_path.resolve(), os.stat(home_path).st_dev, "8:1")],
            removableChecker=lambda major_minor: True,
            homePath=home_path,
            systemName="Linux",
        )


def test_validate_keyfile_location_rejects_same_filesystem_as_home(
    tmp_path: Path,
) -> None:
    home_path = tmp_path / "home"
    usb_path = tmp_path / "usb"
    home_path.mkdir()
    usb_path.mkdir()

    with pytest.raises(KeyfileLocationError, match="same filesystem"):
        validateKeyfileLocation(
            str(usb_path / "vault.key"),
            mounts=[MountInfo(usb_path.resolve(), os.stat(home_path).st_dev, "8:1")],
            removableChecker=lambda major_minor: True,
            homePath=home_path,
            systemName="Linux",
        )


def test_validate_keyfile_location_rejects_non_removable_device(
    tmp_path: Path,
) -> None:
    home_path = tmp_path / "home"
    usb_path = tmp_path / "usb"
    home_path.mkdir()
    usb_path.mkdir()

    with pytest.raises(KeyfileLocationError, match="removable"):
        validateKeyfileLocation(
            str(usb_path / "vault.key"),
            mounts=[MountInfo(usb_path.resolve(), os.stat(home_path).st_dev + 1, "8:1")],
            removableChecker=lambda major_minor: False,
            homePath=home_path,
            systemName="Linux",
        )


def test_windows_removable_validation_uses_platform_checker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("manager.keyfile_location.isWindowsRemovable", lambda path: True)

    validatePlatformRemovable(
        tmp_path,
        mounts=None,
        removableChecker=lambda major_minor: False,
        systemName="Windows",
    )


def test_macos_removable_validation_uses_platform_checker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("manager.keyfile_location.isMacRemovable", lambda path: True)

    validatePlatformRemovable(
        tmp_path,
        mounts=None,
        removableChecker=lambda major_minor: False,
        systemName="Darwin",
    )


def test_validate_keyfile_location_rejects_symbolic_link(
    tmp_path: Path,
) -> None:
    target_path = tmp_path / "target.key"
    link_path = tmp_path / "linked.key"
    target_path.write_bytes(b"key material")
    link_path.symlink_to(target_path)

    with pytest.raises(KeyfileLocationError, match="symbolic link"):
        validateKeyfileLocation(str(link_path))
