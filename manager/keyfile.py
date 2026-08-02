import os
from pathlib import Path

from manager.secure_file import (
    createPrivateFile,
    ensurePrivatePermissions,
    secureReadBytes,
)


KEYFILE_SIZE = 64


def createKeyfile(keyfilePath: str) -> None:
    path = Path(keyfilePath)
    createPrivateFile(
        path,
        os.urandom(KEYFILE_SIZE),
        permissionsRequired=False,
    )


def readKeyfile(keyfilePath: str) -> bytes:
    path = Path(keyfilePath)

    ensurePrivatePermissions(path, required=False)
    keyfileData = secureReadBytes(path, KEYFILE_SIZE)

    if len(keyfileData) != KEYFILE_SIZE:
        raise ValueError(f"Keyfile must be exactly {KEYFILE_SIZE} bytes.")

    return keyfileData
