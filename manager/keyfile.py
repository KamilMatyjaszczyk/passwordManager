import os
from pathlib import Path


KEYFILE_SIZE = 64


def createKeyfile(keyfilePath: str) -> None:
    path = Path(keyfilePath)

    if path.exists():
        raise FileExistsError(f"Keyfile already exists: {keyfilePath}")

    path.write_bytes(os.urandom(KEYFILE_SIZE))


def readKeyfile(keyfilePath: str) -> bytes:
    path = Path(keyfilePath)

    if not path.exists():
        raise FileNotFoundError(f"Keyfile not found: {keyfilePath}")

    keyfileData = path.read_bytes()

    if not keyfileData:
        raise ValueError("Keyfile is empty.")

    return keyfileData
