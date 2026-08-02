import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag

from manager.crypto import (
    MAX_ENCRYPTED_VAULT_BYTES,
    create_panic_block,
    decrypt,
    encrypt,
    get_panic_block,
    is_panic_password,
)
from manager.file_lock import withVaultLock
from manager.keyfile import readKeyfile
from manager.secure_file import (
    atomicWritePrivateFile,
    deletePrivateFile,
    ensurePrivatePermissions,
    rejectLink,
    secureReadBytes,
)
from manager.vault_schema import (
    SCHEMA_VERSION,
    VaultValidationError,
    validateVaultData,
)


DEFAULT_VAULT = {
    "schema_version": SCHEMA_VERSION,
    "entries": []
}


class AmbiguousEntryError(ValueError):
    pass


def validateNewMasterPassword(master_password: str) -> None:
    if master_password == "":
        raise ValueError("Master password cannot be empty.")


def validateNewPanicPassword(panic_password: str) -> None:
    if panic_password == "":
        raise ValueError("Panic password cannot be empty.")


def requirePanicBlock(encryptedData: bytes) -> dict[str, str]:
    panicBlock = get_panic_block(encryptedData)

    if panicBlock is None:
        raise VaultValidationError("Vault panic metadata is missing.")

    return panicBlock


def createEntryId() -> str:
    return uuid.uuid4().hex


def findEntry(vaultData: dict[str, Any], selector: str) -> dict[str, Any] | None:
    entries = vaultData["entries"]
    normalizedSelector = selector.casefold()

    exactIdMatches = [
        entry for entry in entries
        if entry["id"].casefold() == normalizedSelector
    ]
    if exactIdMatches:
        return exactIdMatches[0]

    if len(selector) >= 8:
        idPrefixMatches = [
            entry for entry in entries
            if entry["id"].casefold().startswith(normalizedSelector)
        ]
        if len(idPrefixMatches) == 1:
            return idPrefixMatches[0]
        if len(idPrefixMatches) > 1:
            raise AmbiguousEntryError(
                "Entry ID prefix is ambiguous. Use more characters from the ID."
            )

    titleMatches = [
        entry for entry in entries
        if entry["title"].casefold() == normalizedSelector
    ]

    if len(titleMatches) > 1:
        raise AmbiguousEntryError(
            "Multiple entries have that title. Use the entry ID shown by list."
        )

    if titleMatches:
        return titleMatches[0]

    return None


def atomicWriteVault(
    path: Path,
    encryptedData: bytes,
    master_password: str,
    keyfileData: bytes,
    expectedVaultData: dict[str, Any],
) -> None:
    requirePanicBlock(encryptedData)
    decryptedData = decrypt(encryptedData, master_password, keyfileData)
    validateVaultData(decryptedData)

    def verifyVault(tempPath: Path) -> None:
        verifiedData = decrypt(
            secureReadBytes(tempPath, MAX_ENCRYPTED_VAULT_BYTES),
            master_password,
            keyfileData,
        )
        validateVaultData(verifiedData)

        if verifiedData != expectedVaultData:
            raise ValueError("Encrypted vault verification failed.")

    atomicWritePrivateFile(path, encryptedData, verifyVault)

@withVaultLock
def createVault(vaultPath: str, master_password: str, keyfilePath: str, panic_password: str) -> None:
    validateNewMasterPassword(master_password)
    validateNewPanicPassword(panic_password)
    path = Path(vaultPath)
    rejectLink(path)

    if path.exists():
        raise FileExistsError(f"Vault already exists: {vaultPath}")
    
    keyfileData = readKeyfile(keyfilePath)
    panicBlock = create_panic_block(panic_password, keyfileData)
    vaultData = {
        "schema_version": DEFAULT_VAULT["schema_version"],
        "entries": [],
    }
    validateVaultData(vaultData)
    encryptedData = encrypt(vaultData, master_password, keyfileData, panicBlock)
    atomicWriteVault(path, encryptedData, master_password, keyfileData, vaultData)

def loadVault(vaultPath: str, master_password: str, keyfilePath: str) -> dict[str, Any]:
    path = Path(vaultPath)
    rejectLink(path)

    if not path.exists(): 
        raise FileNotFoundError(f"Vault not found: {vaultPath}")
    
    keyfileData = readKeyfile(keyfilePath)
    ensurePrivatePermissions(path)
    encryptedData = secureReadBytes(path, MAX_ENCRYPTED_VAULT_BYTES)
    requirePanicBlock(encryptedData)
    vaultData = decrypt(encryptedData, master_password, keyfileData)
    validateVaultData(vaultData)

    return vaultData

@withVaultLock
def saveVault(
    vaultPath: str,
    vaultData: dict[str, Any],
    master_password: str,
    keyfilePath: str,
    panicBlock: dict[str, str] | None = None,
) -> None:
    path = Path(vaultPath)
    validateVaultData(vaultData)
    ensurePrivatePermissions(path)
    existingData = secureReadBytes(path, MAX_ENCRYPTED_VAULT_BYTES)
    if panicBlock is None:
        panicBlock = requirePanicBlock(existingData)

    keyfileData = readKeyfile(keyfilePath)
    encryptedData = encrypt(vaultData, master_password, keyfileData, panicBlock)
    atomicWriteVault(path, encryptedData, master_password, keyfileData, vaultData)

def isPanicPassword(vaultPath: str, passwordValue: str, keyfilePath: str) -> bool:
    path = Path(vaultPath)
    rejectLink(path)

    if not path.exists():
        return False

    keyfileData = readKeyfile(keyfilePath)
    ensurePrivatePermissions(path)
    encryptedData = secureReadBytes(path, MAX_ENCRYPTED_VAULT_BYTES)
    return is_panic_password(encryptedData, passwordValue, keyfileData)

def isMasterPassword(vaultPath: str, passwordValue: str, keyfilePath: str) -> bool:
    try:
        loadVault(vaultPath, passwordValue, keyfilePath)
    except InvalidTag:
        return False

    return True

@withVaultLock
def deleteVault(vaultPath: str) -> None:
    deletePrivateFile(Path(vaultPath))

@withVaultLock
def addEntry(vaultPath: str, master_password: str, keyfilePath: str, title: str, username: str, password: str, url: str = "", notes: str = "",) -> str:
    vault = loadVault(vaultPath, master_password, keyfilePath)
    entryId = createEntryId()

    entry = {
        "id": entryId,
        "title" : title,
        "username" : username,
        "password" : password,
        "url" : url,
        "notes" : notes
    }

    vault["entries"].append(entry)
    validateVaultData(vault)
    saveVault(vaultPath, vault, master_password, keyfilePath)
    return entryId

def listEntries(vaultPath: str, master_password: str, keyfilePath: str) -> list[str]:
    vault = loadVault(vaultPath, master_password, keyfilePath)
    return [entry["title"] for entry in vault["entries"]]

def listEntrySummaries(
    vaultPath: str,
    master_password: str,
    keyfilePath: str,
) -> list[dict[str, str]]:
    vault = loadVault(vaultPath, master_password, keyfilePath)
    return [
        {
            "id": entry["id"],
            "title": entry["title"],
            "username": entry["username"],
        }
        for entry in vault["entries"]
    ]


def getEntry(vaultPath: str, master_password: str, keyfilePath: str, selector: str) -> dict[str, Any] | None :
    vault = loadVault(vaultPath, master_password, keyfilePath)
    return findEntry(vault, selector)

@withVaultLock
def updateEntry(
    vaultPath: str,
    master_password: str,
    keyfilePath: str,
    selector: str,
    newTitle: str | None = None,
    username: str | None = None,
    password: str | None = None,
    url: str | None = None,
    notes: str | None = None,
) -> bool:
    vault = loadVault(vaultPath, master_password, keyfilePath)

    entry = findEntry(vault, selector)

    if entry is None:
        return False

    updates = {
        "title": newTitle,
        "username": username,
        "password": password,
        "url": url,
        "notes": notes,
    }

    for field, value in updates.items():
        if value is not None:
            entry[field] = value

    validateVaultData(vault)
    saveVault(vaultPath, vault, master_password, keyfilePath)
    return True

@withVaultLock
def changeMasterPassword(
    vaultPath: str,
    old_master_password: str,
    keyfilePath: str,
    new_master_password: str,
) -> None:
    validateNewMasterPassword(new_master_password)
    vault = loadVault(vaultPath, old_master_password, keyfilePath)
    saveVault(vaultPath, vault, new_master_password, keyfilePath)

@withVaultLock
def changePanicPassword(
    vaultPath: str,
    master_password: str,
    keyfilePath: str,
    new_panic_password: str,
) -> None:
    validateNewPanicPassword(new_panic_password)
    vault = loadVault(vaultPath, master_password, keyfilePath)
    keyfileData = readKeyfile(keyfilePath)
    panicBlock = create_panic_block(new_panic_password, keyfileData)
    saveVault(vaultPath, vault, master_password, keyfilePath, panicBlock)

@withVaultLock
def deleteEntry(vaultPath: str, master_password: str, keyfilePath: str, selector: str) -> bool:
    vault = loadVault(vaultPath, master_password, keyfilePath)
    entry = findEntry(vault, selector)

    if entry is None:
        return False

    vault["entries"].remove(entry)
    saveVault(vaultPath, vault, master_password, keyfilePath)
    return True
