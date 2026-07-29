from pathlib import Path
from typing import Any

from manager.crypto import encrypt, decrypt
from manager.keyfile import readKeyfile


DEFAULT_VAULT = {
    "entries": []
}

def createVault(vaultPath: str, master_password: str, keyfilePath: str) -> None:
    path = Path(vaultPath)

    if path.exists():
        raise FileExistsError(f"Vault already exists: {vaultPath}")
    
    keyfileData = readKeyfile(keyfilePath)
    encryptedData = encrypt(DEFAULT_VAULT, master_password, keyfileData)
    path.write_bytes(encryptedData)

def loadVault(vaultPath: str, master_password: str, keyfilePath: str) -> dict[str, Any]:
    path = Path(vaultPath)

    if not path.exists(): 
        raise FileNotFoundError(f"Vault not found: {vaultPath}")
    
    keyfileData = readKeyfile(keyfilePath)
    encryptedData = path.read_bytes()
    return decrypt(encryptedData, master_password, keyfileData)

def saveVault(vaultPath: str, vaultData: dict[str, Any], master_password: str, keyfilePath: str) -> None: 
    keyfileData = readKeyfile(keyfilePath)
    encryptedData = encrypt(vaultData, master_password, keyfileData)
    Path(vaultPath).write_bytes(encryptedData)

def addEntry(vaultPath: str, master_password: str, keyfilePath: str, title: str, username: str, password: str, url: str = "", notes: str = "",) -> None:
    vault = loadVault(vaultPath, master_password, keyfilePath)
    
    entry = {
        "title" : title,
        "username" : username,
        "password" : password,
        "url" : url,
        "notes" : notes
    }

    vault["entries"].append(entry)
    saveVault(vaultPath, vault, master_password, keyfilePath)

def listEntries(vaultPath: str, master_password: str, keyfilePath: str) -> list[str]:
    vault = loadVault(vaultPath, master_password, keyfilePath)
    return [entry["title"] for entry in vault["entries"]]

def getEntry(vaultPath: str, master_password: str, keyfilePath: str, title: str) -> dict[str, Any] | None :
    vault = loadVault(vaultPath, master_password, keyfilePath)
    for entry in vault["entries"]:
        if entry["title"].lower() == title.lower():
            return entry
        
    return None

def deleteEntry(vaultPath: str, master_password: str, keyfilePath: str, title: str) -> bool:
    vault = loadVault(vaultPath, master_password, keyfilePath)

    originalLength = len(vault["entries"])
    
    vault["entries"] = [
        entry for entry in vault["entries"]
        if entry["title"].lower() != title.lower()
    ]
    
    if len(vault["entries"]) == originalLength:
        return False
    
    saveVault(vaultPath, vault, master_password, keyfilePath)
    return True
