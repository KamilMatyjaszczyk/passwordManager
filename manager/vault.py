from pathlib import Path
from typing import Any

from manager.crypto import encrypt, decrypt


DEFAULT_VAULT = {
    "entries": []
}

def createVault(vaultPath: str, master_password: str) -> None:
    path = Path(vaultPath)

    if path.exists():
        raise FileExistsError(f"Vault already exists: {vaultPath}")
    
    encryptedData = encrypt(DEFAULT_VAULT, master_password)
    path.write_bytes(encryptedData)

def loadVault(vaultPath: str, master_passworsd: str) -> dict[str, Any]:
    path = Path(vaultPath)

    if not path.exists(): 
        raise FileNotFoundError(f"Vault not found: {vaultPath}")
    
    encryptedData = path.read_bytes()
    return decrypt(encryptedData, master_passworsd)

def saveVault(vaultPath: str, vaultData: dict[str, Any], master_password: str) -> None: 
    encryptedData = encrypt(vaultData, master_password)
    Path(vaultPath).write_bytes(encryptedData)

def addEntry(vaultPath: str, master_password: str, title: str, username: str, password: str, url: str = "", notes: str = "",) -> None:
    vault = loadVault(vaultPath, master_password)
    
    entry = {
        "title" : title,
        "username" : username,
        "password" : password,
        "url" : url,
        "notes" : notes
    }

    vault["entries"].append(entry)
    saveVault(vaultPath, vault, master_password)

def listEntries(vaultPath: str, master_password: str) -> list[str]:
    vault = loadVault(vaultPath, master_password)
    return [entry["title"] for entry in vault["entries"]]

def getEntry(vaultPath: str, master_password: str, title: str) -> dict[str, Any] | None :
    vault = loadVault(vaultPath, master_password)
    for entry in vault["entries"]:
        if entry["title"].lower() == title.lower():
            return entry
        
    return None

def deleteEntry(vaultPath: str, master_password: str, title: str) -> bool:
    vault = loadVault(vaultPath, master_password)

    originalLength = len(vault["entries"])
    
    vault["entries"] = [
        entry for entry in vault["entries"]
        if entry["title"].lower() != title.lower()
    ]
    
    if len(vault["entries"]) == originalLength:
        return False
    
    saveVault(vaultPath, vault, master_password)
    return True
