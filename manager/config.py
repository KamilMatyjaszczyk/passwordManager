import json
import os
import sys
from pathlib import Path
from typing import Any

from manager.secure_file import (
    atomicWritePrivateFile,
    deletePrivateFile,
    ensurePrivateDirectory,
    ensurePrivatePermissions,
    isLinkOrReparsePoint,
    rejectLink,
    secureReadText,
)


CONFIG_DIR_ENV = "PASSWORD_MANAGER_CONFIG_DIR"
CONFIG_FILE = "config.json"
CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 64 * 1024
MAX_CONFIG_PATH_LENGTH = 32_768
CONFIG_FIELDS = {
    "version",
    "vault_path",
    "keyfile_path",
}
LEGACY_CONFIG_FIELDS = {
    "vault_path",
    "keyfile_path",
}


class ConfigError(ValueError):
    pass


def getConfigDirectory() -> Path:
    configDir = os.environ.get(CONFIG_DIR_ENV)

    if configDir is not None:
        return Path(configDir)

    if sys.platform.startswith("win"):
        appData = os.environ.get("APPDATA")

        if appData is not None:
            return Path(appData) / "PasswordManager"

        return Path.home() / "AppData" / "Roaming" / "PasswordManager"

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "PasswordManager"

    xdgConfigHome = os.environ.get("XDG_CONFIG_HOME")

    if xdgConfigHome is not None:
        return Path(xdgConfigHome) / "password-manager"

    return Path.home() / ".config" / "password-manager"


def getConfigPath() -> Path:
    return getConfigDirectory() / CONFIG_FILE


def normalizePath(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def rejectDuplicateJsonKeys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ConfigError(f"Duplicate config field: {key}.")

        result[key] = value

    return result


def validateConfigPath(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"Config {field} must be text.")

    if value == "":
        raise ConfigError(f"Config {field} cannot be empty.")

    if "\0" in value:
        raise ConfigError(f"Config {field} contains a null byte.")

    if len(value) > MAX_CONFIG_PATH_LENGTH:
        raise ConfigError(f"Config {field} is too long.")

    return normalizePath(value)


def validateConfig(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ConfigError("Config must be a JSON object.")

    actualFields = set(config)

    if actualFields == LEGACY_CONFIG_FIELDS:
        version = CONFIG_VERSION
    else:
        missingFields = CONFIG_FIELDS - actualFields
        unknownFields = actualFields - CONFIG_FIELDS

        if missingFields:
            fields = ", ".join(sorted(missingFields))
            raise ConfigError(f"Config is missing fields: {fields}.")

        if unknownFields:
            fields = ", ".join(sorted(unknownFields))
            raise ConfigError(f"Config has unknown fields: {fields}.")

        version = config["version"]

        if type(version) is not int or version != CONFIG_VERSION:
            raise ConfigError(f"Unsupported config version: {version}.")

    return {
        "version": version,
        "vault_path": validateConfigPath(config["vault_path"], "vault_path"),
        "keyfile_path": validateConfigPath(config["keyfile_path"], "keyfile_path"),
    }


def loadConfig() -> dict[str, Any]:
    path = getConfigPath()

    if path.parent.exists() or isLinkOrReparsePoint(path.parent):
        ensurePrivatePermissions(path.parent, isDirectory=True)

    rejectLink(path)

    if not path.exists():
        return {}

    ensurePrivatePermissions(path)
    try:
        config = json.loads(
            secureReadText(path, MAX_CONFIG_BYTES),
            object_pairs_hook=rejectDuplicateJsonKeys,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ConfigError("Config is not valid UTF-8 JSON.") from error

    return validateConfig(config)


def saveConfig(vaultPath: str, keyfilePath: str) -> None:
    path = getConfigPath()
    ensurePrivateDirectory(path.parent)

    config = validateConfig(
        {
            "version": CONFIG_VERSION,
            "vault_path": vaultPath,
            "keyfile_path": keyfilePath,
        }
    )

    atomicWritePrivateFile(
        path,
        json.dumps(config, indent=2).encode("utf-8"),
    )


def deleteConfig() -> None:
    deletePrivateFile(getConfigPath())
