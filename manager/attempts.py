import base64
import binascii
import hashlib
import json
import os
import re
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from manager.config import getConfigPath, normalizePath
from manager.crypto import MAX_ENCRYPTED_VAULT_BYTES, get_panic_block
from manager.file_lock import vaultFileLock
from manager.keyfile import readKeyfile
from manager.secure_file import (
    atomicWritePrivateFile,
    deletePrivateFile,
    ensurePrivateDirectory,
    ensurePrivatePermissions,
    isLinkOrReparsePoint,
    rejectLink,
    secureReadBytes,
    secureReadText,
)


ATTEMPTS_FILE = "attempts.enc"
LEGACY_ATTEMPTS_FILE = "attempts.json"
ATTEMPT_STATE_VERSION = 1
ATTEMPT_ENVELOPE_VERSION = 1
ATTEMPT_CIPHER = "aes-256-gcm"
ATTEMPT_KEY_DOMAIN = b"password-manager-attempt-state-key-v1"
ATTEMPT_NONCE_BYTES = 12
MAX_ATTEMPTS_FILE_BYTES = 16 * 1024
MAX_ATTEMPT_PLAINTEXT_BYTES = 4 * 1024
MAX_FAILED_ATTEMPTS = 1_000_000
VAULT_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ATTEMPT_STATE_FIELDS = {
    "version",
    "vault_id",
    "failed_attempts",
    "locked_until",
}
ATTEMPT_ENVELOPE_FIELDS = {
    "version",
    "cipher",
    "vault_id",
    "nonce",
    "ciphertext",
}
LOCK_THRESHOLDS = [
    (15, timedelta(hours=1)),
    (10, timedelta(minutes=10)),
    (8, timedelta(minutes=2)),
    (5, timedelta(seconds=30)),
]


class AttemptStateError(ValueError):
    pass


def getAttemptsPath() -> Path:
    return getConfigPath().with_name(ATTEMPTS_FILE)


def getLegacyAttemptsPath() -> Path:
    return getConfigPath().with_name(LEGACY_ATTEMPTS_FILE)


@contextmanager
def attemptsFileLock() -> Iterator[None]:
    attemptsPath = getAttemptsPath()
    ensurePrivateDirectory(attemptsPath.parent)

    with vaultFileLock(str(attemptsPath)):
        yield


def canonicalJson(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def getVaultIdentifier(vaultPath: str) -> str:
    path = Path(vaultPath)
    rejectLink(path)
    ensurePrivatePermissions(path)
    encryptedData = secureReadBytes(path, MAX_ENCRYPTED_VAULT_BYTES)

    try:
        panicBlock = get_panic_block(encryptedData)
    except ValueError as error:
        raise AttemptStateError(
            "Could not determine the vault identity."
        ) from error

    if panicBlock is None:
        raise AttemptStateError("Vault panic metadata is required.")

    return hashlib.sha256(canonicalJson(panicBlock)).hexdigest()


def getLegacyVaultIdentifier(vaultPath: str) -> str:
    normalizedPath = os.path.normcase(normalizePath(vaultPath))
    return hashlib.sha256(normalizedPath.encode("utf-8")).hexdigest()


def createDefaultAttemptState(vaultId: str) -> dict[str, Any]:
    return {
        "version": ATTEMPT_STATE_VERSION,
        "vault_id": vaultId,
        "failed_attempts": 0,
        "locked_until": None,
    }


def rejectDuplicateJsonKeys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}

    for key, value in pairs:
        if key in result:
            raise AttemptStateError(f"Duplicate attempts field: {key}.")

        result[key] = value

    return result


def loadJson(data: bytes | str, context: str) -> Any:
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        return json.loads(text, object_pairs_hook=rejectDuplicateJsonKeys)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise AttemptStateError(f"{context} is not valid UTF-8 JSON.") from error


def parseLockedUntil(value: Any) -> datetime | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise AttemptStateError("Attempts locked_until must be text or null.")

    try:
        lockedUntil = datetime.fromisoformat(value)
    except ValueError as error:
        raise AttemptStateError("Attempts locked_until is invalid.") from error

    if lockedUntil.tzinfo is None or lockedUntil.utcoffset() is None:
        raise AttemptStateError("Attempts locked_until must include a timezone.")

    return lockedUntil


def validateAttemptState(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise AttemptStateError("Attempts state must be a JSON object.")

    actualFields = set(state)
    missingFields = ATTEMPT_STATE_FIELDS - actualFields
    unknownFields = actualFields - ATTEMPT_STATE_FIELDS

    if missingFields:
        fields = ", ".join(sorted(missingFields))
        raise AttemptStateError(f"Attempts state is missing fields: {fields}.")

    if unknownFields:
        fields = ", ".join(sorted(unknownFields))
        raise AttemptStateError(f"Attempts state has unknown fields: {fields}.")

    if (
        type(state["version"]) is not int
        or state["version"] != ATTEMPT_STATE_VERSION
    ):
        raise AttemptStateError("Unsupported attempts state version.")

    vaultId = state["vault_id"]
    if not isinstance(vaultId, str) or VAULT_ID_PATTERN.fullmatch(vaultId) is None:
        raise AttemptStateError("Attempts vault_id is invalid.")

    failedAttempts = state["failed_attempts"]
    if (
        type(failedAttempts) is not int
        or failedAttempts < 0
        or failedAttempts > MAX_FAILED_ATTEMPTS
    ):
        raise AttemptStateError("Attempts failed_attempts is invalid.")

    parseLockedUntil(state["locked_until"])
    return state


def validateEnvelope(envelope: Any) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise AttemptStateError("Encrypted attempts state must be a JSON object.")

    if set(envelope) != ATTEMPT_ENVELOPE_FIELDS:
        raise AttemptStateError("Encrypted attempts state has invalid fields.")

    if (
        type(envelope["version"]) is not int
        or envelope["version"] != ATTEMPT_ENVELOPE_VERSION
    ):
        raise AttemptStateError("Unsupported encrypted attempts version.")

    if envelope["cipher"] != ATTEMPT_CIPHER:
        raise AttemptStateError("Unsupported attempts cipher.")

    vaultId = envelope["vault_id"]
    if not isinstance(vaultId, str) or VAULT_ID_PATTERN.fullmatch(vaultId) is None:
        raise AttemptStateError("Encrypted attempts vault_id is invalid.")

    for field in ("nonce", "ciphertext"):
        if not isinstance(envelope[field], str):
            raise AttemptStateError(f"Attempts {field} must be Base64 text.")

    return envelope


def decodeBase64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as error:
        raise AttemptStateError(
            f"Attempts {field} is not valid Base64."
        ) from error


def deriveAttemptKey(keyfilePath: str, vaultId: str) -> bytes:
    try:
        keyfileData = readKeyfile(keyfilePath)
    except ValueError as error:
        raise AttemptStateError(
            "The keyfile could not be used for the attempts state."
        ) from error

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(vaultId),
        info=ATTEMPT_KEY_DOMAIN,
    ).derive(keyfileData)


def getAuthenticatedMetadata(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        field: envelope[field]
        for field in ATTEMPT_ENVELOPE_FIELDS
        if field != "ciphertext"
    }


def encryptAttemptState(state: dict[str, Any], keyfilePath: str) -> bytes:
    validatedState = validateAttemptState(state)
    vaultId = validatedState["vault_id"]
    nonce = os.urandom(ATTEMPT_NONCE_BYTES)
    envelope: dict[str, Any] = {
        "version": ATTEMPT_ENVELOPE_VERSION,
        "cipher": ATTEMPT_CIPHER,
        "vault_id": vaultId,
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    plaintext = canonicalJson(validatedState)

    if len(plaintext) > MAX_ATTEMPT_PLAINTEXT_BYTES:
        raise AttemptStateError("Attempts state is too large.")

    ciphertext = AESGCM(deriveAttemptKey(keyfilePath, vaultId)).encrypt(
        nonce,
        plaintext,
        canonicalJson(envelope),
    )
    envelope["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
    return json.dumps(envelope, indent=2).encode("utf-8")


def decryptAttemptState(
    encryptedData: bytes,
    keyfilePath: str,
    expectedVaultId: str,
) -> dict[str, Any]:
    envelope = validateEnvelope(
        loadJson(encryptedData, "Encrypted attempts state")
    )
    nonce = decodeBase64(envelope["nonce"], "nonce")
    ciphertext = decodeBase64(envelope["ciphertext"], "ciphertext")

    if len(nonce) != ATTEMPT_NONCE_BYTES:
        raise AttemptStateError("Attempts nonce has an invalid length.")

    if len(ciphertext) < 16 or len(ciphertext) > MAX_ATTEMPT_PLAINTEXT_BYTES + 16:
        raise AttemptStateError("Attempts ciphertext has an invalid length.")

    try:
        plaintext = AESGCM(
            deriveAttemptKey(keyfilePath, expectedVaultId)
        ).decrypt(
            nonce,
            ciphertext,
            canonicalJson(getAuthenticatedMetadata(envelope)),
        )
    except (InvalidTag, ValueError) as error:
        raise AttemptStateError(
            "Encrypted attempts state could not be authenticated."
        ) from error

    state = validateAttemptState(
        loadJson(plaintext, "Decrypted attempts state")
    )

    if (
        envelope["vault_id"] != expectedVaultId
        or state["vault_id"] != expectedVaultId
    ):
        raise AttemptStateError(
            "Encrypted attempts state belongs to another vault."
        )

    return state


def migrateLegacyAttemptState(
    vaultPath: str,
    keyfilePath: str,
    vaultId: str,
) -> dict[str, Any] | None:
    legacyPath = getLegacyAttemptsPath()
    rejectLink(legacyPath)

    if not legacyPath.exists():
        return None

    ensurePrivatePermissions(legacyPath)
    legacyState = validateAttemptState(
        loadJson(
            secureReadText(legacyPath, MAX_ATTEMPTS_FILE_BYTES),
            "Legacy attempts state",
        )
    )

    if legacyState["vault_id"] != getLegacyVaultIdentifier(vaultPath):
        raise AttemptStateError("Legacy attempts state belongs to another vault.")

    migratedState = {
        **legacyState,
        "vault_id": vaultId,
    }
    saveAttemptState(migratedState, keyfilePath)
    deletePrivateFile(legacyPath)
    return migratedState


def loadAttemptState(vaultPath: str, keyfilePath: str) -> dict[str, Any]:
    path = getAttemptsPath()

    if path.parent.exists() or isLinkOrReparsePoint(path.parent):
        ensurePrivatePermissions(path.parent, isDirectory=True)

    rejectLink(path)
    vaultId = getVaultIdentifier(vaultPath)

    if not path.exists():
        migratedState = migrateLegacyAttemptState(
            vaultPath,
            keyfilePath,
            vaultId,
        )
        return migratedState or createDefaultAttemptState(vaultId)

    ensurePrivatePermissions(path)
    encryptedData = secureReadBytes(path, MAX_ATTEMPTS_FILE_BYTES)
    return decryptAttemptState(encryptedData, keyfilePath, vaultId)


def saveAttemptState(state: dict[str, Any], keyfilePath: str) -> None:
    path = getAttemptsPath()
    ensurePrivateDirectory(path.parent)
    atomicWritePrivateFile(path, encryptAttemptState(state, keyfilePath))


def resetAttempts() -> None:
    with attemptsFileLock():
        deletePrivateFile(getAttemptsPath())
        deletePrivateFile(getLegacyAttemptsPath())


def getLockRemaining(
    vaultPath: str,
    keyfilePath: str,
    now: datetime | None = None,
) -> int:
    currentTime = now or datetime.now(UTC)

    with attemptsFileLock():
        attemptsPath = getAttemptsPath()
        legacyPath = getLegacyAttemptsPath()
        if (
            not (
                attemptsPath.exists()
                or isLinkOrReparsePoint(attemptsPath)
            )
            and not (
                legacyPath.exists()
                or isLinkOrReparsePoint(legacyPath)
            )
        ):
            return 0

        state = loadAttemptState(vaultPath, keyfilePath)
        lockedUntil = parseLockedUntil(state["locked_until"])

    if lockedUntil is None or lockedUntil <= currentTime:
        return 0

    return int((lockedUntil - currentTime).total_seconds())


def formatLockRemaining(seconds: int) -> str:
    if seconds < 60:
        unit = "second" if seconds == 1 else "seconds"
        return f"{seconds} {unit}"

    minutes = seconds // 60

    if minutes < 60:
        unit = "minute" if minutes == 1 else "minutes"
        return f"{minutes} {unit}"

    hours = minutes // 60
    unit = "hour" if hours == 1 else "hours"
    return f"{hours} {unit}"


def getCooldown(failedAttempts: int) -> timedelta | None:
    for threshold, cooldown in LOCK_THRESHOLDS:
        if failedAttempts >= threshold:
            return cooldown

    return None


def recordFailedAttempt(
    vaultPath: str,
    keyfilePath: str,
    now: datetime | None = None,
) -> int:
    currentTime = now or datetime.now(UTC)

    with attemptsFileLock():
        state = loadAttemptState(vaultPath, keyfilePath)
        failedAttempts = min(
            MAX_FAILED_ATTEMPTS,
            state["failed_attempts"] + 1,
        )
        cooldown = getCooldown(failedAttempts)
        lockedUntil = None

        if cooldown is not None:
            lockedUntil = currentTime + cooldown

        saveAttemptState(
            {
                "version": ATTEMPT_STATE_VERSION,
                "vault_id": state["vault_id"],
                "failed_attempts": failedAttempts,
                "locked_until": (
                    lockedUntil.isoformat()
                    if lockedUntil is not None
                    else None
                ),
            },
            keyfilePath,
        )

        if lockedUntil is None:
            return 0

        return max(0, int((lockedUntil - currentTime).total_seconds()))
