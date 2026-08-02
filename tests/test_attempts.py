import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from manager import attempts
from manager.attempts import (
    ATTEMPT_STATE_VERSION,
    AttemptStateError,
    formatLockRemaining,
    getAttemptsPath,
    getLockRemaining,
    getVaultIdentifier,
    loadAttemptState,
    recordFailedAttempt,
    resetAttempts,
)
from manager.keyfile import createKeyfile
from manager.vault import createVault


MASTER_PASSWORD = "master"
PANIC_PASSWORD = "panic"


def createVaultFiles(
    tmp_path: Path,
    name: str = "vault",
) -> tuple[Path, Path]:
    vaultPath = tmp_path / f"{name}.enc"
    keyfilePath = tmp_path / f"{name}.key"
    createKeyfile(str(keyfilePath))
    createVault(
        str(vaultPath),
        MASTER_PASSWORD,
        str(keyfilePath),
        f"{PANIC_PASSWORD}-{name}",
    )
    return vaultPath, keyfilePath


def test_load_attempt_state_defaults_to_no_failures(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    configDirectory = tmp_path / "config"
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(configDirectory))
    vaultId = getVaultIdentifier(str(vaultPath))

    assert getAttemptsPath() == configDirectory / "attempts.enc"
    assert loadAttemptState(str(vaultPath), str(keyfilePath)) == {
        "version": ATTEMPT_STATE_VERSION,
        "vault_id": vaultId,
        "failed_attempts": 0,
        "locked_until": None,
    }


def test_locking_creates_missing_config_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    configDirectory = tmp_path / "missing" / "config"
    monkeypatch.setenv(
        "PASSWORD_MANAGER_CONFIG_DIR",
        str(configDirectory),
    )

    assert not configDirectory.exists()
    assert getLockRemaining(str(vaultPath), str(keyfilePath)) == 0
    assert configDirectory.is_dir()


def test_record_failed_attempt_locks_after_five_failures(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path / "config"))
    now = datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC)

    for _ in range(4):
        assert recordFailedAttempt(
            str(vaultPath),
            str(keyfilePath),
            now,
        ) == 0

    assert recordFailedAttempt(
        str(vaultPath),
        str(keyfilePath),
        now,
    ) == 30
    assert getLockRemaining(
        str(vaultPath),
        str(keyfilePath),
        now + timedelta(seconds=10),
    ) == 20


def test_attempt_state_is_encrypted_on_disk(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path / "config"))

    recordFailedAttempt(str(vaultPath), str(keyfilePath))

    rawState = getAttemptsPath().read_text(encoding="utf-8")
    envelope = json.loads(rawState)
    assert set(envelope) == {
        "version",
        "cipher",
        "vault_id",
        "nonce",
        "ciphertext",
    }
    assert envelope["cipher"] == "aes-256-gcm"
    assert "failed_attempts" not in rawState
    assert "locked_until" not in rawState
    assert loadAttemptState(
        str(vaultPath),
        str(keyfilePath),
    )["failed_attempts"] == 1


def test_reset_attempts_clears_lock(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path / "config"))
    now = datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC)

    for _ in range(5):
        recordFailedAttempt(str(vaultPath), str(keyfilePath), now)

    resetAttempts()

    assert getLockRemaining(str(vaultPath), str(keyfilePath), now) == 0
    assert loadAttemptState(
        str(vaultPath),
        str(keyfilePath),
    )["failed_attempts"] == 0


def test_attempt_state_follows_same_vault_after_rename(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    renamedVaultPath = tmp_path / "renamed.enc"
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path / "config"))

    recordFailedAttempt(str(vaultPath), str(keyfilePath))
    vaultPath.rename(renamedVaultPath)

    assert loadAttemptState(
        str(renamedVaultPath),
        str(keyfilePath),
    )["failed_attempts"] == 1


def test_attempt_state_cannot_be_used_with_another_vault(
    tmp_path: Path,
    monkeypatch,
) -> None:
    firstVault, firstKeyfile = createVaultFiles(tmp_path, "first")
    secondVault, secondKeyfile = createVaultFiles(tmp_path, "second")
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path / "config"))

    recordFailedAttempt(str(firstVault), str(firstKeyfile))

    with pytest.raises(AttemptStateError, match="authenticated"):
        loadAttemptState(str(secondVault), str(secondKeyfile))


def test_tampered_attempt_state_is_rejected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path / "config"))
    recordFailedAttempt(str(vaultPath), str(keyfilePath))
    envelope = json.loads(getAttemptsPath().read_text(encoding="utf-8"))
    ciphertext = envelope["ciphertext"]
    replacement = "A" if ciphertext[0] != "A" else "B"
    envelope["ciphertext"] = replacement + ciphertext[1:]
    getAttemptsPath().write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(AttemptStateError, match="authenticated"):
        loadAttemptState(str(vaultPath), str(keyfilePath))

    with pytest.raises(AttemptStateError, match="authenticated"):
        getLockRemaining(str(vaultPath), str(keyfilePath))

    assert getAttemptsPath().exists()


def test_wrong_keyfile_cannot_decrypt_attempt_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    wrongKeyfilePath = tmp_path / "wrong.key"
    createKeyfile(str(wrongKeyfilePath))
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path / "config"))
    recordFailedAttempt(str(vaultPath), str(keyfilePath))

    with pytest.raises(AttemptStateError, match="authenticated"):
        loadAttemptState(str(vaultPath), str(wrongKeyfilePath))


def test_broken_attempts_symlink_is_rejected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    configDirectory = tmp_path / "config"
    configDirectory.mkdir()
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(configDirectory))
    getAttemptsPath().symlink_to(tmp_path / "missing-attempts")

    with pytest.raises(ValueError, match="symbolic link"):
        getLockRemaining(str(vaultPath), str(keyfilePath))


def test_legacy_plaintext_state_is_migrated(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    configDirectory = tmp_path / "config"
    configDirectory.mkdir()
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(configDirectory))
    legacyPath = configDirectory / "attempts.json"
    legacyPath.write_text(
        json.dumps(
            {
                "version": ATTEMPT_STATE_VERSION,
                "vault_id": attempts.getLegacyVaultIdentifier(str(vaultPath)),
                "failed_attempts": 4,
                "locked_until": None,
            }
        ),
        encoding="utf-8",
    )

    state = loadAttemptState(str(vaultPath), str(keyfilePath))

    assert state["failed_attempts"] == 4
    assert state["vault_id"] == getVaultIdentifier(str(vaultPath))
    assert getAttemptsPath().exists()
    assert not legacyPath.exists()
    assert "failed_attempts" not in getAttemptsPath().read_text(encoding="utf-8")


def test_concurrent_failed_attempts_are_not_lost(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vaultPath, keyfilePath = createVaultFiles(tmp_path)
    monkeypatch.setenv("PASSWORD_MANAGER_CONFIG_DIR", str(tmp_path / "config"))
    originalLoad = attempts.loadAttemptState

    def slowLoad(vault: str, keyfile: str):
        state = originalLoad(vault, keyfile)
        time.sleep(0.01)
        return state

    monkeypatch.setattr(attempts, "loadAttemptState", slowLoad)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                recordFailedAttempt,
                str(vaultPath),
                str(keyfilePath),
            )
            for _ in range(20)
        ]

        for future in futures:
            future.result()

    assert originalLoad(
        str(vaultPath),
        str(keyfilePath),
    )["failed_attempts"] == 20


def test_format_lock_remaining() -> None:
    assert formatLockRemaining(1) == "1 second"
    assert formatLockRemaining(30) == "30 seconds"
    assert formatLockRemaining(60) == "1 minute"
    assert formatLockRemaining(120) == "2 minutes"
    assert formatLockRemaining(3600) == "1 hour"
    assert formatLockRemaining(7200) == "2 hours"
