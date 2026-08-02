import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_FILE = "config.json"
ATTEMPTS_FILE = "attempts.enc"
ADD_BARRIER_ENV = "PASSWORD_MANAGER_TEST_ADD_BARRIER"


def runCli(
    configDirectory: Path,
    *arguments: str,
    userInput: str = "",
    extraEnvironment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PASSWORD_MANAGER_CONFIG_DIR"] = str(configDirectory)

    if extraEnvironment is not None:
        environment.update(extraEnvironment)

    return subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.cli_test_driver",
            *arguments,
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        input=userInput,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def initializeVault(
    tmp_path: Path,
    masterPassword: str = "master",
    panicPassword: str = "panic",
) -> tuple[Path, Path, Path]:
    configDirectory = tmp_path / "config"
    usbDirectory = tmp_path / "usb"
    vaultPath = tmp_path / "vault.enc"
    keyfilePath = usbDirectory / "vault.key"
    usbDirectory.mkdir()

    result = runCli(
        configDirectory,
        "generate-keyfile",
        str(keyfilePath),
    )
    assertCommandSucceeded(result)

    result = runCli(
        configDirectory,
        "--vault",
        str(vaultPath),
        "--keyfile",
        str(keyfilePath),
        "init",
        userInput=(
            f"{masterPassword}\n"
            f"{masterPassword}\n"
            f"{panicPassword}\n"
            f"{panicPassword}\n"
        ),
    )
    assertCommandSucceeded(result)

    return configDirectory, vaultPath, keyfilePath


def assertCommandSucceeded(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, (
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def assertCommandFailedWithoutTraceback(
    result: subprocess.CompletedProcess[str],
) -> None:
    assert result.returncode != 0
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr


def test_init_interactively_requests_paths_and_creates_keyfile(
    tmp_path: Path,
) -> None:
    configDirectory = tmp_path / "config"
    usbDirectory = tmp_path / "usb"
    vaultPath = tmp_path / "vault.enc"
    keyfilePath = usbDirectory / "vault.key"
    usbDirectory.mkdir()

    result = runCli(
        configDirectory,
        "init",
        userInput=(
            f"{vaultPath}\n"
            f"{usbDirectory}\n"
            "master\n"
            "master\n"
            "panic\n"
            "panic\n"
        ),
    )

    assertCommandSucceeded(result)
    assert "Vault path" in result.stdout
    assert "USB device or keyfile path" in result.stdout
    assert "[OK] Vault created and ready." in result.stdout
    assert "Keyfile status: created" in result.stdout
    assert vaultPath.exists()
    assert keyfilePath.exists()
    assert (configDirectory / CONFIG_FILE).exists()


def test_init_rejects_empty_panic_password(tmp_path: Path) -> None:
    configDirectory = tmp_path / "config"
    usbDirectory = tmp_path / "usb"
    vaultPath = tmp_path / "vault.enc"
    keyfilePath = usbDirectory / "vault.key"
    usbDirectory.mkdir()

    keyfileResult = runCli(
        configDirectory,
        "generate-keyfile",
        str(keyfilePath),
    )
    assertCommandSucceeded(keyfileResult)

    result = runCli(
        configDirectory,
        "--vault",
        str(vaultPath),
        "--keyfile",
        str(keyfilePath),
        "init",
        userInput="master\nmaster\n\n\n",
    )

    assertCommandFailedWithoutTraceback(result)
    assert result.returncode == 2
    assert "[ERROR] Panic password cannot be empty." in result.stderr
    assert not vaultPath.exists()
    assert not (configDirectory / CONFIG_FILE).exists()
    assert keyfilePath.exists()


def test_complete_cli_workflow(tmp_path: Path) -> None:
    configDirectory, vaultPath, keyfilePath = initializeVault(tmp_path)

    result = runCli(
        configDirectory,
        "add",
        userInput=(
            "master\n"
            "GitHub\n"
            "user@example.com\n"
            "secret\n"
            "https://github.com\n"
            "first note\n"
        ),
    )
    assertCommandSucceeded(result)
    assert "[OK] Entry saved." in result.stdout
    assert "  Title: GitHub" in result.stdout
    assert "  ID:" in result.stdout

    result = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "GitHub" in result.stdout
    assert "user@example.com" in result.stdout

    result = runCli(
        configDirectory,
        "get",
        "GitHub",
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "Password: [hidden]" in result.stdout
    assert "Password: secret" not in result.stdout

    result = runCli(
        configDirectory,
        "copy",
        "GitHub",
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "[OK] Password copied to the clipboard." in result.stdout
    assert "Automatic clear: 30 seconds" in result.stdout
    assert "History protection: requested" in result.stdout

    result = runCli(
        configDirectory,
        "type",
        "GitHub",
        "--delay",
        "0",
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "[OK] Password typed." in result.stdout
    assert "Backend: test" in result.stdout
    assert "Enter key: not pressed" in result.stdout
    assert "secret" not in result.stdout

    result = runCli(
        configDirectory,
        "edit",
        "GitHub",
        userInput=(
            "master\n"
            "GitHub Updated\n"
            "updated@example.com\n"
            "new-secret\n"
            "https://example.com\n"
            "updated note\n"
        ),
    )
    assertCommandSucceeded(result)
    assert "Entry updated." in result.stdout

    result = runCli(
        configDirectory,
        "get",
        "GitHub Updated",
        "--show-password",
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "Username: updated@example.com" in result.stdout
    assert "Password: new-secret" in result.stdout

    result = runCli(
        configDirectory,
        "delete",
        "GitHub Updated",
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "Entry deleted." in result.stdout

    result = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "ENTRIES (0)" in result.stdout
    assert "pm add" in result.stdout

    result = runCli(
        configDirectory,
        "get",
        "missing",
        userInput="master\n",
    )
    assert result.returncode == 1
    assert result.stdout == "Master password: "
    assert "[ERROR] No entry matched 'missing'." in result.stderr
    assert "[HINT] Run 'pm list'" in result.stderr


def test_wrong_master_password_triggers_cooldown(tmp_path: Path) -> None:
    configDirectory, vaultPath, _ = initializeVault(tmp_path)

    for attemptNumber in range(1, 6):
        result = runCli(
            configDirectory,
            "list",
            userInput="wrong\n",
        )
        assertCommandFailedWithoutTraceback(result)

        if attemptNumber < 5:
            assert "[ERROR] Could not unlock vault." in result.stderr
        else:
            assert "Vault is temporarily locked." in result.stderr

    rawAttemptState = (
        configDirectory / ATTEMPTS_FILE
    ).read_text(encoding="utf-8")
    attemptEnvelope = json.loads(rawAttemptState)
    assert attemptEnvelope["cipher"] == "aes-256-gcm"
    assert "ciphertext" in attemptEnvelope
    assert "failed_attempts" not in rawAttemptState
    assert "locked_until" not in rawAttemptState

    result = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )
    assertCommandFailedWithoutTraceback(result)
    assert "Vault is temporarily locked." in result.stderr
    assert vaultPath.exists()


def test_panic_password_deletes_local_state_but_keeps_keyfile(
    tmp_path: Path,
) -> None:
    configDirectory, vaultPath, keyfilePath = initializeVault(tmp_path)

    result = runCli(
        configDirectory,
        "list",
        userInput="panic\n",
    )

    assertCommandFailedWithoutTraceback(result)
    assert result.stderr == "[ERROR] Could not unlock vault.\n"
    assert not vaultPath.exists()
    assert not (configDirectory / CONFIG_FILE).exists()
    assert not (configDirectory / ATTEMPTS_FILE).exists()
    assert keyfilePath.exists()


def test_panic_password_works_while_vault_is_locked(tmp_path: Path) -> None:
    configDirectory, vaultPath, keyfilePath = initializeVault(tmp_path)

    for _ in range(5):
        runCli(
            configDirectory,
            "list",
            userInput="wrong\n",
        )

    assert (configDirectory / ATTEMPTS_FILE).exists()

    result = runCli(
        configDirectory,
        "list",
        userInput="panic\n",
    )

    assertCommandFailedWithoutTraceback(result)
    assert result.stderr == "[ERROR] Could not unlock vault.\n"
    assert not vaultPath.exists()
    assert not (configDirectory / CONFIG_FILE).exists()
    assert not (configDirectory / ATTEMPTS_FILE).exists()
    assert keyfilePath.exists()


def test_master_password_can_be_changed(tmp_path: Path) -> None:
    configDirectory, vaultPath, _ = initializeVault(tmp_path)

    result = runCli(
        configDirectory,
        "change-master-password",
        userInput="master\nnew-master\nnew-master\n",
    )
    assertCommandSucceeded(result)
    assert "Master password changed." in result.stdout

    oldPasswordResult = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )
    assertCommandFailedWithoutTraceback(oldPasswordResult)
    assert "[ERROR] Could not unlock vault." in oldPasswordResult.stderr

    newPasswordResult = runCli(
        configDirectory,
        "list",
        userInput="new-master\n",
    )
    assertCommandSucceeded(newPasswordResult)
    assert "ENTRIES (0)" in newPasswordResult.stdout
    assert vaultPath.exists()


def test_panic_password_can_be_changed(tmp_path: Path) -> None:
    configDirectory, vaultPath, keyfilePath = initializeVault(tmp_path)

    result = runCli(
        configDirectory,
        "change-panic-password",
        userInput="master\nnew-panic\nnew-panic\n",
    )
    assertCommandSucceeded(result)
    assert "Panic password changed." in result.stdout

    oldPanicResult = runCli(
        configDirectory,
        "list",
        userInput="panic\n",
    )
    assertCommandFailedWithoutTraceback(oldPanicResult)
    assert vaultPath.exists()

    masterResult = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )
    assertCommandSucceeded(masterResult)

    newPanicResult = runCli(
        configDirectory,
        "list",
        userInput="new-panic\n",
    )
    assertCommandFailedWithoutTraceback(newPanicResult)
    assert not vaultPath.exists()
    assert not (configDirectory / CONFIG_FILE).exists()
    assert keyfilePath.exists()


def test_empty_panic_password_is_rejected_without_changing_vault(
    tmp_path: Path,
) -> None:
    configDirectory, vaultPath, keyfilePath = initializeVault(tmp_path)

    result = runCli(
        configDirectory,
        "change-panic-password",
        userInput="master\n\n\n",
    )

    assertCommandFailedWithoutTraceback(result)
    assert result.returncode == 2
    assert "[ERROR] Panic password cannot be empty." in result.stderr
    assert vaultPath.exists()

    oldPanicResult = runCli(
        configDirectory,
        "list",
        userInput="panic\n",
    )
    assertCommandFailedWithoutTraceback(oldPanicResult)
    assert not vaultPath.exists()
    assert not (configDirectory / CONFIG_FILE).exists()
    assert keyfilePath.exists()


def test_keyfile_can_be_relinked_to_a_new_usb_path(tmp_path: Path) -> None:
    configDirectory, vaultPath, keyfilePath = initializeVault(tmp_path)
    newUsbDirectory = tmp_path / "new-usb"
    newKeyfilePath = newUsbDirectory / "vault.key"
    newUsbDirectory.mkdir()
    shutil.copy2(keyfilePath, newKeyfilePath)

    result = runCli(
        configDirectory,
        "relink-keyfile",
        str(newKeyfilePath),
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "[OK] Keyfile location updated." in result.stdout
    assert f"  Keyfile: {newKeyfilePath}" in result.stdout

    savedConfig = json.loads(
        (configDirectory / CONFIG_FILE).read_text(encoding="utf-8")
    )
    assert savedConfig["keyfile_path"] == str(newKeyfilePath)

    keyfilePath.unlink()
    result = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "ENTRIES (0)" in result.stdout
    assert vaultPath.exists()


def test_missing_usb_keyfile_is_reported_without_damaging_vault(
    tmp_path: Path,
) -> None:
    configDirectory, vaultPath, keyfilePath = initializeVault(tmp_path)
    originalVault = vaultPath.read_bytes()
    keyfilePath.unlink()

    result = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )

    assertCommandFailedWithoutTraceback(result)
    assert "[ERROR] Vault or keyfile was not found." in result.stderr
    assert "pm relink-keyfile PATH" in result.stderr
    assert vaultPath.read_bytes() == originalVault


def test_corrupt_config_is_rejected_without_traceback(tmp_path: Path) -> None:
    configDirectory, vaultPath, _ = initializeVault(tmp_path)
    (configDirectory / CONFIG_FILE).write_text("{broken", encoding="utf-8")

    result = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )

    assert result.returncode == 2
    assert (
        "[ERROR] Configuration could not be read: "
        "Config is not valid UTF-8 JSON."
    ) in result.stderr
    assert "[HINT]" in result.stderr
    assertCommandFailedWithoutTraceback(result)
    assert vaultPath.exists()


def test_corrupt_attempt_state_blocks_unlock(tmp_path: Path) -> None:
    configDirectory, vaultPath, _ = initializeVault(tmp_path)
    attemptsPath = configDirectory / ATTEMPTS_FILE
    attemptsPath.write_text(
        '{"failed_attempts": "many", "unexpected": true}',
        encoding="utf-8",
    )

    result = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )

    assertCommandFailedWithoutTraceback(result)
    assert (
        "[ERROR] Failed-attempt state could not be verified."
        in result.stderr
    )
    assert attemptsPath.exists()
    assert vaultPath.exists()


def test_panic_password_works_with_corrupt_attempt_state(
    tmp_path: Path,
) -> None:
    configDirectory, vaultPath, keyfilePath = initializeVault(tmp_path)
    attemptsPath = configDirectory / ATTEMPTS_FILE

    runCli(
        configDirectory,
        "list",
        userInput="wrong\n",
    )

    attemptsPath.write_text('{"ciphertext":"tampered"}', encoding="utf-8")
    result = runCli(
        configDirectory,
        "list",
        userInput="panic\n",
    )

    assertCommandFailedWithoutTraceback(result)
    assert result.stderr == "[ERROR] Could not unlock vault.\n"
    assert not vaultPath.exists()
    assert not (configDirectory / CONFIG_FILE).exists()
    assert not attemptsPath.exists()
    assert keyfilePath.exists()


def test_corrupt_vault_is_rejected_without_traceback(tmp_path: Path) -> None:
    configDirectory, vaultPath, _ = initializeVault(tmp_path)
    vaultPath.write_bytes(b"not-json")

    result = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )

    assertCommandFailedWithoutTraceback(result)
    assert (
        "[ERROR] Command could not be completed: "
        "Encrypted vault is not valid UTF-8 JSON."
    ) in (
        result.stderr
    )
    assert vaultPath.read_bytes() == b"not-json"


def test_two_cli_processes_can_add_without_losing_data(tmp_path: Path) -> None:
    configDirectory, vaultPath, _ = initializeVault(tmp_path)
    barrierPath = tmp_path / "add-barrier"
    environment = {ADD_BARRIER_ENV: str(barrierPath)}
    inputs = [
        "master\nAlpha\nalpha-user\nalpha-secret\nhttps://alpha.test\nfirst\n",
        "master\nBeta\nbeta-user\nbeta-secret\nhttps://beta.test\nsecond\n",
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                runCli,
                configDirectory,
                "add",
                userInput=userInput,
                extraEnvironment=environment,
            )
            for userInput in inputs
        ]
        results = [future.result() for future in futures]

    for result in results:
        assertCommandSucceeded(result)
        assert "[OK] Entry saved." in result.stdout
        assert "  ID:" in result.stdout

    result = runCli(
        configDirectory,
        "list",
        userInput="master\n",
    )
    assertCommandSucceeded(result)
    assert "Alpha" in result.stdout
    assert "Beta" in result.stdout
    assert vaultPath.exists()
