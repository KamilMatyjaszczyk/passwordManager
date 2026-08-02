import os
import time
from pathlib import Path

from manager import cli
from manager.autotype import AutoTypeResult
from manager.clipboard import ClipboardCopyResult


ADD_BARRIER_ENV = "PASSWORD_MANAGER_TEST_ADD_BARRIER"
ADD_BARRIER_TIMEOUT_SECONDS = 10


def readTestInput(prompt: str) -> str:
    return input(prompt)


def waitForConcurrentAdd() -> None:
    barrierValue = os.environ.get(ADD_BARRIER_ENV)

    if barrierValue is None:
        return

    barrierPath = Path(barrierValue)
    barrierPath.mkdir(parents=True, exist_ok=True)
    (barrierPath / f"{os.getpid()}.ready").touch(exist_ok=False)
    deadline = time.monotonic() + ADD_BARRIER_TIMEOUT_SECONDS

    while len(list(barrierPath.glob("*.ready"))) < 2:
        if time.monotonic() >= deadline:
            raise TimeoutError("Timed out waiting for the concurrent add process.")

        time.sleep(0.01)


originalAddEntry = cli.addEntry


def synchronizedAddEntry(*args, **kwargs):
    waitForConcurrentAdd()
    return originalAddEntry(*args, **kwargs)


cli.getpass = readTestInput
cli.validateKeyfileLocation = lambda path: None
cli.copyToClipboard = lambda text: ClipboardCopyResult(
    True,
    True,
    "test",
)
cli.typeCredential = lambda username, password, mode, delay: AutoTypeResult(
    "test",
)
cli.addEntry = synchronizedAddEntry


if __name__ == "__main__":
    raise SystemExit(cli.main())
