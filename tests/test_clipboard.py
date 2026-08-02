import subprocess

import pytest

from manager import clipboard
from manager.clipboard import (
    COPYQ_SENSITIVE_COPY_COMMAND,
    MACOS_CONCEALED_TYPE,
    MACOS_NATIVE_CONCEALED_TYPE,
    WINDOWS_SECRET_FORMATS,
    ClipboardBackend,
    clearClipboardIfUnchanged,
    copyToClipboard,
    findClipboardBackend,
    getClipboardBackends,
    writeWindowsClipboard,
)


TEST_BACKEND = ClipboardBackend(
    "test",
    ("copy",),
    ("read",),
    ("clear",),
)


class FakeWindowsClipboardApi:
    def __init__(self, failOnFormat: str | None = None) -> None:
        self.calls = []
        self.failOnFormat = failOnFormat
        self.formats = {}

    def open(self) -> None:
        self.calls.append(("open",))

    def close(self) -> None:
        self.calls.append(("close",))

    def empty(self) -> None:
        self.calls.append(("empty",))

    def setText(self, text: str) -> None:
        self.calls.append(("text", text))

    def registerFormat(self, name: str) -> int:
        identifier = len(self.formats) + 100
        self.formats[identifier] = name
        self.calls.append(("register", name))
        return identifier

    def setDword(self, identifier: int, value: int) -> None:
        formatName = self.formats[identifier]
        self.calls.append(("dword", formatName, value))

        if formatName == self.failOnFormat:
            raise OSError("marker failed")


def test_wayland_sensitive_backend_uses_history_hint() -> None:
    backend = next(
        backend
        for backend in getClipboardBackends()
        if backend.name == "wayland-sensitive"
    )

    assert backend.copyCommand == ("wl-copy", "--sensitive")
    assert "--paste-once" not in backend.copyCommand
    assert backend.historyProtection is True


def test_wayland_sensitive_backend_is_preferred(
    monkeypatch,
) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setattr(clipboard.sys, "platform", "linux")
    monkeypatch.setattr(
        clipboard.shutil,
        "which",
        lambda executable: (
            f"/usr/bin/{executable}"
            if executable in {"wl-copy", "wl-paste"}
            else None
        ),
    )
    monkeypatch.setattr(clipboard, "commandSupportsOption", lambda *args: True)

    assert findClipboardBackend().name == "wayland-sensitive"


def test_wayland_falls_back_when_sensitive_option_is_unavailable(
    monkeypatch,
) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setattr(clipboard.sys, "platform", "linux")
    monkeypatch.setattr(
        clipboard.shutil,
        "which",
        lambda executable: (
            f"/usr/bin/{executable}"
            if executable in {"wl-copy", "wl-paste"}
            else None
        ),
    )
    monkeypatch.setattr(clipboard, "commandSupportsOption", lambda *args: False)

    backend = findClipboardBackend()

    assert backend is not None
    assert backend.name == "wayland"
    assert backend.historyProtection is False


def test_copyq_sensitive_backend_reads_password_from_standard_input() -> None:
    backend = next(
        backend
        for backend in getClipboardBackends()
        if backend.name == "copyq-sensitive"
    )

    assert backend.copyCommand == COPYQ_SENSITIVE_COPY_COMMAND
    assert backend.copyCommand[-1] == "-"
    assert backend.historyProtection is True


def test_copyq_sensitive_backend_is_preferred_on_x11(monkeypatch) -> None:
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(clipboard.sys, "platform", "linux")
    monkeypatch.setattr(
        clipboard.shutil,
        "which",
        lambda executable: (
            "/usr/bin/copyq"
            if executable == "copyq"
            else None
        ),
    )

    backend = findClipboardBackend()

    assert backend is not None
    assert backend.name == "copyq-sensitive"


def test_windows_native_backend_is_selected(monkeypatch) -> None:
    monkeypatch.setattr(clipboard.sys, "platform", "win32")

    backend = findClipboardBackend()

    assert backend is not None
    assert backend.name == "windows-native"


def test_macos_sensitive_backend_is_selected(monkeypatch) -> None:
    monkeypatch.setattr(clipboard.sys, "platform", "darwin")
    monkeypatch.setattr(
        clipboard.shutil,
        "which",
        lambda executable: f"/usr/bin/{executable}",
    )

    backend = findClipboardBackend()

    assert backend is not None
    assert backend.name == "macos-sensitive"


def test_macos_sensitive_backend_sets_concealed_type() -> None:
    backend = next(
        backend
        for backend in getClipboardBackends()
        if backend.name == "macos-sensitive"
    )

    assert backend.historyProtection is True
    assert MACOS_CONCEALED_TYPE in backend.copyCommand[-1]
    assert MACOS_NATIVE_CONCEALED_TYPE in backend.copyCommand[-1]
    assert "NSPasteboardTypeString" in backend.copyCommand[-1]
    assert "clearContents" in backend.copyCommand[-1]


def test_windows_clipboard_sets_all_secret_markers() -> None:
    api = FakeWindowsClipboardApi()

    writeWindowsClipboard("secret", api)

    assert api.calls[0:3] == [
        ("open",),
        ("empty",),
        ("text", "secret"),
    ]
    assert [
        call[1]
        for call in api.calls
        if call[0] == "register"
    ] == list(WINDOWS_SECRET_FORMATS)
    assert [
        call
        for call in api.calls
        if call[0] == "dword"
    ] == [
        ("dword", formatName, 0)
        for formatName in WINDOWS_SECRET_FORMATS
    ]
    assert api.calls[-1] == ("close",)


def test_windows_clipboard_clears_secret_if_marker_fails() -> None:
    api = FakeWindowsClipboardApi(
        failOnFormat="CanIncludeInClipboardHistory"
    )

    with pytest.raises(OSError, match="marker failed"):
        writeWindowsClipboard("secret", api)

    assert api.calls.count(("empty",)) == 2
    assert api.calls[-1] == ("close",)


def test_copy_to_clipboard_returns_false_without_supported_tool(monkeypatch) -> None:
    monkeypatch.setattr("manager.clipboard.findClipboardBackend", lambda: None)

    result = copyToClipboard("secret")

    assert not result
    assert result.success is False
    assert result.historyProtection is False
    assert result.backendName is None


def test_copy_to_clipboard_schedules_safe_clear(monkeypatch) -> None:
    calls = []

    monkeypatch.setattr(
        "manager.clipboard.findClipboardBackend",
        lambda: TEST_BACKEND,
    )
    monkeypatch.setattr(
        "manager.clipboard.runClipboardCommand",
        lambda command, inputData=None, **kwargs: (
            calls.append((command, inputData)) or b""
        ),
    )
    monkeypatch.setattr(
        "manager.clipboard.scheduleClipboardClear",
        lambda text, backend, seconds: (
            calls.append(("schedule", text, backend.name, seconds)) or True
        ),
    )

    result = copyToClipboard("secret")

    assert result
    assert result.success is True
    assert result.historyProtection is False
    assert result.backendName == "test"
    assert calls == [
        (("copy",), b"secret"),
        ("schedule", "secret", "test", 30),
    ]


def test_clear_clipboard_only_when_secret_is_unchanged(monkeypatch) -> None:
    calls = []

    def fake_run(command, inputData=None, **kwargs):
        calls.append((command, inputData))

        if command == TEST_BACKEND.readCommand:
            return b"secret"

        return b""

    monkeypatch.setattr("manager.clipboard.runClipboardCommand", fake_run)

    assert clearClipboardIfUnchanged("secret", TEST_BACKEND) is True
    assert calls == [
        (("read",), None),
        (("clear",), b""),
    ]


def test_clear_clipboard_preserves_newer_content(monkeypatch) -> None:
    calls = []

    def fake_run(command, inputData=None, **kwargs):
        calls.append((command, inputData))
        return b"new clipboard value"

    monkeypatch.setattr("manager.clipboard.runClipboardCommand", fake_run)

    assert clearClipboardIfUnchanged("secret", TEST_BACKEND) is False
    assert calls == [(("read",), None)]


def test_failed_clear_scheduling_removes_secret_immediately(monkeypatch) -> None:
    calls = []

    monkeypatch.setattr(
        "manager.clipboard.findClipboardBackend",
        lambda: TEST_BACKEND,
    )
    monkeypatch.setattr(
        "manager.clipboard.runClipboardCommand",
        lambda command, inputData=None, **kwargs: (
            calls.append((command, inputData)) or b""
        ),
    )
    monkeypatch.setattr(
        "manager.clipboard.scheduleClipboardClear",
        lambda text, backend, seconds: False,
    )
    monkeypatch.setattr(
        "manager.clipboard.clearClipboardIfUnchanged",
        lambda text, backend: calls.append(("clear-now", text, backend.name)) or True,
    )

    result = copyToClipboard("secret")

    assert not result
    assert result.backendName == "test"
    assert ("clear-now", "secret", "test") in calls


def test_clipboard_write_does_not_capture_daemon_pipes(monkeypatch) -> None:
    calls = []

    def fake_subprocess_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=None, stderr=None)

    monkeypatch.setattr(clipboard.subprocess, "run", fake_subprocess_run)

    clipboard.writeClipboard("secret", TEST_BACKEND)

    command, kwargs = calls[0]
    assert command == TEST_BACKEND.copyCommand
    assert kwargs["input"] == b"secret"
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["timeout"] == clipboard.CLIPBOARD_COMMAND_TIMEOUT_SECONDS


def test_clipboard_timeout_is_reported_as_copy_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        clipboard,
        "findClipboardBackend",
        lambda: TEST_BACKEND,
    )
    monkeypatch.setattr(
        clipboard,
        "writeClipboard",
        lambda text, backend: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(backend.copyCommand, 5)
        ),
    )

    result = copyToClipboard("secret")

    assert result.success is False
    assert result.backendName == "test"
