import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_CLEAR_SECONDS = 30
CLIPBOARD_COMMAND_TIMEOUT_SECONDS = 5
WAYLAND_SENSITIVE_OPTION = "--sensitive"
MACOS_CONCEALED_TYPE = "application/x-nspasteboard-concealed-type"
MACOS_NATIVE_CONCEALED_TYPE = "org.nspasteboard.ConcealedType"
MACOS_CONCEALED_TYPES = (
    MACOS_CONCEALED_TYPE,
    MACOS_NATIVE_CONCEALED_TYPE,
)
WINDOWS_SECRET_FORMATS = (
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
    "Clipboard Viewer Ignore",
)
COPYQ_SENSITIVE_COPY_COMMAND = (
    "copyq",
    "copy",
    "x-kde-passwordManagerHint",
    "secret",
    "text/plain",
    "-",
)
MACOS_SENSITIVE_COPY_SCRIPT = f"""
ObjC.import('AppKit');
ObjC.import('Foundation');

const input = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
const text = $.NSString.alloc.initWithDataEncoding(
    input,
    $.NSUTF8StringEncoding
);
const pasteboard = $.NSPasteboard.generalPasteboard;

pasteboard.clearContents;
const textWritten = pasteboard.setStringForType(
    text,
    $.NSPasteboardTypeString
);
const markerTypes = [
    '{MACOS_CONCEALED_TYPE}',
    '{MACOS_NATIVE_CONCEALED_TYPE}'
];
let markerWritten = true;

for (const markerType of markerTypes) {{
    markerWritten = pasteboard.setStringForType(
        'concealed',
        markerType
    ) && markerWritten;
}}

if (!textWritten || !markerWritten) {{
    pasteboard.clearContents;
    throw new Error('Could not set protected clipboard content');
}}
""".strip()


@dataclass(frozen=True)
class ClipboardBackend:
    name: str
    copyCommand: tuple[str, ...]
    readCommand: tuple[str, ...]
    clearCommand: tuple[str, ...]
    requiredCopyOption: str | None = None
    nativeHandler: str | None = None
    historyProtection: bool = False


@dataclass(frozen=True)
class ClipboardCopyResult:
    success: bool
    historyProtection: bool
    backendName: str | None

    def __bool__(self) -> bool:
        return self.success


def getClipboardBackends() -> list[ClipboardBackend]:
    backends = [
        ClipboardBackend(
            "wayland-sensitive",
            ("wl-copy", WAYLAND_SENSITIVE_OPTION),
            ("wl-paste", "--no-newline"),
            ("wl-copy", "--clear"),
            requiredCopyOption=WAYLAND_SENSITIVE_OPTION,
            historyProtection=True,
        ),
        ClipboardBackend(
            "copyq-sensitive",
            COPYQ_SENSITIVE_COPY_COMMAND,
            ("copyq", "clipboard"),
            ("copyq", "copy", ""),
            historyProtection=True,
        ),
        ClipboardBackend(
            "wayland",
            ("wl-copy",),
            ("wl-paste", "--no-newline"),
            ("wl-copy", "--clear"),
        ),
        ClipboardBackend(
            "xclip",
            ("xclip", "-selection", "clipboard"),
            ("xclip", "-selection", "clipboard", "-o"),
            ("xclip", "-selection", "clipboard"),
        ),
        ClipboardBackend(
            "xsel",
            ("xsel", "--clipboard", "--input"),
            ("xsel", "--clipboard", "--output"),
            ("xsel", "--clipboard", "--input"),
        ),
        ClipboardBackend(
            "macos-sensitive",
            (
                "osascript",
                "-l",
                "JavaScript",
                "-e",
                MACOS_SENSITIVE_COPY_SCRIPT,
            ),
            ("pbpaste",),
            ("pbcopy",),
            historyProtection=True,
        ),
        ClipboardBackend(
            "macos",
            ("pbcopy",),
            ("pbpaste",),
            ("pbcopy",),
        ),
        ClipboardBackend(
            "windows-native",
            (),
            (),
            (),
            nativeHandler="windows",
            historyProtection=True,
        ),
    ]

    return backends


def commandSupportsOption(executable: str, option: str) -> bool:
    try:
        result = subprocess.run(
            [executable, "--help"],
            capture_output=True,
            check=False,
            timeout=CLIPBOARD_COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False

    return option.encode("utf-8") in result.stdout + result.stderr


def backendSupportsCurrentPlatform(backend: ClipboardBackend) -> bool:
    if backend.nativeHandler == "windows":
        return sys.platform.startswith("win")

    if backend.name.startswith("macos"):
        return sys.platform == "darwin"

    if backend.name.startswith("wayland"):
        return (
            sys.platform.startswith("linux")
            and bool(os.environ.get("WAYLAND_DISPLAY"))
        )

    if backend.name == "copyq-sensitive":
        return (
            sys.platform.startswith("linux")
            and bool(
                os.environ.get("WAYLAND_DISPLAY")
                or os.environ.get("DISPLAY")
            )
        )

    if backend.name in {"xclip", "xsel"}:
        return (
            sys.platform.startswith("linux")
            and bool(os.environ.get("DISPLAY"))
        )

    return True


def findClipboardBackend(name: str | None = None) -> ClipboardBackend | None:
    for backend in getClipboardBackends():
        if name is not None and backend.name != name:
            continue

        if not backendSupportsCurrentPlatform(backend):
            continue

        if backend.nativeHandler == "windows":
            return backend

        commands = (
            backend.copyCommand,
            backend.readCommand,
            backend.clearCommand,
        )
        if not all(
            command and shutil.which(command[0]) is not None
            for command in commands
        ):
            continue

        if (
            backend.requiredCopyOption is not None
            and not commandSupportsOption(
                backend.copyCommand[0],
                backend.requiredCopyOption,
            )
        ):
            continue

        return backend

    return None


def runClipboardCommand(
    command: tuple[str, ...],
    inputData: bytes | None = None,
    *,
    captureOutput: bool = True,
) -> bytes:
    result = subprocess.run(
        command,
        input=inputData,
        stdout=subprocess.PIPE if captureOutput else subprocess.DEVNULL,
        stderr=subprocess.PIPE if captureOutput else subprocess.DEVNULL,
        check=True,
        timeout=CLIPBOARD_COMMAND_TIMEOUT_SECONDS,
    )
    return result.stdout or b""


class WindowsClipboardApi:
    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        self.user32.OpenClipboard.argtypes = [wintypes.HWND]
        self.user32.OpenClipboard.restype = wintypes.BOOL
        self.user32.CloseClipboard.argtypes = []
        self.user32.CloseClipboard.restype = wintypes.BOOL
        self.user32.EmptyClipboard.argtypes = []
        self.user32.EmptyClipboard.restype = wintypes.BOOL
        self.user32.SetClipboardData.argtypes = [
            wintypes.UINT,
            wintypes.HANDLE,
        ]
        self.user32.SetClipboardData.restype = wintypes.HANDLE
        self.user32.GetClipboardData.argtypes = [wintypes.UINT]
        self.user32.GetClipboardData.restype = wintypes.HANDLE
        self.user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
        self.user32.RegisterClipboardFormatW.restype = wintypes.UINT
        self.kernel32.GlobalAlloc.argtypes = [
            wintypes.UINT,
            ctypes.c_size_t,
        ]
        self.kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
        self.kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        self.kernel32.GlobalLock.restype = ctypes.c_void_p
        self.kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        self.kernel32.GlobalUnlock.restype = wintypes.BOOL
        self.kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
        self.kernel32.GlobalFree.restype = wintypes.HGLOBAL

    def raiseLastError(self) -> None:
        raise self.ctypes.WinError(self.ctypes.get_last_error())

    def open(self) -> None:
        for _ in range(20):
            if self.user32.OpenClipboard(None):
                return

            time.sleep(0.01)

        self.raiseLastError()

    def close(self) -> None:
        if not self.user32.CloseClipboard():
            self.raiseLastError()

    def empty(self) -> None:
        if not self.user32.EmptyClipboard():
            self.raiseLastError()

    def registerFormat(self, name: str) -> int:
        formatIdentifier = self.user32.RegisterClipboardFormatW(name)

        if formatIdentifier == 0:
            self.raiseLastError()

        return formatIdentifier

    def setBytes(self, formatIdentifier: int, value: bytes) -> None:
        handle = self.kernel32.GlobalAlloc(self.GMEM_MOVEABLE, len(value))

        if not handle:
            self.raiseLastError()

        pointer = self.kernel32.GlobalLock(handle)

        if not pointer:
            self.kernel32.GlobalFree(handle)
            self.raiseLastError()

        try:
            self.ctypes.memmove(pointer, value, len(value))
        finally:
            self.kernel32.GlobalUnlock(handle)

        if not self.user32.SetClipboardData(formatIdentifier, handle):
            self.kernel32.GlobalFree(handle)
            self.raiseLastError()

    def setText(self, text: str) -> None:
        self.setBytes(
            self.CF_UNICODETEXT,
            f"{text}\0".encode("utf-16-le"),
        )

    def setDword(self, formatIdentifier: int, value: int) -> None:
        self.setBytes(
            formatIdentifier,
            value.to_bytes(4, byteorder="little", signed=False),
        )

    def readText(self) -> str:
        handle = self.user32.GetClipboardData(self.CF_UNICODETEXT)

        if not handle:
            return ""

        pointer = self.kernel32.GlobalLock(handle)

        if not pointer:
            self.raiseLastError()

        try:
            return self.ctypes.wstring_at(pointer)
        finally:
            self.kernel32.GlobalUnlock(handle)


def writeWindowsClipboard(
    text: str,
    api: Any | None = None,
) -> None:
    clipboardApi = api or WindowsClipboardApi()
    clipboardApi.open()

    try:
        clipboardApi.empty()
        clipboardApi.setText(text)

        for formatName in WINDOWS_SECRET_FORMATS:
            formatIdentifier = clipboardApi.registerFormat(formatName)
            clipboardApi.setDword(formatIdentifier, 0)
    except Exception:
        clipboardApi.empty()
        raise
    finally:
        clipboardApi.close()


def readWindowsClipboard(api: Any | None = None) -> str:
    clipboardApi = api or WindowsClipboardApi()
    clipboardApi.open()

    try:
        return clipboardApi.readText()
    finally:
        clipboardApi.close()


def clearWindowsClipboard(api: Any | None = None) -> None:
    clipboardApi = api or WindowsClipboardApi()
    clipboardApi.open()

    try:
        clipboardApi.empty()
    finally:
        clipboardApi.close()


def writeClipboard(text: str, backend: ClipboardBackend) -> None:
    if backend.nativeHandler == "windows":
        writeWindowsClipboard(text)
        return

    runClipboardCommand(
        backend.copyCommand,
        text.encode("utf-8"),
        captureOutput=False,
    )


def readClipboard(backend: ClipboardBackend) -> str:
    if backend.nativeHandler == "windows":
        return readWindowsClipboard()

    return runClipboardCommand(backend.readCommand).decode("utf-8")


def clearClipboard(backend: ClipboardBackend) -> None:
    if backend.nativeHandler == "windows":
        clearWindowsClipboard()
        return

    runClipboardCommand(
        backend.clearCommand,
        b"",
        captureOutput=False,
    )


def clearClipboardIfUnchanged(text: str, backend: ClipboardBackend) -> bool:
    try:
        currentValue = readClipboard(backend)

        if currentValue != text:
            return False

        clearClipboard(backend)
        return True
    except (
        OSError,
        UnicodeDecodeError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        return False


def scheduleClipboardClear(
    text: str,
    backend: ClipboardBackend,
    clearAfterSeconds: int,
) -> bool:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--clear-worker",
        backend.name,
        str(clearAfterSeconds),
    ]
    creationFlags = 0

    if os.name == "nt":
        creationFlags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name != "nt",
            creationflags=creationFlags,
        )

        if process.stdin is None:
            return False

        process.stdin.write(text.encode("utf-8"))
        process.stdin.close()
        return True
    except (OSError, BrokenPipeError):
        return False


def copyToClipboard(
    text: str,
    clearAfterSeconds: int = DEFAULT_CLEAR_SECONDS,
) -> ClipboardCopyResult:
    if clearAfterSeconds < 1:
        raise ValueError("Clipboard clear delay must be at least one second.")

    backend = findClipboardBackend()

    if backend is None:
        return ClipboardCopyResult(False, False, None)

    try:
        writeClipboard(text, backend)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        return ClipboardCopyResult(
            False,
            backend.historyProtection,
            backend.name,
        )

    if scheduleClipboardClear(text, backend, clearAfterSeconds):
        return ClipboardCopyResult(
            True,
            backend.historyProtection,
            backend.name,
        )

    clearClipboardIfUnchanged(text, backend)
    return ClipboardCopyResult(
        False,
        backend.historyProtection,
        backend.name,
    )


def runClearWorker(backendName: str, clearAfterSeconds: int) -> None:
    text = sys.stdin.buffer.read().decode("utf-8")
    backend = findClipboardBackend(backendName)

    if backend is None:
        return

    time.sleep(clearAfterSeconds)
    clearClipboardIfUnchanged(text, backend)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--clear-worker":
        runClearWorker(sys.argv[2], int(sys.argv[3]))
