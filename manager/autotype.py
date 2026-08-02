import asyncio
import ctypes
import os
import secrets
import shutil
import subprocess
import sys
import time
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum


DEFAULT_TYPE_DELAY_SECONDS = 3
MAX_TYPE_DELAY_SECONDS = 30
KEYBOARD_DEVICE = 1
KEY_STATE_RELEASED = 0
KEY_STATE_PRESSED = 1
X11_TAB_KEYSYM = 0xFF09
PORTAL_BUS_NAME = "org.freedesktop.portal.Desktop"
PORTAL_OBJECT_PATH = "/org/freedesktop/portal/desktop"
PORTAL_REMOTE_DESKTOP_INTERFACE = "org.freedesktop.portal.RemoteDesktop"
PORTAL_REQUEST_INTERFACE = "org.freedesktop.portal.Request"
PORTAL_SESSION_INTERFACE = "org.freedesktop.portal.Session"


class AutoTypeError(RuntimeError):
    pass


class AutoTypeCancelledError(AutoTypeError):
    pass


class SpecialKey(Enum):
    TAB = "tab"


TypeAction = str | SpecialKey
Countdown = Callable[[int], None]


@dataclass(frozen=True)
class AutoTypeResult:
    backendName: str


def validateTypeText(text: str) -> None:
    if any(unicodedata.category(character) == "Cc" for character in text):
        raise AutoTypeError(
            "The selected value contains control characters and cannot be typed safely."
        )


def buildTypeActions(
    username: str,
    password: str,
    mode: str,
) -> tuple[TypeAction, ...]:
    if mode == "password":
        actions: tuple[TypeAction, ...] = (password,)
    elif mode == "username":
        if username == "":
            raise AutoTypeError("This entry does not have a username.")
        actions = (username,)
    elif mode == "login":
        if username == "":
            raise AutoTypeError("This entry does not have a username.")
        actions = (username, SpecialKey.TAB, password)
    else:
        raise ValueError(f"Unsupported auto-type mode: {mode}.")

    for action in actions:
        if isinstance(action, str):
            validateTypeText(action)

    return actions


def defaultCountdown(delaySeconds: int) -> None:
    if delaySeconds == 0:
        print("Typing now...", flush=True)
        return

    print("Focus the target field. Press Ctrl+C to cancel.", flush=True)

    for remaining in range(delaySeconds, 0, -1):
        print(f"  Typing in {remaining}...", flush=True)
        time.sleep(1)


def keysymForCharacter(character: str) -> int:
    codepoint = ord(character)

    if codepoint <= 0xFF:
        return codepoint

    return 0x01000000 | codepoint


def requireMethodReturn(message, expectedSignature: str | None = None) -> None:
    from dbus_next.constants import MessageType
    from dbus_next.errors import DBusError

    if message.message_type == MessageType.ERROR:
        raise DBusError._from_message(message)

    if message.message_type != MessageType.METHOD_RETURN:
        raise AutoTypeError("The desktop portal returned an invalid response.")

    if expectedSignature is not None and message.signature != expectedSignature:
        raise AutoTypeError("The desktop portal returned unexpected data.")


class PortalRequestBroker:
    def __init__(self, bus) -> None:
        self.bus = bus
        self.portalOwner: str | None = None
        self.responses: dict[str, tuple[int, dict]] = {}
        self.waiters: dict[str, asyncio.Future] = {}

    async def start(self) -> None:
        from dbus_next import Message

        self.bus.add_message_handler(self.handleMessage)
        rule = (
            "type='signal',"
            f"sender='{PORTAL_BUS_NAME}',"
            f"interface='{PORTAL_REQUEST_INTERFACE}',"
            "member='Response'"
        )
        reply = await self.bus.call(
            Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch",
                signature="s",
                body=[rule],
            )
        )
        requireMethodReturn(reply, "")
        ownerReply = await self.bus.call(
            Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="GetNameOwner",
                signature="s",
                body=[PORTAL_BUS_NAME],
            )
        )
        requireMethodReturn(ownerReply, "s")
        self.portalOwner = ownerReply.body[0]

    def handleMessage(self, message) -> bool:
        from dbus_next.constants import MessageType

        if (
            message.message_type != MessageType.SIGNAL
            or message.interface != PORTAL_REQUEST_INTERFACE
            or message.member != "Response"
            or message.path is None
            or message.sender != self.portalOwner
        ):
            return False

        responseCode, results = message.body
        response = (responseCode, results)
        waiter = self.waiters.pop(message.path, None)

        if waiter is not None and not waiter.done():
            waiter.set_result(response)
        else:
            self.responses[message.path] = response

        return True

    async def callRequest(
        self,
        member: str,
        signature: str,
        body: list,
    ) -> dict:
        from dbus_next import Message

        reply = await self.bus.call(
            Message(
                destination=PORTAL_BUS_NAME,
                path=PORTAL_OBJECT_PATH,
                interface=PORTAL_REMOTE_DESKTOP_INTERFACE,
                member=member,
                signature=signature,
                body=body,
            )
        )
        requireMethodReturn(reply, "o")
        requestPath = reply.body[0]

        if requestPath in self.responses:
            responseCode, results = self.responses.pop(requestPath)
        else:
            waiter = asyncio.get_running_loop().create_future()
            self.waiters[requestPath] = waiter
            responseCode, results = await waiter

        if responseCode == 1:
            raise AutoTypeCancelledError("Auto-type permission was cancelled.")

        if responseCode != 0:
            raise AutoTypeError("The desktop denied the auto-type request.")

        return results


async def callPortalMethod(
    bus,
    *,
    path: str,
    interface: str,
    member: str,
    signature: str = "",
    body: list | None = None,
) -> None:
    from dbus_next import Message

    reply = await bus.call(
        Message(
            destination=PORTAL_BUS_NAME,
            path=path,
            interface=interface,
            member=member,
            signature=signature,
            body=body or [],
        )
    )
    requireMethodReturn(reply, "")


async def sendPortalActions(bus, sessionPath: str, actions: Sequence[TypeAction]) -> None:
    for action in actions:
        if action is SpecialKey.TAB:
            keysyms = (X11_TAB_KEYSYM,)
        else:
            keysyms = tuple(keysymForCharacter(character) for character in action)

        for keysym in keysyms:
            for state in (KEY_STATE_PRESSED, KEY_STATE_RELEASED):
                await callPortalMethod(
                    bus,
                    path=PORTAL_OBJECT_PATH,
                    interface=PORTAL_REMOTE_DESKTOP_INTERFACE,
                    member="NotifyKeyboardKeysym",
                    signature="oa{sv}iu",
                    body=[sessionPath, {}, keysym, state],
                )

            await asyncio.sleep(0.002)


async def typeWithWaylandPortal(
    actions: Sequence[TypeAction],
    delaySeconds: int,
    countdown: Countdown,
) -> None:
    try:
        from dbus_next import Variant
        from dbus_next.aio import MessageBus
    except ImportError as error:
        raise AutoTypeError(
            "Wayland auto-type support is not installed. Reinstall the project."
        ) from error

    bus = None
    sessionPath = None

    try:
        bus = await MessageBus().connect()
        broker = PortalRequestBroker(bus)
        await broker.start()
        requestToken = secrets.token_hex(8)
        sessionToken = secrets.token_hex(8)
        createResults = await broker.callRequest(
            "CreateSession",
            "a{sv}",
            [
                {
                    "handle_token": Variant("s", f"pm_create_{requestToken}"),
                    "session_handle_token": Variant(
                        "s",
                        f"pm_session_{sessionToken}",
                    ),
                }
            ],
        )
        sessionVariant = createResults.get("session_handle")

        if sessionVariant is None:
            raise AutoTypeError("The desktop portal did not create a session.")

        sessionPath = sessionVariant.value
        await broker.callRequest(
            "SelectDevices",
            "oa{sv}",
            [
                sessionPath,
                {
                    "handle_token": Variant(
                        "s",
                        f"pm_devices_{secrets.token_hex(8)}",
                    ),
                    "types": Variant("u", KEYBOARD_DEVICE),
                    "persist_mode": Variant("u", 0),
                },
            ],
        )
        startResults = await broker.callRequest(
            "Start",
            "osa{sv}",
            [
                sessionPath,
                "",
                {
                    "handle_token": Variant(
                        "s",
                        f"pm_start_{secrets.token_hex(8)}",
                    ),
                },
            ],
        )
        devicesVariant = startResults.get("devices")

        if (
            devicesVariant is None
            or devicesVariant.value & KEYBOARD_DEVICE == 0
        ):
            raise AutoTypeError("Keyboard access was not granted.")

        countdown(delaySeconds)
        await sendPortalActions(bus, sessionPath, actions)
    except AutoTypeError:
        raise
    except Exception as error:
        raise AutoTypeError(f"Wayland auto-type failed: {error}") from error
    finally:
        if bus is not None and sessionPath is not None:
            try:
                await callPortalMethod(
                    bus,
                    path=sessionPath,
                    interface=PORTAL_SESSION_INTERFACE,
                    member="Close",
                )
            except Exception:
                pass

        if bus is not None:
            bus.disconnect()


def typeWithXdotool(
    actions: Sequence[TypeAction],
    delaySeconds: int,
    countdown: Countdown,
) -> None:
    executable = shutil.which("xdotool")

    if executable is None:
        raise AutoTypeError(
            "X11 auto-type requires xdotool. Install the 'xdotool' package."
        )

    countdown(delaySeconds)

    for action in actions:
        if action is SpecialKey.TAB:
            command = [executable, "key", "--clearmodifiers", "Tab"]
            inputData = None
        else:
            command = [
                executable,
                "type",
                "--clearmodifiers",
                "--delay",
                "2",
                "--file",
                "-",
            ]
            inputData = action.encode("utf-8")

        try:
            subprocess.run(
                command,
                input=inputData,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise AutoTypeError("X11 auto-type failed.") from error


def typeWithWindows(
    actions: Sequence[TypeAction],
    delaySeconds: int,
    countdown: Countdown,
) -> None:
    from ctypes import wintypes

    inputKeyboard = 1
    keyeventKeyup = 0x0002
    keyeventUnicode = 0x0004
    virtualKeyTab = 0x09
    pointerSizedUnsigned = ctypes.c_size_t

    class KeyboardInput(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", pointerSizedUnsigned),
        ]

    class InputUnion(ctypes.Union):
        _fields_ = [("ki", KeyboardInput)]

    class Input(ctypes.Structure):
        _anonymous_ = ("value",)
        _fields_ = [
            ("type", wintypes.DWORD),
            ("value", InputUnion),
        ]

    def keyboardInput(
        virtualKey: int,
        scanCode: int,
        flags: int,
    ) -> Input:
        return Input(
            type=inputKeyboard,
            value=InputUnion(
                ki=KeyboardInput(
                    wVk=virtualKey,
                    wScan=scanCode,
                    dwFlags=flags,
                    time=0,
                    dwExtraInfo=0,
                )
            ),
        )

    events = []

    for action in actions:
        if action is SpecialKey.TAB:
            events.extend(
                (
                    keyboardInput(virtualKeyTab, 0, 0),
                    keyboardInput(virtualKeyTab, 0, keyeventKeyup),
                )
            )
            continue

        encoded = action.encode("utf-16-le")

        for index in range(0, len(encoded), 2):
            codeUnit = int.from_bytes(encoded[index:index + 2], "little")
            events.extend(
                (
                    keyboardInput(0, codeUnit, keyeventUnicode),
                    keyboardInput(
                        0,
                        codeUnit,
                        keyeventUnicode | keyeventKeyup,
                    ),
                )
            )

    countdown(delaySeconds)

    if not events:
        return

    eventArray = (Input * len(events))(*events)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendInput.argtypes = [
        wintypes.UINT,
        ctypes.POINTER(Input),
        ctypes.c_int,
    ]
    user32.SendInput.restype = wintypes.UINT
    sent = user32.SendInput(len(events), eventArray, ctypes.sizeof(Input))

    if sent != len(events):
        raise AutoTypeError("Windows blocked the simulated keyboard input.")


def typeWithMacOS(
    actions: Sequence[TypeAction],
    delaySeconds: int,
    countdown: Countdown,
) -> None:
    coreGraphics = ctypes.CDLL(
        "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"
    )
    coreFoundation = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )
    coreGraphics.CGEventCreateKeyboardEvent.restype = ctypes.c_void_p
    coreGraphics.CGEventCreateKeyboardEvent.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ushort,
        ctypes.c_bool,
    ]
    coreGraphics.CGEventKeyboardSetUnicodeString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ushort),
    ]
    coreGraphics.CGEventPost.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
    coreFoundation.CFRelease.argtypes = [ctypes.c_void_p]
    hidEventTap = 0
    tabKeyCode = 0x30

    def postKey(keyCode: int, pressed: bool, text: str | None = None) -> None:
        event = coreGraphics.CGEventCreateKeyboardEvent(
            None,
            keyCode,
            pressed,
        )

        if not event:
            raise AutoTypeError("macOS could not create a keyboard event.")

        try:
            if text is not None:
                encoded = text.encode("utf-16-le")
                units = [
                    int.from_bytes(encoded[index:index + 2], "little")
                    for index in range(0, len(encoded), 2)
                ]
                unitArray = (ctypes.c_ushort * len(units))(*units)
                coreGraphics.CGEventKeyboardSetUnicodeString(
                    event,
                    len(units),
                    unitArray,
                )

            coreGraphics.CGEventPost(hidEventTap, event)
        finally:
            coreFoundation.CFRelease(event)

    countdown(delaySeconds)

    for action in actions:
        if action is SpecialKey.TAB:
            postKey(tabKeyCode, True)
            postKey(tabKeyCode, False)
            continue

        for character in action:
            postKey(0, True, character)
            postKey(0, False, character)
            time.sleep(0.002)


def typeActions(
    actions: Sequence[TypeAction],
    delaySeconds: int = DEFAULT_TYPE_DELAY_SECONDS,
    countdown: Countdown = defaultCountdown,
) -> AutoTypeResult:
    if delaySeconds < 0 or delaySeconds > MAX_TYPE_DELAY_SECONDS:
        raise ValueError(
            f"Auto-type delay must be between 0 and {MAX_TYPE_DELAY_SECONDS} seconds."
        )

    if sys.platform.startswith("win"):
        typeWithWindows(actions, delaySeconds, countdown)
        return AutoTypeResult("windows-native")

    if sys.platform == "darwin":
        typeWithMacOS(actions, delaySeconds, countdown)
        return AutoTypeResult("macos-native")

    if os.environ.get("WAYLAND_DISPLAY"):
        asyncio.run(typeWithWaylandPortal(actions, delaySeconds, countdown))
        return AutoTypeResult("wayland-portal")

    if os.environ.get("DISPLAY"):
        typeWithXdotool(actions, delaySeconds, countdown)
        return AutoTypeResult("x11-xdotool")

    raise AutoTypeError("No supported graphical desktop session was detected.")


def typeCredential(
    username: str,
    password: str,
    mode: str,
    delaySeconds: int = DEFAULT_TYPE_DELAY_SECONDS,
    countdown: Countdown = defaultCountdown,
) -> AutoTypeResult:
    actions = buildTypeActions(username, password, mode)
    return typeActions(actions, delaySeconds, countdown)
