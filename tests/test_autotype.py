import asyncio
import subprocess

import pytest
from dbus_next import Message
from dbus_next.constants import MessageType

from manager import autotype


def test_build_type_actions_defaults_to_password() -> None:
    actions = autotype.buildTypeActions("user@example.com", "secret", "password")

    assert actions == ("secret",)


def test_build_type_actions_can_type_username_and_login() -> None:
    assert autotype.buildTypeActions("user", "secret", "username") == ("user",)
    assert autotype.buildTypeActions("user", "secret", "login") == (
        "user",
        autotype.SpecialKey.TAB,
        "secret",
    )


@pytest.mark.parametrize("mode", ["username", "login"])
def test_build_type_actions_rejects_missing_username(mode: str) -> None:
    with pytest.raises(autotype.AutoTypeError, match="does not have a username"):
        autotype.buildTypeActions("", "secret", mode)


@pytest.mark.parametrize("value", ["line\nbreak", "tab\tvalue", "null\0value"])
def test_build_type_actions_rejects_control_characters(value: str) -> None:
    with pytest.raises(autotype.AutoTypeError, match="control characters"):
        autotype.buildTypeActions("user", value, "password")


def test_keysym_supports_ascii_and_unicode() -> None:
    assert autotype.keysymForCharacter("A") == ord("A")
    assert autotype.keysymForCharacter("ø") == ord("ø")
    assert autotype.keysymForCharacter("€") == 0x010020AC


def test_default_countdown_waits_once_per_second(monkeypatch, capsys) -> None:
    waits = []
    monkeypatch.setattr(autotype.time, "sleep", lambda seconds: waits.append(seconds))

    autotype.defaultCountdown(3)

    assert waits == [1, 1, 1]
    output = capsys.readouterr().out
    assert "Press Ctrl+C to cancel" in output
    assert "Typing in 3" in output
    assert "Typing in 1" in output


def test_xdotool_receives_secrets_on_standard_input(monkeypatch) -> None:
    calls = []
    countdowns = []
    monkeypatch.setattr(autotype.shutil, "which", lambda name: "/usr/bin/xdotool")

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(autotype.subprocess, "run", fake_run)

    autotype.typeWithXdotool(
        ("user@example.com", autotype.SpecialKey.TAB, "supersecret"),
        3,
        lambda delay: countdowns.append(delay),
    )

    assert countdowns == [3]
    assert calls[0][1]["input"] == b"user@example.com"
    assert calls[1][0][-1] == "Tab"
    assert calls[2][1]["input"] == b"supersecret"
    assert all("supersecret" not in argument for argument in calls[2][0])
    assert all("Return" not in argument and "Enter" not in argument for call in calls for argument in call[0])


def test_type_actions_selects_wayland_portal(monkeypatch) -> None:
    calls = []

    async def fake_type(actions, delay, countdown):
        calls.append((actions, delay, countdown))

    countdown = lambda delay: None
    monkeypatch.setattr(autotype.sys, "platform", "linux")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(autotype, "typeWithWaylandPortal", fake_type)

    result = autotype.typeActions(("secret",), 4, countdown)

    assert result.backendName == "wayland-portal"
    assert calls == [(("secret",), 4, countdown)]


def test_type_actions_selects_x11_without_wayland(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(autotype.sys, "platform", "linux")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(
        autotype,
        "typeWithXdotool",
        lambda actions, delay, countdown: calls.append((actions, delay)),
    )

    result = autotype.typeActions(("secret",), 2, lambda delay: None)

    assert result.backendName == "x11-xdotool"
    assert calls == [(("secret",), 2)]


def test_type_actions_rejects_invalid_delay() -> None:
    with pytest.raises(ValueError, match="between 0 and 30"):
        autotype.typeActions(("secret",), 31)


def test_portal_actions_send_tab_but_never_enter(monkeypatch) -> None:
    events = []

    async def fake_call(bus, **kwargs):
        events.append((kwargs["body"][2], kwargs["body"][3]))

    async def fake_sleep(seconds):
        return None

    monkeypatch.setattr(autotype, "callPortalMethod", fake_call)
    monkeypatch.setattr(autotype.asyncio, "sleep", fake_sleep)

    asyncio.run(
        autotype.sendPortalActions(
            object(),
            "/session",
            ("a", autotype.SpecialKey.TAB, "B"),
        )
    )

    pressedKeysyms = [
        keysym
        for keysym, state in events
        if state == autotype.KEY_STATE_PRESSED
    ]
    assert pressedKeysyms == [ord("a"), autotype.X11_TAB_KEYSYM, ord("B")]
    assert 0xFF0D not in pressedKeysyms


def test_portal_broker_ignores_response_from_wrong_sender() -> None:
    broker = autotype.PortalRequestBroker(object())
    broker.portalOwner = ":1.42"
    message = Message(
        message_type=MessageType.SIGNAL,
        sender=":1.99",
        path="/org/freedesktop/portal/desktop/request/1_1/token",
        interface=autotype.PORTAL_REQUEST_INTERFACE,
        member="Response",
        signature="ua{sv}",
        body=[0, {}],
    )

    assert broker.handleMessage(message) is False
    assert broker.responses == {}
