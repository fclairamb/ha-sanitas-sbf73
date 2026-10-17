"""Minimal BlueZ pairing agent, registered only while the config flow pairs the scale.

Home Assistant registers no BlueZ agent, so a pairing that asks for a passkey would
fail. This agent forwards the passkey request to the config flow, where the user
types the code shown on the scale display.
"""

import asyncio
import logging

from dbus_fast import BusType, Message, MessageType
from dbus_fast.aio import MessageBus
from dbus_fast.annotations import DBusObjectPath, DBusStr, DBusUInt16, DBusUInt32
from dbus_fast.service import ServiceInterface, dbus_method

_LOGGER = logging.getLogger(__name__)

AGENT_PATH = "/org/homeassistant/sanitas_sbf73/agent"
PASSKEY_TIMEOUT_S = 60


class PasskeyAgent(ServiceInterface):
    """org.bluez.Agent1 that waits for the passkey from the config flow."""

    def __init__(self) -> None:
        super().__init__("org.bluez.Agent1")
        self.passkey_requested = asyncio.Event()
        self._passkey: asyncio.Future[int] | None = None
        self._bus: MessageBus | None = None

    async def register(self) -> None:
        self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        self._bus.export(AGENT_PATH, self)
        await self._call("RegisterAgent", "os", [AGENT_PATH, "KeyboardDisplay"])
        await self._call("RequestDefaultAgent", "o", [AGENT_PATH])

    async def unregister(self) -> None:
        if self._bus is None:
            return
        try:
            await self._call("UnregisterAgent", "o", [AGENT_PATH])
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("UnregisterAgent failed: %s", err)
        self._bus.disconnect()
        self._bus = None

    def provide_passkey(self, passkey: int) -> None:
        self.passkey_requested.clear()
        if self._passkey is not None and not self._passkey.done():
            self._passkey.set_result(passkey)

    async def _call(self, member: str, signature: str, body: list) -> None:
        assert self._bus is not None
        reply = await self._bus.call(
            Message(
                destination="org.bluez",
                path="/org/bluez",
                interface="org.bluez.AgentManager1",
                member=member,
                signature=signature,
                body=body,
            )
        )
        if reply is None or reply.message_type == MessageType.ERROR:
            raise RuntimeError(f"BlueZ {member} failed: {reply and reply.body}")

    @dbus_method()
    async def RequestPasskey(self, device: DBusObjectPath) -> DBusUInt32:  # noqa: N802
        _LOGGER.debug("Passkey requested for %s", device)
        self._passkey = asyncio.get_running_loop().create_future()
        self.passkey_requested.set()
        return await asyncio.wait_for(self._passkey, PASSKEY_TIMEOUT_S)

    @dbus_method()
    def DisplayPasskey(  # noqa: N802
        self, device: DBusObjectPath, passkey: DBusUInt32, entered: DBusUInt16
    ) -> None:
        _LOGGER.debug("Passkey %06d displayed for %s", passkey, device)

    @dbus_method()
    def RequestConfirmation(self, device: DBusObjectPath, passkey: DBusUInt32) -> None:  # noqa: N802
        _LOGGER.debug("Confirming passkey %06d for %s", passkey, device)

    @dbus_method()
    def RequestAuthorization(self, device: DBusObjectPath) -> None:  # noqa: N802
        pass

    @dbus_method()
    def AuthorizeService(self, device: DBusObjectPath, uuid: DBusStr) -> None:  # noqa: N802
        pass

    @dbus_method()
    def Release(self) -> None:  # noqa: N802
        pass

    @dbus_method()
    def Cancel(self) -> None:  # noqa: N802
        _LOGGER.debug("Pairing cancelled by BlueZ")
