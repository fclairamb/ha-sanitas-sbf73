"""BLE session with a Sanitas SBF73 scale, following the sequence of the official app."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import date, datetime
import logging

from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from . import bluez, protocol as p

_LOGGER = logging.getLogger(__name__)

# Subscription order used by the app, which waits 1 s between each.
NOTIFY_ORDER = (
    p.CHR_CURRENT_TIME,
    p.CHR_VENDOR_USER_LIST,
    p.CHR_USER_CONTROL_POINT,
    p.CHR_WEIGHT_MEASUREMENT,
    p.CHR_DB_CHANGE_INCREMENT,
    p.CHR_BODY_COMPOSITION,
    p.CHR_VENDOR_TAKE_MEASUREMENT,
)
NOTIFY_DELAY_S = 0.5
RESPONSE_TIMEOUT_S = 10


class ScaleError(Exception):
    """The scale refused or did not answer a request."""


class Sbf73Client:
    """One connection to the scale. Use connect(), then the requests, then disconnect()."""

    def __init__(
        self,
        ble_device: BLEDevice,
        on_measurement: Callable[[p.Measurement], None] | None = None,
    ) -> None:
        self._device = ble_device
        self._on_measurement = on_measurement
        self._client: BleakClientWithServiceCache | None = None
        self._ucp: asyncio.Queue[p.UcpResponse] = asyncio.Queue()
        self._user_list: asyncio.Queue[p.ScaleUser | int] = asyncio.Queue()
        self._take: asyncio.Queue[int] = asyncio.Queue()
        self._pending: p.Measurement | None = None
        self._last_packet = 0.0
        self._last_notify: tuple[str, bytes] | None = None
        self._last_notify_at = 0.0
        self._disconnected = asyncio.Event()

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    async def connect(self, pair: bool = False) -> None:
        self._disconnected.clear()
        self._client = await establish_connection(
            BleakClientWithServiceCache,
            self._device,
            self._device.name or self._device.address,
            disconnected_callback=lambda _: self._disconnected.set(),
            max_attempts=3,
        )
        if pair:
            await self._client.pair()
        for uuid in NOTIFY_ORDER:
            await asyncio.sleep(NOTIFY_DELAY_S)
            await self._client.start_notify(uuid, self._handle)
        await self._write(p.CHR_CURRENT_TIME, p.build_current_time(datetime.now()))
        await asyncio.sleep(0.2)

    async def disconnect(self) -> None:
        self._flush()
        if self._client is not None:
            await self._client.disconnect()
            self._client = None
        try:
            await bluez.async_disconnect(self._device.address)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("BlueZ Disconnect failed: %s", err)

    async def list_users(self) -> list[p.ScaleUser]:
        _drain(self._user_list)
        await self._write(p.CHR_VENDOR_USER_LIST, b"\x00")
        users: list[p.ScaleUser] = []
        # Records, then a status byte: 01 = complete, 02 = failed / no user.
        while isinstance(item := await self._get(self._user_list), p.ScaleUser):
            users.append(item)
        return users

    async def show_pin(self, user_index: int) -> None:
        """Ask the scale to display the 4-digit PIN of an existing user."""
        _drain(self._user_list)
        await self._write(
            p.CHR_VENDOR_USER_LIST, bytes([p.USER_LIST_SHOW_PIN_BASE + user_index])
        )
        status = await self._get(self._user_list)
        if status != p.PIN_SHOWN:
            raise ScaleError(f"scale could not display the PIN (status {status!r})")

    async def register(self, consent_code: int) -> int:
        """Create a user on the scale, return its index."""
        resp = await self._ucp_request(p.build_register_new_user(consent_code))
        if not resp.ok or resp.user_index is None:
            raise ScaleError(f"user registration failed: {resp.result_name}")
        return resp.user_index

    async def consent(self, user_index: int, consent_code: int, attempts: int = 1) -> bool:
        for _ in range(attempts):
            resp = await self._ucp_request(p.build_consent(user_index, consent_code))
            if resp.ok:
                return True
            if resp.result != p.UCP_USER_NOT_AUTHORIZED:
                raise ScaleError(f"consent failed: {resp.result_name}")
            await asyncio.sleep(0.2)
        return False

    async def write_user_data(
        self,
        birth_date: date,
        gender: int,
        height_cm: int,
        activity_level: int,
        initials: str,
        db_change_increment: int,
    ) -> None:
        """Write the profile of the consented user, in the app's order."""
        for uuid, payload in (
            (p.CHR_DATE_OF_BIRTH, p.build_date_of_birth(birth_date)),
            (p.CHR_GENDER, p.build_gender(gender)),
            (p.CHR_HEIGHT, p.build_height(height_cm)),
            (p.CHR_VENDOR_ACTIVITY_LEVEL, p.build_activity_level(activity_level)),
            (p.CHR_VENDOR_INITIALS, p.build_initials(initials)),
            (p.CHR_DB_CHANGE_INCREMENT, p.build_db_change_increment(db_change_increment)),
        ):
            await self._write(uuid, payload)
            await asyncio.sleep(0.05)

    async def take_measurement(self) -> None:
        """Ask the scale to measure the consented user (initial reference weighing)."""
        _drain(self._take)
        await self._write(p.CHR_VENDOR_TAKE_MEASUREMENT, b"\x00")
        status = await self._get(self._take)
        if status != p.TAKE_MEASUREMENT_OK:
            raise ScaleError(f"scale refused the measurement (status {status})")

    async def read_battery(self) -> int | None:
        assert self._client is not None
        try:
            return (await self._client.read_gatt_char(p.CHR_BATTERY_LEVEL))[0]
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Battery read failed: %s", err)
            return None

    async def wait_quiet(self, quiet_s: float, max_s: float) -> None:
        """Wait until no measurement arrived for quiet_s, the scale left, or max_s elapsed."""
        loop = asyncio.get_running_loop()
        self._last_packet = loop.time()
        deadline = loop.time() + max_s
        while not self._disconnected.is_set():
            now = loop.time()
            if now >= deadline or now - self._last_packet >= quiet_s:
                return
            try:
                await asyncio.wait_for(self._disconnected.wait(), 0.5)
            except TimeoutError:
                pass

    async def _ucp_request(self, payload: bytes) -> p.UcpResponse:
        _drain(self._ucp)
        await self._write(p.CHR_USER_CONTROL_POINT, payload)
        while True:
            resp = await self._get(self._ucp)
            if resp.request == payload[0]:
                return resp

    async def _write(self, uuid: str, payload: bytes) -> None:
        if self._client is None:
            raise ScaleError("not connected")
        _LOGGER.debug("Write %s: %s", uuid[4:8], payload.hex())
        await self._client.write_gatt_char(uuid, payload, response=True)

    async def _get(self, queue: asyncio.Queue):
        get = asyncio.ensure_future(queue.get())
        gone = asyncio.ensure_future(self._disconnected.wait())
        try:
            done, _ = await asyncio.wait(
                {get, gone}, timeout=RESPONSE_TIMEOUT_S, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            gone.cancel()
        if get in done:
            return get.result()
        get.cancel()
        raise ScaleError("scale disconnected" if gone in done else "no answer from the scale")

    def _handle(self, char: BleakGATTCharacteristic, data: bytearray) -> None:
        uuid = char.uuid.lower()
        # BlueZ delivers every notification twice on this scale: drop the copy.
        now = asyncio.get_running_loop().time()
        key = (uuid, bytes(data))
        if key == self._last_notify and now - self._last_notify_at < 1:
            return
        self._last_notify, self._last_notify_at = key, now
        _LOGGER.debug("Notify %s: %s", uuid[4:8], bytes(data).hex())
        try:
            if uuid == p.CHR_USER_CONTROL_POINT:
                self._ucp.put_nowait(p.parse_ucp_response(data))
            elif uuid == p.CHR_VENDOR_USER_LIST:
                self._user_list.put_nowait(p.parse_user_list_entry(data))
            elif uuid == p.CHR_VENDOR_TAKE_MEASUREMENT and data:
                self._take.put_nowait(data[0])
            elif uuid == p.CHR_WEIGHT_MEASUREMENT:
                self._flush()
                self._pending = p.parse_weight(data)
                self._last_packet = asyncio.get_running_loop().time()
            elif uuid == p.CHR_BODY_COMPOSITION:
                comp = p.parse_body_composition(data)
                if self._pending is not None:
                    self._pending.merge(comp)
                    comp = self._pending
                    self._pending = None
                self._last_packet = asyncio.get_running_loop().time()
                self._emit(comp)
        except p.ProtocolError as err:
            _LOGGER.warning("Unexpected packet on %s: %s", uuid[4:8], err)

    def _flush(self) -> None:
        """Deliver a weight that came without body composition (e.g. weighed with socks)."""
        if self._pending is not None:
            self._emit(self._pending)
            self._pending = None

    def _emit(self, m: p.Measurement) -> None:
        if self._on_measurement is not None and m.weight_kg is not None:
            self._on_measurement(m)


def _drain(queue: asyncio.Queue) -> None:
    while not queue.empty():
        queue.get_nowait()
