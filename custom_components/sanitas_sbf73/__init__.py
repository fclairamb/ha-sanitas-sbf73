"""Sanitas SBF73 body composition scale."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
import logging
import time

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, Platform
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.util import dt as dt_util

from . import bluez
from .client import Sbf73Client
from .const import (
    CONF_CONSENT_CODE,
    CONF_LAST_TIMESTAMP,
    CONF_USER_INDEX,
    DOMAIN,
    IDLE_TIMEOUT_S,
    QUIET_S,
    SYNC_COOLDOWN_S,
    WSS_SERVICE_UUID,
)
from .protocol import Measurement

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.BUTTON, Platform.SENSOR]

type Sbf73ConfigEntry = ConfigEntry[Sbf73Coordinator]


async def async_setup_entry(hass: HomeAssistant, entry: Sbf73ConfigEntry) -> bool:
    coordinator = Sbf73Coordinator(hass, entry)
    entry.runtime_data = coordinator
    for m in hass.data.get(DOMAIN, {}).pop(coordinator.address, []):
        coordinator.async_add_measurement(m)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    # Unlike async_register_callback, this fires on every advertisement, even
    # unchanged ones: the scale's advertisement never changes.
    entry.async_on_unload(
        bluetooth.async_register_advertisement_callback(
            hass, coordinator.async_advertisement, coordinator.address
        )
    )
    # BlueZ may already hold the scale (auto-connect): release it so it advertises.
    entry.async_create_background_task(
        hass, _async_release(coordinator.address), "sanitas_sbf73 release"
    )
    return True


async def _async_release(address: str) -> None:
    try:
        await bluez.async_disconnect(address)
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug("BlueZ Disconnect failed: %s", err)


async def async_unload_entry(hass: HomeAssistant, entry: Sbf73ConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


class Sbf73Coordinator:
    """Connects to the scale when it advertises, and keeps the last measurement."""

    def __init__(self, hass: HomeAssistant, entry: Sbf73ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.address: str = entry.data[CONF_ADDRESS]
        self.name = entry.title
        self.measurement: Measurement | None = None
        self.measured_at: datetime | None = None
        self.battery: int | None = None
        self._listeners: list[CALLBACK_TYPE] = []
        self._lock = asyncio.Lock()
        self._last_attempt = 0.0
        self._last_service_data: bytes | None = None
        last = entry.data.get(CONF_LAST_TIMESTAMP)
        self._last_ts = dt_util.parse_datetime(last) if last else None

    @callback
    def async_add_listener(self, update: CALLBACK_TYPE) -> Callable[[], None]:
        self._listeners.append(update)
        return lambda: self._listeners.remove(update)

    @callback
    def async_advertisement(self, info: bluetooth.BluetoothServiceInfoBleak) -> None:
        # Idle, the scale advertises an empty Weight Scale service data and refuses
        # GATT writes. Woken up by a weighing, it advertises every 200 ms and the
        # service data becomes 01: that's when we connect.
        data = info.service_data.get(WSS_SERVICE_UUID)
        if data != self._last_service_data:
            _LOGGER.debug("Weight Scale service data: %s (RSSI %s)", data and data.hex(), info.rssi)
            self._last_service_data = data
        if not data or self._lock.locked():
            return
        if time.monotonic() - self._last_attempt < SYNC_COOLDOWN_S:
            return
        self.entry.async_create_background_task(
            self.hass, self.async_sync(), f"sanitas_sbf73 sync {self.address}"
        )

    async def async_sync(self) -> None:
        """Connect, consent as our user, collect the stored measurements."""
        if self._lock.locked():
            return
        async with self._lock:
            self._last_attempt = time.monotonic()
            ble_device = bluetooth.async_ble_device_from_address(
                self.hass, self.address, connectable=True
            )
            if ble_device is None:
                _LOGGER.debug("Scale %s not in range", self.address)
                return
            client = Sbf73Client(ble_device, self.async_add_measurement)
            try:
                await client.connect()
                if not await client.consent(
                    self.entry.data[CONF_USER_INDEX], self.entry.data[CONF_CONSENT_CODE]
                ):
                    _LOGGER.error(
                        "The scale rejected the PIN of user %s: the user was probably "
                        "deleted or reset on the scale. Remove and re-add the integration",
                        self.entry.data[CONF_USER_INDEX],
                    )
                    return
                self.battery = await client.read_battery()
                await client.wait_quiet(QUIET_S, IDLE_TIMEOUT_S)
            except Exception as err:  # noqa: BLE001
                _LOGGER.info("Sync with %s failed: %s", self.address, err)
            finally:
                await client.disconnect()
            self._notify()

    @callback
    def async_add_measurement(self, m: Measurement) -> None:
        if m.user_index not in (None, self.entry.data[CONF_USER_INDEX]):
            return
        ts = (
            m.timestamp.replace(tzinfo=dt_util.get_default_time_zone())
            if m.timestamp
            else dt_util.now()
        )
        if self._last_ts is not None and ts < self._last_ts:
            return  # older than what we have
        _LOGGER.debug("New measurement at %s: %s", ts, m)
        self.measurement = m
        self.measured_at = ts
        self._last_ts = ts
        self.hass.config_entries.async_update_entry(
            self.entry, data={**self.entry.data, CONF_LAST_TIMESTAMP: ts.isoformat()}
        )
        self._notify()

    @callback
    def _notify(self) -> None:
        for update in list(self._listeners):
            update()
