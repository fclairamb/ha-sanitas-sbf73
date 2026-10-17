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

from .client import Sbf73Client
from .const import (
    CONF_CONSENT_CODE,
    CONF_LAST_TIMESTAMP,
    CONF_USER_INDEX,
    DOMAIN,
    IDLE_TIMEOUT_S,
    MANUFACTURER_ID,
    QUIET_S,
    SYNC_COOLDOWN_S,
    SYNC_INTERVAL_S,
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
    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            coordinator.async_advertisement,
            bluetooth.BluetoothCallbackMatcher(address=coordinator.address, connectable=True),
            bluetooth.BluetoothScanningMode.ACTIVE,
        )
    )
    return True


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
        self._last_adv: bytes | None = None
        last = entry.data.get(CONF_LAST_TIMESTAMP)
        self._last_ts = dt_util.parse_datetime(last) if last else None

    @callback
    def async_add_listener(self, update: CALLBACK_TYPE) -> Callable[[], None]:
        self._listeners.append(update)
        return lambda: self._listeners.remove(update)

    @callback
    def async_advertisement(
        self, info: bluetooth.BluetoothServiceInfoBleak, change: bluetooth.BluetoothChange
    ) -> None:
        # The scale advertises all the time, even idle. Connect when its
        # advertisement changes (woken up, new measurement), otherwise rarely.
        adv = info.manufacturer_data.get(MANUFACTURER_ID, b"") + "".join(
            sorted(info.service_uuids)
        ).encode()
        changed = self._last_adv is not None and adv != self._last_adv
        if adv != self._last_adv:
            _LOGGER.debug(
                "Advertisement: manufacturer data %s, services %s, RSSI %s",
                info.manufacturer_data.get(MANUFACTURER_ID, b"").hex(),
                info.service_uuids,
                info.rssi,
            )
            self._last_adv = adv
        # Count from the last attempt, not the last success: a scale that keeps
        # refusing must not be hammered (it runs on batteries).
        since = time.monotonic() - self._last_attempt
        if self._lock.locked() or since < SYNC_COOLDOWN_S:
            return
        if not changed and self._last_attempt and since < SYNC_INTERVAL_S:
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
        if self._last_ts is not None and ts <= self._last_ts:
            return  # already seen: the scale may resend its history
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
