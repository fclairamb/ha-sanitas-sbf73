"""Config flow: pair with the scale, then pick or create a user on it."""

from __future__ import annotations

import asyncio
from datetime import date
import logging
import random
from typing import Any

import voluptuous as vol

from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_ble_device_from_address,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import callback
from homeassistant.helpers import selector

from . import protocol as p
from .bluez import PasskeyAgent
from .client import ScaleError, Sbf73Client
from .const import CONF_CONSENT_CODE, CONF_USER_INDEX, DOMAIN

_LOGGER = logging.getLogger(__name__)

NEW_USER = "new"
MEASURE_TIMEOUT_S = 120

NEW_USER_SCHEMA = vol.Schema(
    {
        vol.Required("initials"): selector.TextSelector(),
        vol.Required("birth_date"): selector.DateSelector(),
        vol.Required("height", default=175): selector.NumberSelector(
            selector.NumberSelectorConfig(min=100, max=220, unit_of_measurement="cm")
        ),
        vol.Required("gender"): selector.SelectSelector(
            selector.SelectSelectorConfig(options=["male", "female"], translation_key="gender")
        ),
        vol.Required("activity_level", default=3): selector.NumberSelector(
            selector.NumberSelectorConfig(min=1, max=5, mode=selector.NumberSelectorMode.SLIDER)
        ),
    }
)


class Sbf73ConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._address: str | None = None
        self._name = "SBF73"
        self._discovered: dict[str, str] = {}
        self._client: Sbf73Client | None = None
        self._agent: PasskeyAgent | None = None
        self._connect_task: asyncio.Task[list[p.ScaleUser]] | None = None
        self._wait_task: asyncio.Task[None] | None = None
        self._measure_task: asyncio.Task[str | None] | None = None
        self._error = ""
        self._users: list[p.ScaleUser] = []
        self._user_index: int | None = None
        self._consent_code: int | None = None
        self._measured = asyncio.Event()
        self._measurements: list[p.Measurement] = []

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._address = discovery_info.address
        self._name = discovery_info.name
        self.context["title_placeholders"] = {"name": self._name}
        return await self.async_step_wake()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            self._address = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(self._address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            return await self.async_step_wake()
        configured = self._async_current_ids(include_ignore=False)
        for info in async_discovered_service_info(self.hass, connectable=True):
            if info.name == "SBF73" and info.address not in configured:
                self._discovered[info.address] = f"{info.name} ({info.address})"
        if not self._discovered:
            return self.async_abort(reason="no_devices_found")
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({vol.Required(CONF_ADDRESS): vol.In(self._discovered)}),
        )

    async def async_step_wake(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is None:
            return self.async_show_form(
                step_id="wake", description_placeholders={"name": self._name}
            )
        return await self.async_step_connect()

    async def async_step_connect(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Connect and pair; a passkey request from BlueZ interrupts the progress."""
        if self._connect_task is None:
            self._agent = PasskeyAgent()
            self._connect_task = self.hass.async_create_task(self._async_connect())
        if self._wait_task is None:
            self._wait_task = self.hass.async_create_task(self._async_wait_connect())
        if not self._wait_task.done():
            return self.async_show_progress(
                step_id="connect", progress_action="connect", progress_task=self._wait_task
            )
        self._wait_task = None
        if not self._connect_task.done():
            return self.async_show_progress_done(next_step_id="passkey")
        task, self._connect_task = self._connect_task, None
        try:
            self._users = task.result()
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Could not connect to the scale: %r", err)
            self._error = str(err) or type(err).__name__
            await self._async_disconnect()
            return self.async_show_progress_done(next_step_id="connect_failed")
        return self.async_show_progress_done(next_step_id="select_user")

    async def async_step_passkey(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            passkey = user_input["passkey"].strip()
            if passkey.isdigit() and len(passkey) <= 6:
                assert self._agent is not None
                self._agent.provide_passkey(int(passkey))
                return await self.async_step_connect()
            errors["passkey"] = "invalid_passkey"
        return self.async_show_form(
            step_id="passkey",
            data_schema=vol.Schema({vol.Required("passkey"): selector.TextSelector()}),
            errors=errors,
        )

    async def async_step_connect_failed(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return await self.async_step_connect()
        return self.async_show_form(
            step_id="connect_failed", description_placeholders={"error": self._error}
        )

    async def async_step_select_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            if user_input["user"] == NEW_USER:
                return await self.async_step_new_user()
            self._user_index = int(user_input["user"])
            try:
                await self._async_ensure_connected()
                await self._client.show_pin(self._user_index)
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("Could not show the PIN: %r", err)
                errors["base"] = "cannot_connect"
            else:
                return await self.async_step_pin()
        options = [
            selector.SelectOptionDict(
                value=str(u.index),
                label=f"P{u.index} {u.initials or '?'} ({u.birth_date}, {u.height_cm} cm)",
            )
            for u in self._users
        ]
        if len(self._users) < p.MAX_USERS:
            new_label = "+ Nouvel utilisateur" if self.hass.config.language == "fr" else "+ New user"
            options.append(selector.SelectOptionDict(value=NEW_USER, label=new_label))
        return self.async_show_form(
            step_id="select_user",
            data_schema=vol.Schema(
                {
                    vol.Required("user"): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=options, mode=selector.SelectSelectorMode.LIST
                        )
                    )
                }
            ),
            errors=errors,
        )

    async def async_step_pin(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            pin = user_input["pin"].strip()
            if not (pin.isdigit() and len(pin) == 4):
                errors["pin"] = "wrong_pin"
            else:
                try:
                    await self._async_ensure_connected()
                    ok = await self._client.consent(self._user_index, int(pin))
                except Exception as err:  # noqa: BLE001
                    _LOGGER.warning("Consent failed: %r", err)
                    errors["base"] = "cannot_connect"
                else:
                    if ok:
                        self._consent_code = int(pin)
                        return await self.async_step_finish()
                    errors["pin"] = "wrong_pin"
        return self.async_show_form(
            step_id="pin",
            data_schema=vol.Schema({vol.Required("pin"): selector.TextSelector()}),
            errors=errors,
        )

    async def async_step_new_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            code = random.randint(1000, 9999)
            try:
                await self._async_ensure_connected()
                index = await self._client.register(code)
                await asyncio.sleep(2)  # the app waits 2 s before consenting
                if not await self._client.consent(index, code, attempts=5):
                    raise ScaleError("the scale refused the new user's PIN")
                await self._client.write_user_data(
                    birth_date=date.fromisoformat(user_input["birth_date"]),
                    gender=p.GENDER_FEMALE if user_input["gender"] == "female" else p.GENDER_MALE,
                    height_cm=int(user_input["height"]),
                    activity_level=int(user_input["activity_level"]),
                    initials=user_input["initials"],
                    db_change_increment=1,
                )
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("User registration failed: %r", err)
                self._error = str(err) or type(err).__name__
                errors["base"] = "register_failed"
            else:
                self._user_index, self._consent_code = index, code
                return await self.async_step_measure()
        return self.async_show_form(
            step_id="new_user",
            data_schema=self.add_suggested_values_to_schema(NEW_USER_SCHEMA, user_input),
            errors=errors,
            description_placeholders={"error": self._error},
        )

    async def async_step_measure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Reference weighing, so the scale learns to recognize the new user."""
        if self._measure_task is None:
            self._measure_task = self.hass.async_create_task(self._async_measure())
        if not self._measure_task.done():
            return self.async_show_progress(
                step_id="measure", progress_action="measure", progress_task=self._measure_task
            )
        if error := self._measure_task.result():
            _LOGGER.warning("Reference measurement not done: %s", error)
        return self.async_show_progress_done(next_step_id="finish")

    async def async_step_finish(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        await self._async_disconnect()
        self.hass.data.setdefault(DOMAIN, {})[self._address] = self._measurements
        return self.async_create_entry(
            title=f"{self._name} P{self._user_index}",
            data={
                CONF_ADDRESS: self._address,
                CONF_USER_INDEX: self._user_index,
                CONF_CONSENT_CODE: self._consent_code,
            },
        )

    async def _async_connect(self) -> list[p.ScaleUser]:
        ble_device = async_ble_device_from_address(self.hass, self._address, connectable=True)
        if ble_device is None:
            raise ScaleError("scale not in range, wake it up and retry")
        self._client = Sbf73Client(ble_device, self._on_measurement)
        assert self._agent is not None
        try:
            await self._agent.register()
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Could not register the pairing agent: %r", err)
        try:
            await self._client.connect(pair=True)
        finally:
            await self._agent.unregister()
        return await self._client.list_users()

    async def _async_wait_connect(self) -> None:
        """Return when the connection is done or BlueZ asks for a passkey."""
        assert self._agent is not None and self._connect_task is not None
        passkey = asyncio.ensure_future(self._agent.passkey_requested.wait())
        try:
            await asyncio.wait({self._connect_task, passkey}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            passkey.cancel()

    async def _async_measure(self) -> str | None:
        try:
            await self._async_ensure_connected()
            if not await self._client.consent(self._user_index, self._consent_code):
                return "consent refused"
            await self._client.take_measurement()
            await asyncio.wait_for(self._measured.wait(), MEASURE_TIMEOUT_S)
        except Exception as err:  # noqa: BLE001
            return repr(err)
        return None

    async def _async_ensure_connected(self) -> None:
        """The scale may drop the link while the user fills a form: reconnect."""
        assert self._client is not None
        if not self._client.is_connected:
            await self._client.connect()

    @callback
    def _on_measurement(self, m: p.Measurement) -> None:
        _LOGGER.debug("Measurement during setup: %s", m)
        # The scale sends pending measurements right after consent: hand them
        # over to the config entry instead of losing them.
        self._measurements.append(m)
        self._measured.set()

    async def _async_disconnect(self) -> None:
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Disconnect failed: %r", err)
            self._client = None

    @callback
    def async_remove(self) -> None:
        for task in (self._connect_task, self._wait_task, self._measure_task):
            if task is not None:
                task.cancel()
        self.hass.async_create_task(self._async_disconnect())
        if self._agent is not None:
            self.hass.async_create_task(self._agent.unregister())
