"""Manual sync button for the Sanitas SBF73 scale."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import Sbf73ConfigEntry


async def async_setup_entry(
    hass: HomeAssistant,
    entry: Sbf73ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([Sbf73SyncButton(entry)])


class Sbf73SyncButton(ButtonEntity):
    """Fetch the measurements stored on the scale now."""

    _attr_has_entity_name = True
    _attr_translation_key = "sync"

    def __init__(self, entry: Sbf73ConfigEntry) -> None:
        self.coordinator = entry.runtime_data
        self._attr_unique_id = f"{self.coordinator.uid}_sync"
        self._attr_device_info = self.coordinator.device_info

    async def async_press(self) -> None:
        await self.coordinator.async_sync()
