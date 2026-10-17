"""Sensors for the Sanitas SBF73 scale."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfMass,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import Sbf73ConfigEntry, Sbf73Coordinator
from .protocol import Measurement


@dataclass(frozen=True, kw_only=True)
class Sbf73SensorDescription(SensorEntityDescription):
    value_fn: Callable[[Sbf73Coordinator], float | datetime | None]


def _m(attr: str) -> Callable[[Sbf73Coordinator], float | None]:
    def get(coordinator: Sbf73Coordinator) -> float | None:
        m: Measurement | None = coordinator.measurement
        return None if m is None else getattr(m, attr)

    return get


SENSORS: tuple[Sbf73SensorDescription, ...] = (
    Sbf73SensorDescription(
        key="weight",
        translation_key="weight",
        device_class=SensorDeviceClass.WEIGHT,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfMass.KILOGRAMS,
        suggested_display_precision=2,
        value_fn=_m("weight_kg"),
    ),
    Sbf73SensorDescription(
        key="bmi",
        translation_key="bmi",
        icon="mdi:human",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="kg/m²",
        suggested_display_precision=1,
        value_fn=_m("bmi"),
    ),
    Sbf73SensorDescription(
        key="body_fat",
        translation_key="body_fat",
        icon="mdi:scale-bathroom",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        suggested_display_precision=1,
        value_fn=_m("fat_pct"),
    ),
    Sbf73SensorDescription(
        key="body_water",
        translation_key="body_water",
        icon="mdi:water-percent",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        suggested_display_precision=1,
        value_fn=_m("water_pct"),
    ),
    Sbf73SensorDescription(
        key="muscle",
        translation_key="muscle",
        icon="mdi:arm-flex",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        suggested_display_precision=1,
        value_fn=_m("muscle_pct"),
    ),
    Sbf73SensorDescription(
        key="bone_mass",
        translation_key="bone_mass",
        icon="mdi:bone",
        device_class=SensorDeviceClass.WEIGHT,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfMass.KILOGRAMS,
        suggested_display_precision=1,
        value_fn=_m("bone_mass_kg"),
    ),
    Sbf73SensorDescription(
        key="bmr",
        translation_key="bmr",
        icon="mdi:fire",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="kcal",
        suggested_display_precision=0,
        value_fn=_m("bmr_kcal"),
    ),
    Sbf73SensorDescription(
        key="impedance",
        translation_key="impedance",
        icon="mdi:omega",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="Ω",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=_m("impedance_ohm"),
    ),
    Sbf73SensorDescription(
        key="last_measurement",
        translation_key="last_measurement",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda c: c.measured_at,
    ),
    Sbf73SensorDescription(
        key="battery",
        device_class=SensorDeviceClass.BATTERY,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: c.battery,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: Sbf73ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(Sbf73Sensor(coordinator, d) for d in SENSORS)


class Sbf73Sensor(RestoreSensor):
    """A value from the last weighing, restored across restarts."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    entity_description: Sbf73SensorDescription

    def __init__(
        self, coordinator: Sbf73Coordinator, description: Sbf73SensorDescription
    ) -> None:
        self.coordinator = coordinator
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}"
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, coordinator.address)},
            name=coordinator.name,
            manufacturer="Sanitas",
            model="SBF73",
        )

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if (last := await self.async_get_last_sensor_data()) is not None:
            self._attr_native_value = last.native_value
        if (value := self.entity_description.value_fn(self.coordinator)) is not None:
            self._attr_native_value = value
        self.async_on_remove(self.coordinator.async_add_listener(self._update))

    @callback
    def _update(self) -> None:
        value = self.entity_description.value_fn(self.coordinator)
        if value is not None:
            self._attr_native_value = value
            self.async_write_ha_state()
