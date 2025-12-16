"""Binary sensor platform for AREDN Node integration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.helpers.entity import EntityCategory

from .entity import ArednNodeEntity

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import ArednNodeDataUpdateCoordinator
    from .data import ArednNodeConfigEntry


ENTITY_DESCRIPTION = BinarySensorEntityDescription(
    key="reachable",
    name="Reachable",
    device_class=BinarySensorDeviceClass.CONNECTIVITY,
    entity_category=EntityCategory.DIAGNOSTIC,
)


async def async_setup_entry(
    hass: HomeAssistant,  # noqa: ARG001
    entry: ArednNodeConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary sensor platform."""
    async_add_entities(
        [ArednNodeReachableSensor(coordinator=entry.runtime_data.coordinator)]
    )


class ArednNodeReachableSensor(ArednNodeEntity, BinarySensorEntity):
    """AREDN Node reachability sensor."""

    def __init__(self, coordinator: ArednNodeDataUpdateCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = ENTITY_DESCRIPTION
        self._attr_unique_id = (
            f"{coordinator.config_entry.entry_id}-{ENTITY_DESCRIPTION.key}"
        )

    @property
    def is_on(self) -> bool:
        """Return true if the host is reachable."""
        return self.coordinator.last_update_success
