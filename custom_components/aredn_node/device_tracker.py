"""Device tracker platform for AREDN Node integration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import TrackerEntity

from .entity import ArednNodeEntity

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import ArednNodeDataUpdateCoordinator
    from .data import ArednNodeConfigEntry


async def async_setup_entry(
    hass: HomeAssistant,  # noqa: ARG001
    entry: ArednNodeConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the device tracker platform."""
    async_add_entities(
        [ArednNodeDeviceTracker(coordinator=entry.runtime_data.coordinator)]
    )


class ArednNodeDeviceTracker(ArednNodeEntity, TrackerEntity):
    """AREDN Node device tracker."""

    _attr_icon = "mdi:wifi-marker"

    def __init__(self, coordinator: ArednNodeDataUpdateCoordinator) -> None:
        """Initialize the device tracker."""
        super().__init__(coordinator)
        node_name = coordinator.data.get("node")
        self._attr_name = node_name  # Device tracker name is often just the device name
        self._attr_unique_id = f"{coordinator.config_entry.entry_id}-location"

    @property
    def latitude(self) -> float | None:
        """Return latitude value of the device."""
        return self.coordinator.data.get("lat")

    @property
    def longitude(self) -> float | None:
        """Return longitude value of the device."""
        return self.coordinator.data.get("lon")

    @property
    def source_type(self) -> SourceType:
        """Return the source type, eg gps or router, of the device."""
        return SourceType.GPS
