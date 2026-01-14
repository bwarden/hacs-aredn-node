"""BlueprintEntity class."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER
from .coordinator import ArednNodeDataUpdateCoordinator


class ArednNodeEntity(CoordinatorEntity[ArednNodeDataUpdateCoordinator]):
    """AREDN Node entity class."""

    def __init__(self, coordinator: ArednNodeDataUpdateCoordinator) -> None:
        """Initialize."""
        super().__init__(coordinator)

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information about this entity."""
        node_details = self.coordinator.data.get("node_details", {})
        firmware_version = node_details.get("firmware_version")
        model = node_details.get("model")
        node_name = self.coordinator.data.get("node")

        return DeviceInfo(
            identifiers={(DOMAIN, self.coordinator.config_entry.entry_id)},
            name=node_name,
            manufacturer=MANUFACTURER,
            model=model,
            sw_version=firmware_version,
            configuration_url=f"http://{self.coordinator.config_entry.data['host']}",
        )
