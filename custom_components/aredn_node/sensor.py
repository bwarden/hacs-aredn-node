"""Sensor platform for AREDN Node integration."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    SIGNAL_STRENGTH_DECIBELS,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    UnitOfFrequency,
    UnitOfInformation,
)
from homeassistant.helpers.entity import EntityCategory
from homeassistant.util.dt import utcnow

from .entity import ArednNodeEntity

if TYPE_CHECKING:
    from collections.abc import Callable

    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import ArednNodeDataUpdateCoordinator
    from .data import ArednNodeConfigEntry


@dataclass(frozen=True, kw_only=True)
class ArednNodeSensorEntityDescription(SensorEntityDescription):
    """Describes AREDN Node sensor entity."""

    value_fn: Callable[[dict[str, Any]], str | int | None]
    attr_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None


def _get_sysinfo_value(key: str) -> Callable[[dict[str, Any]], str | int | None]:
    """Get a value from the sysinfo dict."""
    return lambda data: data.get("sysinfo", {}).get(key)


def _get_meshrf_value(key: str) -> Callable[[dict[str, Any]], str | int | None]:
    """Get a value from the meshrf dict."""
    return lambda data: data.get("meshrf", {}).get(key)


def _get_antenna_value(key: str) -> Callable[[dict[str, Any]], str | int | None]:
    """Get a value from the antenna dict within meshrf."""
    return lambda data: data.get("meshrf", {}).get("antenna", {}).get(key)


def _get_tunnels_value(key: str) -> Callable[[dict[str, Any]], str | int | None]:
    """Get a value from the tunnels dict."""
    return lambda data: data.get("tunnels", {}).get(key)


ENTITY_DESCRIPTIONS: tuple[ArednNodeSensorEntityDescription, ...] = (
    ArednNodeSensorEntityDescription(
        key="api_version",
        name="API Version",
        icon="mdi:api",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("api_version"),
    ),
    ArednNodeSensorEntityDescription(
        key="gridsquare",
        name="Gridsquare",
        icon="mdi:grid",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("gridsquare"),
    ),
    ArednNodeSensorEntityDescription(
        key="freememory",
        name="Free Memory",
        native_unit_of_measurement=UnitOfInformation.KILOBYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_get_sysinfo_value("freememory"),
    ),
    ArednNodeSensorEntityDescription(
        key="load_1m",
        name="Load (1m)",
        icon="mdi:chart-line",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("sysinfo", {}).get("loads", [None, None, None])[
            0
        ],
    ),
    ArednNodeSensorEntityDescription(
        key="load_5m",
        name="Load (5m)",
        icon="mdi:chart-line",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("sysinfo", {}).get("loads", [None, None, None])[
            1
        ],
    ),
    ArednNodeSensorEntityDescription(
        key="load_15m",
        name="Load (15m)",
        icon="mdi:chart-line",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("sysinfo", {}).get("loads", [None, None, None])[
            2
        ],
    ),
    ArednNodeSensorEntityDescription(
        key="meshrf_status",
        name="Mesh RF Status",
        icon="mdi:wifi",
        value_fn=_get_meshrf_value("status"),
    ),
    ArednNodeSensorEntityDescription(
        key="meshrf_ssid",
        name="Mesh RF SSID",
        icon="mdi:wifi-settings",
        value_fn=_get_meshrf_value("ssid"),
    ),
    ArednNodeSensorEntityDescription(
        key="meshrf_freq",
        name="Mesh RF Frequency",
        native_unit_of_measurement=UnitOfFrequency.MEGAHERTZ,
        device_class=SensorDeviceClass.FREQUENCY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:radio-tower",
        value_fn=_get_meshrf_value("freq"),
    ),
    ArednNodeSensorEntityDescription(
        key="meshrf_chanbw",
        name="Mesh RF Channel Bandwidth",
        native_unit_of_measurement=UnitOfFrequency.MEGAHERTZ,
        device_class=SensorDeviceClass.FREQUENCY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:arrow-expand-horizontal",
        value_fn=_get_meshrf_value("chanbw"),
    ),
    ArednNodeSensorEntityDescription(
        key="antenna_gain",
        name="Antenna Gain",
        icon="mdi:antenna",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        native_unit_of_measurement="dBi",
        value_fn=_get_antenna_value("gain"),
    ),
    ArednNodeSensorEntityDescription(
        key="antenna_beamwidth",
        name="Antenna Beamwidth",
        icon="mdi:angle-acute",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        native_unit_of_measurement="°",
        value_fn=_get_antenna_value("beamwidth"),
    ),
    ArednNodeSensorEntityDescription(
        key="link_info",
        name="Linked Nodes",
        icon="mdi:lan-connect",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: len(data.get("link_info", {})),
        attr_fn=lambda data: {
            "links": [v.get("hostname") for v in data.get("link_info", {}).values()]
        },
    ),
    ArednNodeSensorEntityDescription(
        key="nodes",
        name="Mesh Nodes",
        icon="mdi:lan",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: len(data.get("nodes", [])),
    ),
    ArednNodeSensorEntityDescription(
        key="active_tunnels",
        name="Active Tunnels",
        icon="mdi:tunnel",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_get_tunnels_value("active_tunnel_count"),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ArednNodeConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the sensor platform."""
    coordinator = entry.runtime_data.coordinator

    entities: list[
        ArednNodeSensor | ArednNodeInterfaceSensor | ArednNodeLinkTypeSensor
    ] = [
        ArednNodeSensor(
            coordinator=coordinator,
            entity_description=entity_description,
        )
        for entity_description in ENTITY_DESCRIPTIONS
    ]

    # Dynamically create sensors for each RF link
    rf_peers = set()
    if coordinator.data and "link_info" in coordinator.data:
        for peer_ip, link_data in coordinator.data["link_info"].items():
            if link_data.get("linkType") == "RF":
                rf_peers.add(peer_ip)

    # Also add previously discovered RF peers so sensors don't disappear
    if "rf_peers" in entry.data:
        rf_peers.update(entry.data["rf_peers"])

    hass.config_entries.async_update_entry(
        entry, data={**entry.data, "rf_peers": list(rf_peers)}
    )

    for peer_ip in rf_peers:
        for description in RF_PEER_SENSOR_DESCRIPTIONS:
            entities.append(
                ArednNodeRfPeerSensor(
                    coordinator=coordinator,
                    peer_ip=peer_ip,
                    entity_description=description,
                )
            )

    entities.append(ArednNodeBootTimeSensor(coordinator=coordinator))

    # Dynamically create sensors for each link type
    link_types = set()
    if coordinator.data and "link_info" in coordinator.data:
        for link in coordinator.data["link_info"].values():
            if link_type := link.get("linkType"):
                link_types.add(link_type)

    # Also add previously discovered link types so sensors don't disappear
    if "link_types" in entry.data:
        link_types.update(entry.data["link_types"])

    # This function is not a coroutine and returns a boolean.
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, "link_types": list(link_types)}
    )

    entities.extend(
        [
            ArednNodeLinkTypeSensor(coordinator=coordinator, link_type=link_type)
            for link_type in link_types
        ]
    )

    # Create sensors for each interface, disabled by default
    if interfaces := coordinator.data.get("interfaces"):
        entities.extend(
            ArednNodeInterfaceSensor(
                coordinator=coordinator,
                interface_name=interface["name"],
            )
            for interface in interfaces
            if "ip" in interface
        )
    async_add_entities(entities)


class ArednNodeSensor(ArednNodeEntity, SensorEntity):
    """AREDN Node sensor class."""

    entity_description: ArednNodeSensorEntityDescription

    def __init__(
        self,
        coordinator: ArednNodeDataUpdateCoordinator,
        entity_description: ArednNodeSensorEntityDescription,
    ) -> None:
        """Initialize the sensor class."""
        super().__init__(coordinator)
        self.entity_description = entity_description
        node_name = coordinator.data.get("node")
        self._attr_name = f"{node_name} {entity_description.name}"
        self._attr_unique_id = (
            f"{coordinator.config_entry.entry_id}-{entity_description.key}"
        )

    @property
    def native_value(self) -> str | int | None:
        """Return the native value of the sensor."""
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return the state attributes."""
        if self.entity_description.attr_fn:
            return self.entity_description.attr_fn(self.coordinator.data)
        return None


class ArednNodeInterfaceSensor(ArednNodeEntity, SensorEntity):
    """AREDN Node interface sensor class."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    def __init__(
        self,
        coordinator: ArednNodeDataUpdateCoordinator,
        interface_name: str,
    ) -> None:
        """Initialize the sensor class."""
        super().__init__(coordinator)
        self._interface_name = interface_name
        node_name = coordinator.data.get("node")
        self._attr_name = f"{node_name} Interface {interface_name}"
        self._attr_unique_id = (
            f"{coordinator.config_entry.entry_id}-iface-{interface_name}"
        )

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        for interface in self.coordinator.data.get("interfaces", []):
            if interface.get("name") == self._interface_name:
                return interface.get("ip")
        return None


class ArednNodeLinkTypeSensor(ArednNodeEntity, SensorEntity):
    """AREDN Node sensor for a specific link type."""

    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:lan-connect"

    def __init__(
        self,
        coordinator: ArednNodeDataUpdateCoordinator,
        link_type: str,
    ) -> None:
        """Initialize the sensor class."""
        super().__init__(coordinator)
        self._link_type = link_type
        node_name = coordinator.data.get("node")
        self._attr_name = f"{node_name} Linked Nodes ({link_type.title()})"
        self._attr_unique_id = (
            f"{coordinator.config_entry.entry_id}-linktype-{link_type.lower()}"
        )

    @property
    def native_value(self) -> int:
        """Return the number of links of this type."""
        count = 0
        if self.coordinator.data and "link_info" in self.coordinator.data:
            for link in self.coordinator.data["link_info"].values():
                if link.get("linkType") == self._link_type:
                    count += 1
        return count

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return the state attributes."""
        if not (link_info := self.coordinator.data.get("link_info")):
            return {"links": []}
        return {
            "links": [
                v.get("hostname")
                for v in link_info.values()
                if v.get("linkType") == self._link_type
            ]
        }


class ArednNodeBootTimeSensor(ArednNodeEntity, SensorEntity):
    """AREDN Node boot time sensor with update threshold."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _last_boot_time: datetime | None = None

    def __init__(self, coordinator: ArednNodeDataUpdateCoordinator) -> None:
        """Initialize the boot time sensor."""
        super().__init__(coordinator)
        node_name = coordinator.data.get("node")
        self._attr_name = f"{node_name} Boot Time"
        self._attr_unique_id = f"{coordinator.config_entry.entry_id}-boot_time"

    def _calculate_boot_time(self) -> datetime | None:
        """Calculate the boot time from the uptime string."""
        uptime_str = self.coordinator.data.get("sysinfo", {}).get("uptime")
        if not uptime_str:
            return None

        now = utcnow()
        days_match = re.search(r"(\d+)\s+days?", uptime_str)
        time_match = re.search(r"(\d+):(\d+)", uptime_str)

        return now - timedelta(
            days=int(days_match.group(1)) if days_match else 0,
            hours=int(time_match.group(1)) if time_match else 0,
            minutes=int(time_match.group(2)) if time_match else 0,
        )

    @property
    def native_value(self) -> datetime | None:
        """Return the state of the sensor."""
        new_boot_time = self._calculate_boot_time()

        # On first run or if the value is somehow not a datetime, set the value.
        if self._last_boot_time is None or new_boot_time is None:
            self._last_boot_time = new_boot_time
            return self._last_boot_time

        # Only update if the new value is more than 2 minutes different.
        time_difference = abs(self._last_boot_time - new_boot_time)
        if time_difference > timedelta(minutes=2):
            self._last_boot_time = new_boot_time

        # Otherwise, keep the existing value.
        return self._last_boot_time


RF_PEER_SENSOR_DESCRIPTIONS: tuple[ArednNodeSensorEntityDescription, ...] = (
    ArednNodeSensorEntityDescription(
        key="signal",
        name="Signal",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda data: data.get("signal"),
    ),
    ArednNodeSensorEntityDescription(
        key="noise",
        name="Noise",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda data: data.get("noise"),
    ),
    ArednNodeSensorEntityDescription(
        key="snr",
        name="SNR",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda data: (
            data["signal"] - data["noise"]
            if "signal" in data and "noise" in data
            else None
        ),
    ),
)


class ArednNodeRfPeerSensor(ArednNodeEntity, SensorEntity):
    """AREDN Node sensor for a specific RF peer link."""

    entity_description: ArednNodeSensorEntityDescription

    def __init__(
        self,
        coordinator: ArednNodeDataUpdateCoordinator,
        peer_ip: str,
        entity_description: ArednNodeSensorEntityDescription,
    ) -> None:
        """Initialize the sensor class."""
        super().__init__(coordinator)
        self.entity_description = entity_description
        self._peer_ip = peer_ip

        # Get the hostname for this peer, falling back to the IP
        peer_info = coordinator.data.get("link_info", {}).get(peer_ip, {})
        peer_name = peer_info.get("hostname", peer_ip)

        node_name = coordinator.data.get("node")
        self._attr_name = f"{node_name} {peer_name} {entity_description.name}"
        self._attr_unique_id = f"{coordinator.config_entry.entry_id}-peer-{peer_ip}-{entity_description.key}"

    @property
    def native_value(self) -> int | None:
        """Return the native value of the sensor."""
        peer_info = self.coordinator.data.get("link_info", {}).get(self._peer_ip)

        if not peer_info or peer_info.get("linkType") != "RF":
            return None

        return self.entity_description.value_fn(peer_info)
