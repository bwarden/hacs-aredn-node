# Home Assistant AREDN Node Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Default-orange.svg)](https://github.com/hacs/integration)

This is a custom integration for [Home Assistant](https://www.home-assistant.io/) to monitor nodes on an [Amateur Radio Emergency Data Network (AREDN)](https://www.arednmesh.org/).

It connects to AREDN nodes and creates sensors representing various information about them, including peer (linked) nodes, total number of nodes on the mesh, RF details, and other system information.

!AREDN Node Device View

## Features

- **Auto-Discovery**: Automatically probes your network gateways and `localnode.local.mesh` to find nearby nodes. It will even spider out to discover nodes linked from the initial nodes it finds.
- **Rich Sensor Data**: Creates a wide variety of sensors for detailed monitoring and automation.
- **Device-Centric**: Groups all sensors under a single Home Assistant device for each AREDN node.
- **Dynamic Link Sensors**: Automatically creates sensors for each type of link (e.g., RF, WIREGUARD, DTD) your node reports.
- **Reconfiguration**: Allows you to easily change the hostname or IP address of a configured node without removing and re-adding it.

## Requirements

This integration uses the `ucode` API endpoint for retrieving data. At this time, it will only work on firmware versions that support this endpoint (e.g., recent `babel-only` firmware).

- **ucode (supported):** `http://<node>/a/sysinfo`
- **cgi-bin (not supported):** `http://<node>/cgi-bin/sysinfo.json`

## Installation

The recommended way to install this integration is through the Home Assistant Community Store (HACS).

1. [![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=bwarden&repository=hacs-aredn-node&category=Integrations)
2. Download the integration.
3. Restart Home Assistant.

## Configuration

1.  Navigate to **Settings > Devices & Services**.
2.  Click **Add Integration** and search for "AREDN Node".
3.  The configuration dialog will open. The integration will attempt to auto-discover nodes on your network and present them in a dropdown list.
4.  Select a discovered node or manually enter the hostname or IP address of your AREDN node.
5.  Click **Submit**. The integration will be configured, and a new device with all its sensors will be added.

## Sensors

This integration creates the following entities for each configured node. The node's name will be prepended to all entity names (e.g., `MYCALL-MYNODE Reachable`).

### Binary Sensor

| Entity | Description |
| :--- | :--- |
| **Reachable** | A connectivity sensor that is `On` if the node is reachable by Home Assistant. |

### Device Tracker

| Entity | Description |
| :--- | :--- |
| **`[Node Name]`** | A device tracker representing the physical GPS location of the node, _as reported by the node itself_. |

### Sensors

| Entity | Description | Category |
| :--- | :--- | :--- |
| **Linked Nodes** | The total count of directly connected peer nodes. | |
| **Linked Nodes (RF)** | The count of directly connected RF peer nodes. (Dynamically created) | |
| **Linked Nodes (WIREGUARD)** | The count of directly connected WireGuard peer nodes. (Dynamically created) | |
| **Linked Nodes (DTD)** | The count of directly connected DtD peer nodes. (Dynamically created) | |
| **Mesh Nodes** | The total number of nodes detected on the entire mesh. | |
| **Mesh RF Status** | The status of the Mesh RF interface (e.g., `on`). | |
| **Mesh RF SSID** | The SSID of the mesh radio. | |
| **Mesh RF Frequency** | The frequency of the mesh radio in MHz. | |
| **Mesh RF Channel Bandwidth** | The channel bandwidth of the mesh radio in MHz. | |
| **Antenna Beamwidth** | The beamwidth of the RF antenna in degrees. | Diagnostic (Disabled by default) |
| **Antenna Gain** | The gain of the RF antenna in dBi. | Diagnostic (Disabled by default) |
| **API Version** | The version of the node's `sysinfo` API. | Diagnostic |
| **Active Tunnels** | The number of active tunnels on the node. | Diagnostic |
| **Boot Time** | A timestamp of when the node was last booted. | Diagnostic |
| **Free Memory** | The amount of free memory in Kilobytes. | Diagnostic |
| **Gridsquare** | The Maidenhead grid square of the node. | Diagnostic |
| **Load (1m / 5m / 15m)** | The 1, 5, and 15-minute system load averages. | Diagnostic |
| **Interface `[name]`** | The IP address of a given network interface (e.g., `br-lan`). | Diagnostic (Disabled by default) |
| **`[Peer]` Signal** | The signal strength of a specific RF peer link. | Diagnostic (Disabled by default) |
| **`[Peer]` Noise** | The noise level of a specific RF peer link. | Diagnostic (Disabled by default) |
| **`[Peer]` SNR** | The calculated Signal-to-Noise Ratio of a specific RF peer link. | Diagnostic (Disabled by default) |
