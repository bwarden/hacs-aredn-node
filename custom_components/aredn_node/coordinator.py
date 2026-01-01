"""DataUpdateCoordinator for integration_blueprint."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from homeassistant.const import CONF_HOST, CONF_PORT, CONF_SSL
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import ArednNodeApiClientError

if TYPE_CHECKING:
    from .data import ArednNodeConfigEntry


def _split_hostish(raw: str) -> tuple[str, int | None]:
    """Return (hostname_or_ip, port) from a stored host field.

    Accepts:
      - host
      - host:port
      - http(s)://host:port
    """
    s = (raw or "").strip()

    # Ensure urlsplit can parse host:port reliably
    if "://" not in s:
        split = urlsplit(f"http://{s}")
    else:
        split = urlsplit(s)

    host = split.hostname or s
    port = split.port
    return host, port


def _is_ip_address(value: str) -> bool:
    """Best-effort check if value is an IPv4/IPv6 address."""
    try:
        socket.getaddrinfo(value, None)
    except OSError:
        return False

    # If it resolves without DNS and looks like an IP literal, it’s likely an IP.
    # (getaddrinfo will also resolve hostnames, so we do a stricter check)
    # Simple heuristic: contains only hex/digits/:/. plus dots.
    allowed = set("0123456789abcdefABCDEF:.")
    return all(c in allowed for c in value)


# https://developers.home-assistant.io/docs/integration_fetching_data#coordinated-single-api-poll-for-data-for-all-entities
class ArednNodeDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    config_entry: ArednNodeConfigEntry
    _cached_ip: str | None = None

    @property
    def cached_ip(self) -> str | None:
        """Return the cached IP address."""
        return self._cached_ip

    async def _async_resolve_host(self, host: str) -> str | None:
        """Resolve hostname to IP address."""
        try:
            return await self.hass.async_add_executor_job(socket.gethostbyname, host)
        except OSError:
            return None

    async def _async_update_data(self) -> Any:
        """Update data via library."""
        client = self.config_entry.runtime_data.client

        # New config data: host may be stored as "host" or "host:port" (or rarely full URL)
        host_raw: str = self.config_entry.data.get(CONF_HOST, "")
        use_ssl: bool = bool(self.config_entry.data.get(CONF_SSL, False))
        cfg_port: int | None = self.config_entry.data.get(CONF_PORT)

        host_only, host_port = _split_hostish(host_raw)
        effective_port = cfg_port if cfg_port is not None else host_port

        # If HTTPS is enabled and the user configured a hostname (not an IP),
        # don't swap to a resolved IP because TLS certs often won’t match the IP.
        should_avoid_ip_swap = use_ssl and not _is_ip_address(host_only)

        target_host_only = host_only

        if not should_avoid_ip_swap:
            resolved_ip = await self._async_resolve_host(host_only)
            if resolved_ip:
                self._cached_ip = resolved_ip
                target_host_only = resolved_ip
            elif self._cached_ip:
                target_host_only = self._cached_ip

        # Build the override host string we pass to the client:
        # - If we have a custom port, include it as host:port
        # - Otherwise just host (or cached/resolved IP)
        target_host = (
            f"{target_host_only}:{effective_port}"
            if effective_port is not None
            else target_host_only
        )

        try:
            # Client will decide scheme/verification based on how it was constructed
            # (ssl/port from entry), but we still pass an override host for discovery/IP caching.
            return await client.async_get_data(host=target_host)
        except ArednNodeApiClientError as exception:
            raise UpdateFailed(exception) from exception
