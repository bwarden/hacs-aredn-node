"""DataUpdateCoordinator for integration_blueprint."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, Any

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import ArednNodeApiClientError

if TYPE_CHECKING:
    from .data import ArednNodeConfigEntry


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
        host = self.config_entry.data["host"]

        resolved_ip = await self._async_resolve_host(host)
        target_host = host

        if resolved_ip:
            self._cached_ip = resolved_ip
            target_host = resolved_ip
        elif self._cached_ip:
            target_host = self._cached_ip

        try:
            return await client.async_get_data(host=target_host)
        except ArednNodeApiClientError as exception:
            raise UpdateFailed(exception) from exception
