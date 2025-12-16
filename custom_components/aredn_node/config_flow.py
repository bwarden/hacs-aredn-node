"""Adds config flow for Blueprint."""

from __future__ import annotations

import asyncio
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.typing import DiscoveryInfoType
from slugify import slugify

from .api import (
    ArednNodeApiClient,
    ArednNodeApiClientCommunicationError,
    ArednNodeApiClientError,
)
from .const import DOMAIN, LOGGER


class ArednNodeFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for AREDN Node."""

    VERSION = 1

    async def async_step_dhcp(
        self, discovery_info: DiscoveryInfoType
    ) -> config_entries.ConfigFlowResult:
        """Handle discovery via DHCP."""
        # We can get multiple DHCP discoveries for the same node, so we'll use the IP
        # as the unique ID to avoid creating multiple entries.
        await self.async_set_unique_id(discovery_info.ip)
        self._abort_if_unique_id_configured(updates={CONF_HOST: discovery_info.ip})

        try:
            api_data = await self._get_data(discovery_info.ip)
        except (ArednNodeApiClientCommunicationError, ArednNodeApiClientError):
            return self.async_abort(reason="cannot_connect")

        # The DHCP discovery may not have the final node name, so we'll update the
        # unique ID to use the host from the API data if it's different.
        if discovery_info.ip != api_data.get("node"):
            await self.async_set_unique_id(
                slugify(api_data.get("node")), raise_on_progress=False
            )
            self._abort_if_unique_id_configured(updates={CONF_HOST: discovery_info.ip})

        self.context["title_placeholders"] = {
            "name": api_data.get("node", discovery_info.ip)
        }
        return self.async_create_entry(
            title=api_data.get("node", discovery_info.ip),
            data={
                CONF_HOST: discovery_info.ip,
            },
        )

    async def async_step_user(
        self,
        user_input: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Handle a flow initialized by the user."""
        _errors = {}
        if user_input is not None:
            try:
                await self._test_credentials(
                    host=user_input[CONF_HOST],
                )
            except ArednNodeApiClientCommunicationError as exception:
                LOGGER.error(exception)
                _errors["base"] = "cannot_connect"
            except ArednNodeApiClientError as exception:
                LOGGER.exception(exception)
                _errors["base"] = "unknown"
            else:
                api_data = await self._get_data(user_input[CONF_HOST])
                await self.async_set_unique_id(slugify(api_data.get("node")))
                self._abort_if_unique_id_configured(
                    updates={CONF_HOST: user_input[CONF_HOST]}
                )
                return self.async_create_entry(
                    title=api_data.get("node"),
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_HOST,
                        default=(user_input or {}).get(CONF_HOST, vol.UNDEFINED),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.TEXT,
                        ),
                    ),
                },
            ),
            errors=_errors,
        )

    async def _test_credentials(self, host: str) -> dict[str, Any]:
        """Validate credentials."""
        return await self._get_data(host)

    async def _get_data(self, host: str) -> dict[str, Any]:
        """Get data from the API."""
        client = ArednNodeApiClient(
            host=host,
            session=async_create_clientsession(self.hass),
        )
        return await client.async_get_data()
