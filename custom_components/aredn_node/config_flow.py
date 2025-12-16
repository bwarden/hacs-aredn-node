"""Adds config flow for Blueprint."""

from __future__ import annotations

import asyncio
from typing import Any

import netifaces
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
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

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle a reconfiguration flow initialized by the user."""
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        assert entry

        errors: dict[str, str] = {}

        if user_input:
            try:
                await self._test_credentials(
                    host=user_input[CONF_HOST],
                )
            except ArednNodeApiClientCommunicationError:
                errors["base"] = "cannot_connect"
            except ArednNodeApiClientError as e:
                LOGGER.exception(e)
                errors["base"] = "unknown"
            else:
                self.hass.config_entries.async_update_entry(
                    entry, data={**entry.data, **user_input}
                )
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reconfigure_successful")

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_HOST, default=entry.data.get(CONF_HOST)
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_user(
        self,
        user_input: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Handle a flow initialized by the user."""
        _errors = {}
        if user_input:
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

        # Discover potential nodes
        hosts_to_check = {"localnode.local.mesh"}
        try:
            gateways = netifaces.gateways()
            for gateway_info in gateways.get("default", {}).values():
                hosts_to_check.add(gateway_info[0])
        except Exception as e:
            LOGGER.debug("Could not determine gateways with netifaces: %s", e)

        discovered_hosts = set()
        checked_hosts = set()

        # Perform a 2-level discovery
        for i in range(2):
            # Only check hosts we haven't already processed
            hosts_to_probe = hosts_to_check - checked_hosts
            if not hosts_to_probe:
                break

            LOGGER.debug("Discovery pass %d, probing: %s", i + 1, hosts_to_probe)
            checked_hosts.update(hosts_to_probe)

            results = await asyncio.gather(
                *(self._get_data(host) for host in hosts_to_probe),
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, Exception) or not isinstance(result, dict):
                    continue

                # Add the valid host to our discovered list
                discovered_hosts.add(result["host"])

                # Add linked nodes to the list for the next pass
                for link_ip, link_data in result.get("link_info", {}).items():
                    hosts_to_check.add(link_ip)
                    if hostname := link_data.get("hostname"):
                        hosts_to_check.add(hostname)

        schema = {}
        if discovered_hosts_list := sorted(list(discovered_hosts)):
            schema[vol.Required(CONF_HOST)] = selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=discovered_hosts_list,
                    mode=selector.SelectSelectorMode.DROPDOWN,
                    custom_value=True,
                )
            )
        else:
            schema[vol.Required(CONF_HOST)] = selector.TextSelector(
                selector.TextSelectorConfig(
                    type=selector.TextSelectorType.TEXT,
                ),
            )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(schema),
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
        data = await client.async_get_data()
        data["host"] = host  # Add host to data for discovery
        return data
