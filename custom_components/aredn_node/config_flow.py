"""Adds config flow for Blueprint."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any
from urllib.parse import urlsplit

import netifaces
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_SSL
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from slugify import slugify

from .api import (
    ArednNodeApiClient,
    ArednNodeApiClientCommunicationError,
    ArednNodeApiClientError,
)
from .const import DOMAIN, LOGGER


def _parse_host_input(raw: str) -> tuple[str, bool, int | None]:
    """Parse a host input that may include scheme and/or port.

    Accepts:
      - localnode.local.mesh
      - 10.23.45.67
      - 10.23.45.67:8443
      - https://10.23.45.67
      - https://node.example.com:8443
      - http://node.example.com:8080

    Returns: (hostname_or_ip, ssl, port)
    """
    s = (raw or "").strip()

    # urlsplit needs a scheme to reliably parse host:port
    has_scheme = "://" in s
    split = urlsplit(s if has_scheme else f"http://{s}")

    host = split.hostname or ""
    if not host:
        raise ValueError("Invalid host")

    scheme = (split.scheme or "http").lower()
    ssl = scheme == "https"

    port = split.port  # None if not supplied
    if port is not None and not (1 <= port <= 65535): # noqa: PLR2004
        raise ValueError("Invalid port")

    return host, ssl, port


def _format_host_for_storage(host: str, port: int | None) -> str:
    """Store host as host[:port] for backward compatibility with code that only reads CONF_HOST."""
    return host if port is None else f"{host}:{port}"


class ArednNodeFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for AREDN Node."""

    VERSION = 1

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle a reconfiguration flow initialized by the user."""
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        if not entry:
            return self.async_abort(reason="unknown_error")

        errors: dict[str, str] = {}

        if user_input:
            try:
                # Parse any https:// and/or :port that the user entered
                parsed_host, ssl, port = _parse_host_input(user_input[CONF_HOST])
                stored_host = _format_host_for_storage(parsed_host, port)

                await self._test_credentials(
                    host_input=user_input[CONF_HOST],
                )
            except ValueError:
                errors["base"] = "invalid_host"
            except ArednNodeApiClientCommunicationError:
                errors["base"] = "cannot_connect"
            except ArednNodeApiClientError as e:
                LOGGER.exception(e)
                errors["base"] = "unknown"
            else:
                # Keep UI as one field (CONF_HOST), but persist ssl/port too.
                updated = {
                    **entry.data,
                    CONF_HOST: stored_host,
                    CONF_SSL: ssl,
                    CONF_PORT: port,
                }
                self.hass.config_entries.async_update_entry(entry, data=updated)
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

    def _process_discovery_result(
        self,
        result: dict[str, Any],
        discovered_nodes: dict[str, str],
        hosts_to_check: set[str],
    ) -> None:
        """Process a single successful discovery result."""
        if not (node_name := result.get("node")):
            return

        # Add/update the node in our discovered list, prioritizing specific hostnames.
        if node_name not in discovered_nodes or "localnode" in discovered_nodes.get(
            node_name, ""
        ):
            discovered_nodes[node_name] = result["host"]

        # Add the node's own FQDN to the check list for the next pass.
        if (node_fqdn := f"{node_name.lower()}.local.mesh") != result["host"]:
            hosts_to_check.add(node_fqdn)

        # Add linked nodes to the check list for the next pass.
        for link_ip, link_data in result.get("link_info", {}).items():
            if hostname := link_data.get("hostname"):
                if "." not in hostname:
                    hostname += ".local.mesh"
                hosts_to_check.add(hostname)
            else:
                hosts_to_check.add(link_ip)

    async def _async_discover_nodes(self) -> dict[str, str]:
        """Discover AREDN nodes on the network."""
        hosts_to_check = {"localnode.local.mesh"}
        try:
            gateways = netifaces.gateways()
            for gateway_info in gateways.get("default", {}).values():
                hosts_to_check.add(gateway_info[0])
        except OSError as e:
            LOGGER.debug("Could not determine gateways with netifaces: %s", e)

        discovered_nodes: dict[str, str] = {}  # {node_name: host}
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
                *(self._get_data(host_input=host) for host in hosts_to_probe),
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, Exception) or not isinstance(result, dict):
                    continue
                self._process_discovery_result(result, discovered_nodes, hosts_to_check)
        return discovered_nodes

    async def async_step_user(
        self,
        user_input: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Handle a flow initialized by the user."""
        _errors: dict[str, str] = {}

        if user_input:
            try:
                parsed_host, ssl, port = _parse_host_input(user_input[CONF_HOST])
                stored_host = _format_host_for_storage(parsed_host, port)

                await self._test_credentials(
                    host_input=user_input[CONF_HOST],
                )
            except ValueError:
                _errors["base"] = "invalid_host"
            except ArednNodeApiClientCommunicationError as exception:
                LOGGER.error(exception)
                _errors["base"] = "cannot_connect"
            except ArednNodeApiClientError as exception:
                LOGGER.exception(exception)
                _errors["base"] = "unknown"
            else:
                api_data = await self._get_data(host_input=user_input[CONF_HOST])

                # Keep same unique_id strategy (node name). If the host changes, we update entry.
                await self.async_set_unique_id(slugify(api_data.get("node")))
                self._abort_if_unique_id_configured(
                    updates={
                        CONF_HOST: stored_host,
                        CONF_SSL: ssl,
                        CONF_PORT: port,
                    }
                )

                return self.async_create_entry(
                    title=api_data.get("node"),
                    data={
                        CONF_HOST: stored_host,
                        CONF_SSL: ssl,
                        CONF_PORT: port,
                    },
                )

        # Discover potential nodes
        discovered_nodes = await self._async_discover_nodes()

        schema: dict[Any, Any] = {}
        if discovered_hosts_list := sorted(discovered_nodes.values()):
            schema[vol.Required(CONF_HOST)] = selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=discovered_hosts_list,
                    mode=selector.SelectSelectorMode.DROPDOWN,
                    custom_value=True,  # user can type https://host:port here too
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

    async def _test_credentials(self, host_input: str) -> dict[str, Any]:
        """Validate connectivity to the node."""
        return await self._get_data(host_input)

    async def _get_data(self, host_input: str) -> dict[str, Any]:
        """Get data from the API.

        Supports host strings that may include:
          - scheme (http/https)
          - port
        """
        host, ssl, port = _parse_host_input(host_input)

        # Build kwargs in a backward/forward compatible way:
        # - If client supports port/ssl/base_url params, pass them.
        # - Otherwise, keep host as either "host" or "host:port".
        sig = inspect.signature(ArednNodeApiClient)
        params = sig.parameters

        host_arg: str
        kwargs: dict[str, Any] = {}

        if "port" in params:
            host_arg = host
            kwargs["port"] = port
        else:
            host_arg = _format_host_for_storage(host, port)

        # Prefer explicit SSL flag if supported
        if "ssl" in params:
            kwargs["ssl"] = ssl
        elif "use_ssl" in params:
            kwargs["use_ssl"] = ssl
        elif "https" in params:
            kwargs["https"] = ssl
        elif "base_url" in params:
            # If the client wants a base URL, provide one.
            scheme = "https" if ssl else "http"
            netloc = _format_host_for_storage(host, port)
            kwargs["base_url"] = f"{scheme}://{netloc}"
        else:
            # Last resort: if user requested https but the client only accepts "host",
            # try passing a fully-qualified URL and hope the client treats it as a base URL.
            if ssl:
                scheme = "https"
                netloc = _format_host_for_storage(host, port)
                host_arg = f"{scheme}://{netloc}"

        client = ArednNodeApiClient(
            host=host_arg,
            session=async_create_clientsession(self.hass),
            **kwargs,
        )

        data = await client.async_get_data()

        # Add host to data for discovery/debug; keep original input as the "host" we probed
        data["host"] = host_input
        return data
