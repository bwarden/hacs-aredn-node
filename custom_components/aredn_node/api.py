"""AREDn Node API Client."""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlsplit

import aiohttp
import async_timeout
from yarl import URL


class ArednNodeApiClientError(Exception):
    """Exception to indicate a general API error."""


class ArednNodeApiClientCommunicationError(ArednNodeApiClientError):
    """Exception to indicate a communication error."""


def _verify_response_or_raise(response: aiohttp.ClientResponse) -> None:
    """Verify that the response is valid."""
    response.raise_for_status()


def _parse_hostish(raw: str) -> tuple[str, bool | None, int | None]:
    """Parse host input that may contain scheme and/or port.

    Returns (host, ssl, port) where ssl may be None if not inferable.
    """
    s = (raw or "").strip()
    if not s:
        raise ValueError("Empty host")

    # urlsplit needs a scheme to reliably parse host:port
    has_scheme = "://" in s
    split = urlsplit(s if has_scheme else f"http://{s}")

    host = split.hostname or ""
    if not host:
        raise ValueError("Invalid host")

    scheme = (split.scheme or "").lower()
    ssl: bool | None = None
    if scheme == "https":
        ssl = True
    elif scheme == "http":
        ssl = False

    port = split.port
    if port is not None and not (1 <= port <= 65535): # noqa: PLR2004
        raise ValueError("Invalid port")

    return host, ssl, port


class ArednNodeApiClient:
    """AREDn Node API Client."""

    def __init__(
        self,
        host: str,
        session: aiohttp.ClientSession,
        *,
        ssl: bool | None = None,
        port: int | None = None,
        timeout: int = 10,
        verify_ssl: bool = True,
    ) -> None:
        """
        host: hostname/IP, may also be host:port or full URL for backward compat
        ssl: preferred scheme (True=https, False=http). If None, infer from host or default to http.
        port: preferred port. If None, infer from host or default by scheme.
        verify_ssl: for self-signed certs you can set False (future config option if you want).
        """
        self._raw_host = host
        self._session = session
        self._timeout = timeout
        self._verify_ssl = verify_ssl

        parsed_host, parsed_ssl, parsed_port = _parse_hostish(host)

        # Prefer explicit args from config entry, otherwise infer from host string
        self._host = parsed_host
        self._ssl = ssl if ssl is not None else (parsed_ssl if parsed_ssl is not None else False)
        self._port = port if port is not None else parsed_port

    def _base_url(self) -> URL:
        """Build the base URL from stored params."""
        scheme = "https" if self._ssl else "http"
        return URL.build(scheme=scheme, host=self._host, port=self._port)

    def _url_for(self, host_override: str | None = None) -> URL:
        """Build the full sysinfo URL for either the configured host or an override.

        If the override provides no port, we keep the configured port.
        If the override provides no scheme, we keep the configured scheme.
        """
        if not host_override:
            base = self._base_url()
        else:
            h, h_ssl, h_port = _parse_hostish(host_override)

            scheme_ssl = self._ssl if h_ssl is None else h_ssl
            port = self._port if h_port is None else h_port  # <-- important fix

            base = URL.build(
                scheme="https" if scheme_ssl else "http",
                host=h,
                port=port,
            )

        return base.with_path("/a/sysinfo").with_query({"nodes": "1", "link_info": "1"})

    async def async_get_data(self, host: str | None = None) -> Any:
        """Get data from the API.

        Optional host override is supported for discovery/resolved IP caching,
        and may include scheme/port.
        """
        url = self._url_for(host_override=host)
        return await self._api_wrapper(method="get", url=url)

    async def _api_wrapper(
        self,
        method: str,
        url: URL,
        data: dict | None = None,
        headers: dict | None = None,
    ) -> Any:
        """Make an API request and return JSON."""
        try:
            async with async_timeout.timeout(self._timeout):
                # aiohttp `ssl=`:
                # - For https: pass True to verify, False to skip verification (self-signed)
                # - For http: pass None
                ssl_param: bool | None = None
                if url.scheme == "https":
                    ssl_param = True if self._verify_ssl else False

                response = await self._session.request(
                    method=method,
                    url=str(url),
                    headers=headers,
                    json=data,
                    ssl=ssl_param,
                )
                _verify_response_or_raise(response)
                return await response.json()

        except TimeoutError as exception:
            msg = f"Timeout error fetching information - {exception}"
            raise ArednNodeApiClientCommunicationError(msg) from exception
        except (aiohttp.ClientError, socket.gaierror, OSError) as exception:
            msg = f"Error fetching information - {exception}"
            raise ArednNodeApiClientCommunicationError(msg) from exception
        except Exception as exception:  # pylint: disable=broad-except
            msg = f"Something really wrong happened! - {exception}"
            raise ArednNodeApiClientError(msg) from exception
