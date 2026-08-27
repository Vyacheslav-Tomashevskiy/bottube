# SPDX-License-Identifier: MIT
"""Single source of truth for resolving the caller's IP behind a reverse proxy.

``X-Forwarded-For`` is client-controlled: any caller can set it to an arbitrary
value. It may only be trusted when the immediate peer (``request.remote_addr``)
is one of our own proxies -- otherwise every per-IP quota, cooldown or ban in
the app becomes a no-op, because the caller simply picks a new IP per request.

``bottube_server._get_client_ip()`` and ``scraper_detective._get_client_ip()``
already do the trusted-peer check; blueprints used to reimplement the naive
version. Import this helper instead of writing a third copy.
"""
import os

from flask import request

_DEFAULT_TRUSTED_PROXIES = "127.0.0.1,::1"


def trusted_proxies():
    """Peers whose ``X-Forwarded-For`` we accept.

    Defaults to loopback (nginx runs on the same host). Override with
    ``BOTTUBE_TRUSTED_PROXIES`` (comma-separated) when the proxy is remote.
    """
    raw = os.environ.get("BOTTUBE_TRUSTED_PROXIES", _DEFAULT_TRUSTED_PROXIES)
    return {p.strip() for p in raw.split(",") if p.strip()}


def resolve_client_ip() -> str:
    """Return the caller's IP, honouring X-Forwarded-For only from a trusted peer."""
    if request.remote_addr in trusted_proxies():
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"
