# SPDX-License-Identifier: MIT
"""X-Forwarded-For is caller-controlled, so a per-IP quota that reads it
unconditionally is not a quota at all -- the caller just picks a new IP per
request.

``bottube_server._get_client_ip()`` and ``scraper_detective._get_client_ip()``
already only trust the header when the immediate peer is one of our proxies.
``gemini_blueprint`` and ``sophia_blueprint`` did not, and in gemini's case the
per-IP counter is the *only* gate in front of the unauthenticated free tier
(``/api/gemini/free/generate-video`` -> a billed Veo 3 job).
"""
import os

import pytest
from flask import Flask

from client_ip import resolve_client_ip

app = Flask(__name__)


def _ctx(remote_addr, xff=None):
    headers = {"X-Forwarded-For": xff} if xff else {}
    return app.test_request_context("/", environ_base={"REMOTE_ADDR": remote_addr}, headers=headers)


def test_forwarded_header_ignored_from_untrusted_peer():
    with _ctx("203.0.113.9", xff="1.2.3.4"):
        assert resolve_client_ip() == "203.0.113.9"


def test_forwarded_header_honoured_from_loopback_proxy():
    with _ctx("127.0.0.1", xff="1.2.3.4, 10.0.0.1"):
        assert resolve_client_ip() == "1.2.3.4"


def test_falls_back_to_remote_addr_without_header():
    with _ctx("198.51.100.7"):
        assert resolve_client_ip() == "198.51.100.7"


def test_trusted_proxy_list_is_configurable(monkeypatch):
    monkeypatch.setenv("BOTTUBE_TRUSTED_PROXIES", "10.9.9.9")
    with _ctx("10.9.9.9", xff="1.2.3.4"):
        assert resolve_client_ip() == "1.2.3.4"
    with _ctx("127.0.0.1", xff="1.2.3.4"):
        assert resolve_client_ip() == "127.0.0.1"


def test_gemini_free_tier_quota_cannot_be_reset_by_spoofing(monkeypatch, tmp_path):
    monkeypatch.setenv("BOTTUBE_DB_PATH", str(tmp_path / "bottube.db"))
    gemini_blueprint = pytest.importorskip("gemini_blueprint")
    monkeypatch.setattr(gemini_blueprint, "_ip_rate_buckets", {})

    allowed = 0
    for i in range(10):
        with _ctx("203.0.113.9", xff=f"10.0.0.{i}"):
            ip = gemini_blueprint._get_client_ip()
        if gemini_blueprint._check_ip_rate(ip, "video", gemini_blueprint.FREE_VIDEO_PER_DAY):
            allowed += 1

    # 10 requests from one untrusted host, each claiming a different XFF:
    # the free-video cap must still apply.
    assert allowed == gemini_blueprint.FREE_VIDEO_PER_DAY


def test_gemini_ip_bucket_dict_is_bounded(monkeypatch, tmp_path):
    monkeypatch.setenv("BOTTUBE_DB_PATH", str(tmp_path / "bottube.db"))
    gemini_blueprint = pytest.importorskip("gemini_blueprint")
    stale = {f"free:video:10.0.{i // 256}.{i % 256}": [0.0] for i in range(gemini_blueprint._MAX_IP_BUCKETS + 5)}
    monkeypatch.setattr(gemini_blueprint, "_ip_rate_buckets", stale)

    gemini_blueprint._check_ip_rate("198.51.100.7", "video", 2)

    assert len(gemini_blueprint._ip_rate_buckets) < gemini_blueprint._MAX_IP_BUCKETS


def test_sophia_anon_cooldown_uses_peer_not_header(monkeypatch, tmp_path):
    monkeypatch.setenv("BOTTUBE_DB_PATH", str(tmp_path / "bottube.db"))
    sophia_blueprint = pytest.importorskip("sophia_blueprint")
    with _ctx("203.0.113.9", xff="1.2.3.4"):
        assert sophia_blueprint._client_ip() == "203.0.113.9"
