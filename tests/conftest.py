# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""Shared test helpers: a fake HTTP layer so no test touches the network."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.siem_clients import base_client  # noqa: E402


class FakeResponse:
    def __init__(self, status=200, body=None, text=None, headers=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else (json.dumps(body) if body is not None else "")
        self.headers = headers or {}

    def json(self):
        if self._body is None:
            return json.loads(self.text)
        return self._body


class FakeHTTP:
    """
    Records requests and answers them from a route table.
    Each route is (method, url_substring, response_or_list_or_callable).
    A list is consumed one item per call (the last item repeats).
    """

    def __init__(self):
        self.routes = []
        self.calls = []

    def add(self, method, url_part, response):
        self.routes.append((method.upper(), url_part, response))

    def __call__(self, method, url, **kwargs):
        self.calls.append({"method": method.upper(), "url": url, **kwargs})
        for route_method, part, response in self.routes:
            if route_method == method.upper() and part in url:
                if callable(response) and not isinstance(response, FakeResponse):
                    return response(method, url, **kwargs)
                if isinstance(response, list):
                    return response.pop(0) if len(response) > 1 else response[0]
                return response
        raise AssertionError(f"Unexpected request: {method} {url}")

    def count(self, method, url_part):
        return sum(1 for c in self.calls if c["method"] == method and url_part in c["url"])


@pytest.fixture
def http(monkeypatch):
    fake = FakeHTTP()
    monkeypatch.setattr(base_client.requests, "request", fake)
    return fake


@pytest.fixture
def config():
    return {
        "siem": {
            "mock_mode": False,
            "timeout_seconds": 5,
            "qradar": {
                "base_url": "https://qradar.test/api",
                "verify_ssl": True,
                "search_poll_seconds": 0,
                "page_size": 2,
            },
            "fortisiem": {
                "base_url": "https://fsm.test/phoenix/rest",
                "query_poll_seconds": 0,
            },
            "seceon": {"base_url": "https://seceon.test/api/v2"},
        }
    }
