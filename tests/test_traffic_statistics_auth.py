"""Exercise real app middleware without starting production workers."""

import sys
from pathlib import Path

from fastapi.testclient import TestClient
from starlette.requests import Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app import main


def test_statistics_inherit_anomalies_permission():
    for path in (
        "/api/threat-intelligence/statistics/summary",
        "/api/threat-intelligence/statistics/history",
    ):
        request = Request(
            {"type": "http", "method": "GET", "path": path, "headers": []}
        )
        assert main.permission_for_protected_api_route(request) == "anomalies.view"
        assert main.permission_for_legacy_admin_route(request) == "anomalies.view"


def test_statistics_requires_authentication_and_old_route_remains_protected():
    # No TestClient lifespan context: no schedulers/detection startup.
    client = TestClient(main.app)
    for path in (
        "/api/threat-intelligence/statistics/summary",
        "/api/threat-intelligence/statistics/history",
        "/api/threat-intelligence/providers",
        "/api/flows/search",
    ):
        assert client.get(path).status_code == 401


def test_old_routes_still_registered():
    paths = {r.path for r in main.app.routes}
    assert {
        "/health",
        "/api/flows/search",
        "/api/threat-intelligence/providers",
        "/api/threat-intelligence/statistics/summary",
        "/api/threat-intelligence/statistics/history",
    } <= paths
