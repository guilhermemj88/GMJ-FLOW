"""Exercise real app middleware without starting production workers."""

import sys
from pathlib import Path

import importlib

# The wider suite installs lightweight stubs for third-party modules in
# sys.modules; purge them so the real packages are imported when everything
# runs in one process.
for _stub in ("fastapi", "starlette", "pydantic", "jose", "passlib", "clickhouse_connect"):
    _module = sys.modules.get(_stub)
    if _module is not None and not hasattr(_module, "__file__") and not hasattr(_module, "__path__"):
        for _name in [n for n in sys.modules if n == _stub or n.startswith(_stub + ".")]:
            del sys.modules[_name]
        importlib.invalidate_caches()

# The feature modules may have been imported earlier (via app.main) while the
# stubs were active; drop them so they are rebuilt against the real packages.
for _parent, _child in (
    ("app.api", "traffic_statistics"),
    ("app.services", "traffic_statistics"),
    ("app.services", "traffic_statistics_math"),
):
    sys.modules.pop(_parent + "." + _child, None)
    # `from app.api import X` returns the cached package attribute without
    # re-importing, so the attribute must be dropped as well.
    _package = sys.modules.get(_parent)
    if _package is not None:
        _package.__dict__.pop(_child, None)

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
