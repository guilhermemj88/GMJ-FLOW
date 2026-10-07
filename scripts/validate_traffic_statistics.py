"""Isolated development validation: SELECT-only ClickHouse; analytics DB only."""

import json
from pathlib import Path
import time
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.api.traffic_statistics import router
from app.services.traffic_statistics import Scope, get_service


def main():
    output = Path("/work/.dev-data")
    output.mkdir(exist_ok=True)
    service = get_service()
    client = service.client_factory()
    try:
        row = client.query(
            """SELECT sensor, toString(exporter_ip), toString(dst_ip), input_if FROM flow_raw
            PREWHERE flow_time >= now()-INTERVAL 1 MINUTE
            WHERE time_classification='VALID_TIME' LIMIT 1""",
            settings={"readonly": 1, "max_threads": 1, "max_execution_time": 10},
        ).result_rows[0]
    finally:
        client.close()
    sensor, exporter, target, interface = row
    app = FastAPI()
    app.include_router(router)
    api = TestClient(app)
    cases = [
        ("target", dict(scopeType="target", scopeId=target, sensor=sensor)),
        (
            "interface",
            dict(
                scopeType="interface",
                scopeId=str(interface),
                sensor=sensor,
                exporter=exporter,
            ),
        ),
        ("global", dict(scopeType="global")),
    ]
    for name, params in cases:
        started = time.monotonic()
        result = api.get("/api/threat-intelligence/statistics/summary", params=params)
        (output / f"api-{name}.json").write_text(
            json.dumps(result.json(), indent=2, ensure_ascii=False)
        )
        print(
            name, result.status_code, round(time.monotonic() - started, 3), flush=True
        )
        if result.status_code == 200:
            data = result.json()
            print(
                "rows",
                data["sampling"]["flow_records"],
                "timings",
                data["query_ms"],
                flush=True,
            )
            start = time.monotonic()
            again = api.get(
                "/api/threat-intelligence/statistics/summary", params=params
            )
            print(
                "cached",
                again.status_code,
                round(time.monotonic() - start, 3),
                flush=True,
            )
        history = api.get("/api/threat-intelligence/statistics/history", params=params)
        (output / f"history-{name}.json").write_text(
            json.dumps(history.json(), indent=2)
        )
    # Genuine historical windows, no fabricated baseline. A small target bounds the read volume.
    scope = Scope("target", target, sensor)
    now = int(time.time()) // 300 * 300
    for end in range(now - 13 * 300, now, 300):
        try:
            service.summary(scope, end=end)
        except Exception as exc:
            print("history failed", type(exc).__name__, flush=True)
            break
    # Use a fresh completed minute so the initial cold-cache response cannot
    # mask the historical observations collected by this validation run.
    reference_end = now - 60
    service.summary(scope, end=reference_end)
    with patch("app.services.traffic_statistics.time.time", return_value=reference_end):
        response = api.get(
            "/api/threat-intelligence/statistics/summary", params=cases[0][1]
        )
        assert response.status_code == 200, response.text
        result = response.json()
    (output / "api-target-baseline.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False)
    )
    print("baseline", result["baseline"], flush=True)
    history = api.get("/api/threat-intelligence/statistics/history", params=cases[0][1])
    (output / "history-target-final.json").write_text(
        json.dumps(history.json(), indent=2)
    )


if __name__ == "__main__":
    main()
