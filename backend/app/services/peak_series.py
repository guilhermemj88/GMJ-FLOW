from __future__ import annotations

"""Aggregate series fetcher for the Peak Hunter (minute granularity).

Self-contained on purpose: it does NOT import clickhouse at module top, so
importing it never drags the legacy clickhouse->peak_hunter->mitigation chain
(which breaks under the duplicated ``backend.app`` / ``app`` namespace used by
some static tests). Heavy imports are resolved lazily inside the function.
"""

from datetime import datetime
from typing import Any


def fetch_interface_aggregate_series(
    sensor: str,
    interface_id: int,
    direction: str,
    start_time: datetime,
    end_time: datetime,
) -> list[dict[str, Any]]:
    """Minute-granular BPS/PPS series for an interface from the aggregate.

    Uses flow_dashboard_series_1m (never flow_raw) so the Peak Hunter polling
    path stays cheap and bounded. Returns rows with bucket/bits_s/packets_s.
    """
    from app.services.clickhouse import FLOW_SAMPLE_RATE_FALLBACK, query_clickhouse_context

    direction = str(direction or "total").strip().lower()
    if direction in {"sends", "transmits", "outbound"}:
        where_if = "AND output_if = {interface_id:UInt32}"
    elif direction in {"receives", "inbound"}:
        where_if = "AND input_if = {interface_id:UInt32}"
    else:
        where_if = "AND (input_if = {interface_id:UInt32} OR output_if = {interface_id:UInt32})"
    params: dict[str, Any] = {
        "start": start_time,
        "end": end_time,
        "sensor": sensor,
        "interface_id": int(interface_id),
    }
    return query_clickhouse_context(
        "fetch_interface_aggregate_series",
        f"""
        SELECT
            minute AS bucket,
            sum(bytes * {FLOW_SAMPLE_RATE_FALLBACK}) * 8 / 60 AS bits_s,
            sum(packets * {FLOW_SAMPLE_RATE_FALLBACK}) / 60 AS packets_s
        FROM flow_dashboard_series_1m
        WHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
          AND sensor = {{sensor:String}}
          {where_if}
        GROUP BY minute
        ORDER BY minute
        """,
        params,
    )
