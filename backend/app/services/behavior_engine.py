from __future__ import annotations

"""Baseline Builder (SHADOW) — E2.2 of the Behavior/Baseline Engine v1.

Scope of this module:
- reads ONLY existing ClickHouse 1-minute aggregates (never flow_raw);
- processes closed 1-minute windows (batch: one query per entity per run);
- builds compact seasonal snapshots using the E2.1 statistics module;
- classifies each candidate window as ELIGIBLE / QUARANTINED / REJECTED;
- persists a compact snapshot, exception-only window audit, hourly counters
  and a resumable checkpoint.

Out of scope here: anomaly evaluator, BEHAVIOR_ANOMALY emission, Threat
Intelligence correlation, mitigation, AI. No existing detector, threshold,
Threat Score or policy is touched. prefix_behavior_baselines keeps working
unchanged as the vector-engine denominator.
"""

import argparse
import hashlib
import json
import math
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from typing import Any, Callable, Mapping, Sequence

from app.services.behavior_baseline import (
    ELIGIBLE,
    QUARANTINED,
    REJECTED,
    baseline_confidence,
    baseline_distribution,
    robust_z_score,
    seasonal_bucket,
)


# NOTE: clickhouse is imported lazily inside build_report_from_args() so the
# pure builder logic stays importable without clickhouse_connect (unit tests).


# Entity types (V1 only — no protocol/ASN/port as entity keys).
ENTITY_PREFIX = "prefix"
ENTITY_PREFIX_DIRECTION = "prefix_direction"
ENTITY_INTERFACE = "interface"
ENTITY_SENSOR = "sensor"
ENTITY_TYPES = (ENTITY_PREFIX, ENTITY_PREFIX_DIRECTION, ENTITY_INTERFACE, ENTITY_SENSOR)

# Scalar metrics learned per entity (bps/pps are 1-minute rates; flows is the
# raw count per minute; packets is the corrected packet count per minute).
SCALAR_METRICS = ("bps", "pps", "flows", "packets", "unique_sources", "unique_destinations")

# Payload metrics (distribution-like; stored compactly as JSON).
PAYLOAD_METRICS = ("protocol_distribution", "top_dst_ports")

# Window / bucket knobs.
WINDOW_SECONDS = 60
DEFAULT_BOOTSTRAP_HOURS = 24
DEFAULT_CLOSED_WINDOW_DELAY_MINUTES = 3
DEFAULT_MIN_BUCKET_SAMPLES = 3
DEFAULT_MIN_QUARANTINE_SAMPLES = 24
DEFAULT_QUARANTINE_Z = 4.0

SAMPLE_RATE_EXPR = "greatest(toFloat64(sample_rate), 1.0)"

# Chunk/cycle outcome markers (SHADOW builder).
CHUNK_STATUS_COMPLETED = "completed"
SKIPPED_ALREADY_PROCESSED = "SKIPPED_ALREADY_PROCESSED"
SKIPPED_LOAD_GUARD = "SKIPPED_LOAD_GUARD"
NO_NEW_MINUTES = "NO_NEW_MINUTES"

QueryExecutor = Callable[..., Any]


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _floor_minute(value: datetime) -> datetime:
    return value.replace(second=0, microsecond=0)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _chunk_id(start: datetime, end: datetime) -> str:
    return hashlib.sha1(f"{_iso(start)}|{_iso(end)}".encode("utf-8")).hexdigest()[:20]


def _row_dict(row: Any) -> dict[str, Any]:
    if isinstance(row, Mapping):
        return dict(row)
    if row is not None and hasattr(row, "keys"):
        return {key: row[key] for key in row.keys()}
    return {}


class BaselineBuilderConfig:
    def __init__(
        self,
        *,
        bootstrap_hours: int = DEFAULT_BOOTSTRAP_HOURS,
        closed_window_delay_minutes: int = DEFAULT_CLOSED_WINDOW_DELAY_MINUTES,
        min_bucket_samples: int = DEFAULT_MIN_BUCKET_SAMPLES,
        min_quarantine_samples: int = DEFAULT_MIN_QUARANTINE_SAMPLES,
        quarantine_z: float = DEFAULT_QUARANTINE_Z,
        include_payload_metrics: bool = True,
    ) -> None:
        self.bootstrap_hours = max(1, int(bootstrap_hours))
        self.closed_window_delay_minutes = max(1, int(closed_window_delay_minutes))
        self.min_bucket_samples = max(1, int(min_bucket_samples))
        self.min_quarantine_samples = max(1, int(min_quarantine_samples))
        self.quarantine_z = max(0.0, float(quarantine_z))
        self.include_payload_metrics = bool(include_payload_metrics)


# --------------------------------------------------------------------------
# Schema (proposed; created only when build_once(persist=True) runs).
# --------------------------------------------------------------------------

SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS behavior_baselines_v1 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_key TEXT NOT NULL,
        metric TEXT NOT NULL,
        bucket_type TEXT NOT NULL,
        bucket_key TEXT NOT NULL,
        samples REAL NOT NULL DEFAULT 0,
        p50 REAL NOT NULL DEFAULT 0,
        p75 REAL NOT NULL DEFAULT 0,
        p90 REAL NOT NULL DEFAULT 0,
        p95 REAL NOT NULL DEFAULT 0,
        p99 REAL NOT NULL DEFAULT 0,
        mad REAL NOT NULL DEFAULT 0,
        min REAL NOT NULL DEFAULT 0,
        max REAL NOT NULL DEFAULT 0,
        avg REAL NOT NULL DEFAULT 0,
        confidence TEXT NOT NULL DEFAULT 'COLD',
        payload_json TEXT NOT NULL DEFAULT '',
        first_sample_at TEXT NOT NULL DEFAULT '',
        last_sample_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL,
        UNIQUE(entity_type, entity_key, metric, bucket_type, bucket_key)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS behavior_baseline_runtime_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        last_processed_minute TEXT NOT NULL DEFAULT '',
        last_success_at TEXT NOT NULL DEFAULT '',
        last_error TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS behavior_baseline_window_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        window_start TEXT NOT NULL,
        window_end TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_key TEXT NOT NULL,
        classification TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(window_start, entity_type, entity_key, classification)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS behavior_baseline_hour_counters (
        hour TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_key TEXT NOT NULL,
        eligible INTEGER NOT NULL DEFAULT 0,
        quarantined INTEGER NOT NULL DEFAULT 0,
        rejected INTEGER NOT NULL DEFAULT 0,
        insufficient INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (hour, entity_type, entity_key)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS behavior_baseline_processed_chunks (
        chunk_id TEXT NOT NULL,
        chunk_start TEXT NOT NULL,
        chunk_end TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'completed',
        started_at TEXT NOT NULL DEFAULT '',
        completed_at TEXT NOT NULL DEFAULT '',
        windows_processed INTEGER NOT NULL DEFAULT 0,
        runtime_seconds REAL NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        UNIQUE(chunk_start, chunk_end)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_behavior_baseline_processed_chunks_status ON behavior_baseline_processed_chunks(status, chunk_end)",
    "CREATE INDEX IF NOT EXISTS idx_behavior_baselines_v1_entity ON behavior_baselines_v1(entity_type, entity_key)",
    "CREATE INDEX IF NOT EXISTS idx_behavior_baseline_audit_entity ON behavior_baseline_window_audit(entity_type, entity_key, window_start)",
)


def ensure_behavior_engine_schema(conn: Any) -> None:
    for statement in SCHEMA_STATEMENTS:
        conn.execute(statement)


def estimate_snapshot_storage(snapshot_rows: int, audit_rows: int, counter_rows: int) -> dict[str, Any]:
    bytes_estimate = snapshot_rows * 320 + audit_rows * 220 + counter_rows * 160
    return {
        "snapshot_rows": snapshot_rows,
        "audit_rows": audit_rows,
        "counter_rows": counter_rows,
        "estimated_bytes": bytes_estimate,
        "estimated_mb": round(bytes_estimate / (1024 * 1024), 2),
    }


# --------------------------------------------------------------------------
# Entity discovery (SQLite, read-only).
# --------------------------------------------------------------------------

def discover_entities(conn: Any) -> list[dict[str, Any]]:
    entities: list[dict[str, Any]] = []
    for row in conn.execute("SELECT cidr FROM ip_zone_prefixes WHERE active = 1").fetchall():
        cidr = _clean(row["cidr"] if isinstance(row, Mapping) else row[0])
        if not cidr:
            continue
        entities.append({"entity_type": ENTITY_PREFIX, "entity_key": cidr, "prefix": cidr, "direction": "in"})
        entities.append({"entity_type": ENTITY_PREFIX_DIRECTION, "entity_key": f"{cidr}|in", "prefix": cidr, "direction": "in"})
        entities.append({"entity_type": ENTITY_PREFIX_DIRECTION, "entity_key": f"{cidr}|out", "prefix": cidr, "direction": "out"})
    sensors = conn.execute("SELECT id, name FROM sensors WHERE active = 1").fetchall()
    sensor_by_id = {}
    for row in sensors:
        item = dict(row)
        name = _clean(item.get("name"))
        if not name:
            continue
        sensor_by_id[int(item.get("id") or 0)] = name
        for direction in ("in", "out"):
            entities.append({"entity_type": ENTITY_SENSOR, "entity_key": f"{name}|{direction}", "sensor": name, "direction": direction})
    for row in conn.execute("SELECT sensor_id, if_index FROM sensor_interfaces WHERE monitor_enabled = 1").fetchall():
        item = dict(row)
        name = sensor_by_id.get(int(item.get("sensor_id") or 0))
        if not name:
            continue
        if_index = int(item.get("if_index") or 0)
        for direction in ("in", "out"):
            entities.append({
                "entity_type": ENTITY_INTERFACE,
                "entity_key": f"{name}|{if_index}|{direction}",
                "sensor": name,
                "if_index": if_index,
                "direction": direction,
            })
    return entities


# --------------------------------------------------------------------------
# Prefix lookup abstraction (batch; NO ClickHouse schema objects created).
# --------------------------------------------------------------------------

class PrefixLookup:
    """Maps an IP column to a prefix entity key in SQL.

    Longest-prefix-match: prefixes are ordered most-specific first, so the
    first matching branch wins (documented LPM rule). The provisional strategy
    is a read-only multiIf chain; the production candidate is an ip_trie
    dictionary (see design — not created yet).
    """

    def __init__(self, prefixes: Sequence[str]) -> None:
        self.prefixes = sorted(
            {_clean(prefix) for prefix in prefixes if _clean(prefix)},
            key=lambda prefix: ip_network(prefix, strict=False).prefixlen,
            reverse=True,
        )

    @staticmethod
    def _normalized(ip_column: str) -> str:
        # IPv4 rows are stored as IPv4-mapped IPv6; strip the prefix so plain
        # IPv4 CIDRs match (same convention as the event investigation). Native
        # IPv6 addresses are left unchanged.
        return f"replaceRegexpOne(toString({ip_column}), '^::ffff:', '')"


class MultiIfPrefixLookup(PrefixLookup):
    """Provisional read-only strategy: multiIf chain evaluated per row.

    Correct for overlapping prefixes (ordered most-specific first). Per-row
    cost is O(number of prefixes), so it is only suitable for a SMALL prefix
    count; the ip_trie dictionary is the production path for thousands.
    """

    def expression(self, ip_column: str) -> str:
        norm = self._normalized(ip_column)
        clauses: list[str] = []
        for prefix in self.prefixes:
            clauses.append(f"isIPAddressInRange({norm}, '{prefix}')")
            clauses.append(f"'{prefix}'")
        clauses.append("''")
        return "multiIf(" + ", ".join(clauses) + ")"


class IpTriePrefixLookup(PrefixLookup):
    """Production candidate (requires an approved CREATE DICTIONARY). Unused."""

    def expression(self, ip_column: str) -> str:
        raise NotImplementedError("ip_trie lookup requires an approved dictionary")


# --------------------------------------------------------------------------
# ClickHouse fetchers — BATCH: a FIXED number of queries for ALL entities.
# --------------------------------------------------------------------------

def fetch_batch_protocol_metrics(executor: QueryExecutor, start: datetime, end: datetime) -> list[dict[str, Any]]:
    params = {"start": start, "end": end}
    return executor(
        f"""
        SELECT minute, sensor, input_if, output_if, proto,
               sum(bytes * {SAMPLE_RATE_EXPR}) AS bytes,
               sum(packets * {SAMPLE_RATE_EXPR}) AS packets,
               sum(flows) AS flows
        FROM flow_dashboard_protocol_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, sensor, input_if, output_if, proto
        """,
        params,
    )


def fetch_batch_interface_uniques(executor: QueryExecutor, start: datetime, end: datetime) -> list[dict[str, Any]]:
    params = {"start": start, "end": end}
    return executor(
        f"""
        SELECT minute, sensor, input_if AS if_index, 1 AS direction, 'src' AS kind, uniqExact(src_ip) AS value
        FROM flow_dashboard_src_ip_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, sensor, input_if
        UNION ALL
        SELECT minute, sensor, output_if AS if_index, 2 AS direction, 'src' AS kind, uniqExact(src_ip) AS value
        FROM flow_dashboard_src_ip_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, sensor, output_if
        UNION ALL
        SELECT minute, sensor, toUInt32(0) AS if_index, 0 AS direction, 'src' AS kind, uniqExact(src_ip) AS value
        FROM flow_dashboard_src_ip_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, sensor
        UNION ALL
        SELECT minute, sensor, input_if AS if_index, 1 AS direction, 'dst' AS kind, uniqExact(dst_ip) AS value
        FROM flow_dashboard_dst_ip_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, sensor, input_if
        UNION ALL
        SELECT minute, sensor, output_if AS if_index, 2 AS direction, 'dst' AS kind, uniqExact(dst_ip) AS value
        FROM flow_dashboard_dst_ip_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, sensor, output_if
        UNION ALL
        SELECT minute, sensor, toUInt32(0) AS if_index, 0 AS direction, 'dst' AS kind, uniqExact(dst_ip) AS value
        FROM flow_dashboard_dst_ip_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, sensor
        """,
        params,
    )


def fetch_batch_prefix_metrics(executor: QueryExecutor, start: datetime, end: datetime, lookup: PrefixLookup) -> list[dict[str, Any]]:
    dst_expr = lookup.expression("dst_ip")
    src_expr = lookup.expression("src_ip")
    params = {"start": start, "end": end}
    return executor(
        f"""
        SELECT minute, proto, dst_port, {dst_expr} AS prefix_key, 'in' AS direction,
               sum(bytes * {SAMPLE_RATE_EXPR}) AS bytes,
               sum(packets * {SAMPLE_RATE_EXPR}) AS packets,
               sum(flows) AS flows
        FROM flow_dashboard_prefix_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, proto, dst_port, prefix_key, direction
        HAVING prefix_key != ''
        UNION ALL
        SELECT minute, proto, dst_port, {src_expr} AS prefix_key, 'out' AS direction,
               sum(bytes * {SAMPLE_RATE_EXPR}) AS bytes,
               sum(packets * {SAMPLE_RATE_EXPR}) AS packets,
               sum(flows) AS flows
        FROM flow_dashboard_prefix_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, proto, dst_port, prefix_key, direction
        HAVING prefix_key != ''
        """,
        params,
    )


def fetch_batch_prefix_uniques(executor: QueryExecutor, start: datetime, end: datetime, lookup: PrefixLookup) -> list[dict[str, Any]]:
    dst_expr = lookup.expression("dst_ip")
    src_expr = lookup.expression("src_ip")
    params = {"start": start, "end": end}
    return executor(
        f"""
        SELECT minute, {dst_expr} AS prefix_key, 'in' AS direction,
               uniqExact(src_ip) AS unique_sources, uniqExact(dst_ip) AS unique_destinations
        FROM flow_dashboard_prefix_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, prefix_key, direction
        HAVING prefix_key != ''
        UNION ALL
        SELECT minute, {src_expr} AS prefix_key, 'out' AS direction,
               uniqExact(src_ip) AS unique_sources, uniqExact(dst_ip) AS unique_destinations
        FROM flow_dashboard_prefix_1m
        PREWHERE minute >= {{start:DateTime}} AND minute <= {{end:DateTime}}
        GROUP BY minute, prefix_key, direction
        HAVING prefix_key != ''
        """,
        params,
    )


# --------------------------------------------------------------------------
# In-memory fan-out: batch rows -> per-entity per-minute (metrics, payload).
# --------------------------------------------------------------------------

def _minute_key(value: Any) -> str:
    return _iso(value) if isinstance(value, datetime) else _clean(value)


def _new_bucket() -> dict[str, Any]:
    return {"bytes": 0.0, "packets": 0.0, "flows": 0.0, "proto_bytes": {}, "port_bytes": {}}


def _accumulate_metric_row(bucket: dict[str, Any], row: Mapping[str, Any]) -> None:
    row_bytes = float(row.get("bytes") or 0)
    bucket["bytes"] += row_bytes
    bucket["packets"] += float(row.get("packets") or 0)
    bucket["flows"] += float(row.get("flows") or 0)
    proto = _clean(row.get("proto"))
    bucket["proto_bytes"][proto] = bucket["proto_bytes"].get(proto, 0.0) + row_bytes
    dst_port = row.get("dst_port")
    if dst_port is not None:
        port_key = _clean(dst_port)
        bucket["port_bytes"][port_key] = bucket["port_bytes"].get(port_key, 0.0) + row_bytes


def _build_metrics_payload(bucket: Mapping[str, Any]) -> tuple[dict[str, float], dict[str, Any]]:
    bytes_total = float(bucket.get("bytes") or 0)
    metrics: dict[str, float] = {
        "bps": round(bytes_total * 8 / WINDOW_SECONDS, 3),
        "pps": round(float(bucket.get("packets") or 0) / WINDOW_SECONDS, 3),
        "flows": round(float(bucket.get("flows") or 0), 3),
        "packets": round(float(bucket.get("packets") or 0), 3),
    }
    if bucket.get("unique_sources") is not None:
        metrics["unique_sources"] = float(bucket["unique_sources"])
    if bucket.get("unique_destinations") is not None:
        metrics["unique_destinations"] = float(bucket["unique_destinations"])
    protocol_shares: dict[str, float] = {}
    top_dst_ports: list[dict[str, Any]] = []
    if bytes_total > 0:
        protocol_shares = {proto: round(share / bytes_total, 4) for proto, share in bucket["proto_bytes"].items()}
        top_dst_ports = [
            {"port": port, "share": round(share / bytes_total, 4)}
            for port, share in sorted(bucket["port_bytes"].items(), key=lambda item: -item[1])[:5]
        ]
    payload = {"protocol_shares": protocol_shares, "top_dst_ports": top_dst_ports}
    return metrics, payload


def fanout_entity_minutes(
    proto_rows: Sequence[Mapping[str, Any]],
    uniq_rows: Sequence[Mapping[str, Any]],
    prefix_metric_rows: Sequence[Mapping[str, Any]],
    prefix_uniq_rows: Sequence[Mapping[str, Any]],
    entities: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, tuple[dict[str, float], dict[str, Any]]]]:
    # --- interface/sensor buckets ---
    proto_by_sensor: dict[str, dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(_new_bucket))
    proto_by_iface_in: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(_new_bucket))
    proto_by_iface_out: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(_new_bucket))
    for row in proto_rows:
        minute = _minute_key(row.get("minute"))
        sensor = _clean(row.get("sensor"))
        _accumulate_metric_row(proto_by_sensor[sensor][minute], row)
        input_if = row.get("input_if")
        output_if = row.get("output_if")
        if input_if is not None:
            _accumulate_metric_row(proto_by_iface_in[(sensor, int(input_if))][minute], row)
        if output_if is not None:
            _accumulate_metric_row(proto_by_iface_out[(sensor, int(output_if))][minute], row)

    uniq_by_sensor: dict[str, dict[str, dict[str, float]]] = defaultdict(dict)
    uniq_by_iface: dict[tuple[str, int, int], dict[str, dict[str, float]]] = defaultdict(dict)
    for row in uniq_rows:
        minute = _minute_key(row.get("minute"))
        sensor = _clean(row.get("sensor"))
        if_index = int(row.get("if_index") or 0)
        direction = int(row.get("direction") or 0)
        kind = _clean(row.get("kind"))
        value = float(row.get("value") or 0)
        field = "unique_sources" if kind == "src" else "unique_destinations"
        if if_index == 0:
            uniq_by_sensor[sensor].setdefault(minute, {})[field] = value
        else:
            uniq_by_iface[(sensor, if_index, direction)].setdefault(minute, {})[field] = value

    # --- prefix buckets ---
    prefix_metric: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(_new_bucket))
    for row in prefix_metric_rows:
        minute = _minute_key(row.get("minute"))
        prefix_key = _clean(row.get("prefix_key"))
        direction = _clean(row.get("direction"))
        _accumulate_metric_row(prefix_metric[(prefix_key, direction)][minute], row)

    prefix_uniq: dict[tuple[str, str], dict[str, dict[str, float]]] = defaultdict(dict)
    for row in prefix_uniq_rows:
        minute = _minute_key(row.get("minute"))
        prefix_key = _clean(row.get("prefix_key"))
        direction = _clean(row.get("direction"))
        prefix_uniq[(prefix_key, direction)][minute] = {
            "unique_sources": float(row.get("unique_sources") or 0),
            "unique_destinations": float(row.get("unique_destinations") or 0),
        }

    # --- assemble per entity ---
    minutes_by_key: dict[str, dict[str, tuple[dict[str, float], dict[str, Any]]]] = {}
    for entity in entities:
        entity_key = entity["entity_key"]
        entity_type = entity["entity_type"]
        result: dict[str, tuple[dict[str, float], dict[str, Any]]] = {}
        if entity_type == ENTITY_SENSOR:
            for minute, bucket in proto_by_sensor.get(entity["sensor"], {}).items():
                merged = dict(bucket)
                merged.update(uniq_by_sensor.get(entity["sensor"], {}).get(minute, {}))
                result[minute] = _build_metrics_payload(merged)
        elif entity_type == ENTITY_INTERFACE:
            direction = entity["direction"]
            source = proto_by_iface_in if direction == "in" else proto_by_iface_out
            direction_number = 1 if direction == "in" else 2
            iface_key = (entity["sensor"], int(entity["if_index"]))
            for minute, bucket in source.get(iface_key, {}).items():
                merged = dict(bucket)
                merged.update(uniq_by_iface.get((entity["sensor"], int(entity["if_index"]), direction_number), {}).get(minute, {}))
                result[minute] = _build_metrics_payload(merged)
        elif entity_type == ENTITY_PREFIX:
            in_buckets = prefix_metric.get((entity["prefix"], "in"), {})
            out_buckets = prefix_metric.get((entity["prefix"], "out"), {})
            for minute in set(in_buckets) | set(out_buckets):
                merged = _new_bucket()
                for source in (in_buckets.get(minute), out_buckets.get(minute)):
                    if not source:
                        continue
                    merged["bytes"] += source["bytes"]
                    merged["packets"] += source["packets"]
                    merged["flows"] += source["flows"]
                    for proto, share in source["proto_bytes"].items():
                        merged["proto_bytes"][proto] = merged["proto_bytes"].get(proto, 0.0) + share
                    for port, share in source["port_bytes"].items():
                        merged["port_bytes"][port] = merged["port_bytes"].get(port, 0.0) + share
                # Aggregate prefix entity carries no uniqueness (directionless
                # union is non-additive) — documented decision.
                result[minute] = _build_metrics_payload(merged)
        else:  # ENTITY_PREFIX_DIRECTION
            direction = entity["direction"]
            for minute, bucket in prefix_metric.get((entity["prefix"], direction), {}).items():
                merged = dict(bucket)
                merged.update(prefix_uniq.get((entity["prefix"], direction), {}).get(minute, {}))
                result[minute] = _build_metrics_payload(merged)
        minutes_by_key[entity_key] = result
    return minutes_by_key


# --------------------------------------------------------------------------
# Attack signals (existing data only — no new detection).
# --------------------------------------------------------------------------

def fetch_attack_signals_range(conn: Any, start: datetime, end: datetime) -> list[dict[str, Any]]:
    """All confirmed signals overlapping [start, end) in ONE query (batch)."""
    rows = conn.execute(
        """
        SELECT attack_type, severity, verdict, src_ip, target_ip, target_prefix, sensor, first_seen, last_seen
        FROM security_events
        WHERE (severity = 'CRITICAL' OR verdict = 'CONFIRMED_ATTACK')
          AND first_seen < ? AND last_seen >= ?
        """,
        (_iso(end), _iso(start)),
    ).fetchall()
    return [dict(row) for row in rows]


def _index_signals_by_window(
    signals: Sequence[Mapping[str, Any]],
    start: datetime,
    end: datetime,
) -> dict[datetime, list[dict[str, Any]]]:
    """Maps each 1-minute window start to the signals overlapping that window."""
    index: dict[datetime, list[dict[str, Any]]] = {}
    for signal in signals:
        first = _parse_iso(_clean(signal.get("first_seen")))
        last = _parse_iso(_clean(signal.get("last_seen")))
        if first is None or last is None:
            continue
        cursor = _floor_minute(max(first, start))
        stop = min(last, end)
        while cursor <= stop:
            if start <= cursor < end:
                index.setdefault(cursor, []).append(signal)
            cursor += timedelta(seconds=WINDOW_SECONDS)
    return index


def _parse_iso(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def fetch_attack_signals(conn: Any, window_start: datetime, window_end: datetime) -> list[dict[str, Any]]:
    """Per-window confirmed signals (kept for unit tests; runtime uses the
    batched fetch_attack_signals_range). behavioral_attack_vectors is
    intentionally NOT used as a signal source in E2.2: it has no
    severity/verdict columns, so treating any of its rows as a rejection
    signal would contaminate the baseline with false negatives."""
    return fetch_attack_signals_range(conn, window_start, window_end)


def _signal_matches_entity(signal: Mapping[str, Any], entity: Mapping[str, Any]) -> bool:
    sensor = _clean(signal.get("sensor"))
    entity_sensor = entity.get("sensor")
    if entity_sensor:
        # Interface/sensor entities require an explicit matching sensor; a
        # signal without sensor attribution is never attributed to them.
        return bool(sensor) and entity_sensor == sensor
    prefix = entity.get("prefix")
    if not prefix:
        return True
    try:
        network = ip_network(prefix, strict=False)
    except ValueError:
        return True
    candidates = [_clean(signal.get("target_prefix")), _clean(signal.get("target_ip")), _clean(signal.get("src_ip"))]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            if "/" in candidate:
                if ip_network(candidate, strict=False).overlaps(network):
                    return True
            elif ip_address(candidate) in network:
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------
# Window classification (conservative; no runtime anomaly score in E2.2).
# --------------------------------------------------------------------------

def classify_window(
    entity: Mapping[str, Any],
    metrics: Mapping[str, float],
    signals: Sequence[Mapping[str, Any]],
    previous_snapshot: Mapping[str, Any] | None,
    config: BaselineBuilderConfig,
) -> tuple[str, str]:
    """REJECTED via existing confirmed signals; QUARANTINED only via the
    previous snapshot's robust z-score (bps); ELIGIBLE otherwise — including
    during bootstrap, when there is not enough history to judge. That is the
    documented conservative E2.2 strategy."""
    matching = [signal for signal in signals if _signal_matches_entity(signal, entity)]
    if matching:
        signal = matching[0]
        verdict = _clean(signal.get("verdict"))
        attack_type = _clean(signal.get("attack_type"))
        return REJECTED, f"{verdict or 'CRITICAL'}:{attack_type or 'unknown'}"
    snapshot = previous_snapshot
    if snapshot and int(snapshot.get("samples") or 0) >= config.min_quarantine_samples:
        bps = metrics.get("bps")
        if bps is not None:
            z_score = robust_z_score(bps, snapshot.get("p50"), snapshot.get("mad"))
            if abs(z_score) >= config.quarantine_z:
                return QUARANTINED, f"HIGH_ANOMALY:z={z_score:.2f}"
    return ELIGIBLE, "NORMAL_WINDOW"


# --------------------------------------------------------------------------
# Snapshot accumulation + persistence.
# --------------------------------------------------------------------------

def _accumulate_window(
    accumulators: dict[tuple[str, str], dict[tuple[str, str, str], dict[str, Any]]],
    entity: Mapping[str, Any],
    metrics: Mapping[str, float],
    bucket: Mapping[str, Any],
    window_start: datetime,
) -> None:
    key = (entity["entity_type"], entity["entity_key"])
    metric_values = accumulators.setdefault(key, {})
    for metric_name, value in metrics.items():
        if value is None or (isinstance(value, float) and not math.isfinite(value)):
            continue
        for bucket_type, bucket_key in (("dow_hour", bucket["dow_hour_key"]), ("hour", bucket["hour_key"]), ("global", bucket["global_key"])):
            entry = metric_values.setdefault((metric_name, bucket_type, bucket_key), {"values": [], "first": None, "last": None})
            entry["values"].append(float(value))
            entry["first"] = window_start if entry["first"] is None else min(entry["first"], window_start)
            entry["last"] = window_start if entry["last"] is None else max(entry["last"], window_start)


def _aggregate_payload(windows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    protocol_totals: dict[str, float] = {}
    port_totals: dict[str, float] = {}
    protocol_count = 0
    port_count = 0
    for window in windows:
        shares = window.get("protocol_shares") or {}
        for protocol, share in shares.items():
            protocol_totals[protocol] = protocol_totals.get(protocol, 0.0) + float(share)
            protocol_count += 1
        for port_item in window.get("top_dst_ports") or []:
            port_totals[str(port_item.get("port"))] = port_totals.get(str(port_item.get("port")), 0.0) + float(port_item.get("share") or 0)
            port_count += 1
    protocol_distribution = {
        protocol: round(protocol_totals[protocol] / max(1, len(windows)), 4)
        for protocol in protocol_totals
    }
    top_dst_ports = [
        {"port": port, "share": round(share / max(1, len(windows)), 4)}
        for port, share in sorted(port_totals.items(), key=lambda item: -item[1])[:5]
    ]
    return {"protocol_distribution": protocol_distribution, "top_dst_ports": top_dst_ports}


# --------------------------------------------------------------------------
# Builder.
# --------------------------------------------------------------------------

class BaselineBuilder:
    def __init__(
        self,
        connection_factory: Callable[[], Any],
        query_executor: QueryExecutor,
        config: BaselineBuilderConfig | None = None,
        now_fn: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.connection_factory = connection_factory
        self.query_executor = query_executor
        self.config = config or BaselineBuilderConfig()
        self.now_fn = now_fn

    def _checkpoint(self, conn: Any) -> datetime | None:
        try:
            row = conn.execute("SELECT last_processed_minute, last_error FROM behavior_baseline_runtime_state WHERE id = 1").fetchone()
        except Exception:
            return None
        if row is None:
            return None
        item = _row_dict(row)
        try:
            parsed = datetime.fromisoformat(_clean(item.get("last_processed_minute")).replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _existing_snapshots(self, conn: Any) -> dict[tuple[str, str, str, str, str], dict[str, Any]]:
        snapshots: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        try:
            rows = conn.execute(
                "SELECT entity_type, entity_key, metric, bucket_type, bucket_key, samples, p50, mad FROM behavior_baselines_v1"
            ).fetchall()
        except Exception:
            return snapshots
        for row in rows:
            item = _row_dict(row)
            snapshots[(item["entity_type"], item["entity_key"], item["metric"], item["bucket_type"], item["bucket_key"])] = item
        return snapshots

    def _chunk_completed(self, conn: Any, start: datetime, end: datetime) -> bool:
        try:
            row = conn.execute(
                "SELECT 1 FROM behavior_baseline_processed_chunks "
                "WHERE chunk_start = ? AND chunk_end = ? AND status = ? LIMIT 1",
                (_iso(start), _iso(end), CHUNK_STATUS_COMPLETED),
            ).fetchone()
        except Exception:
            return False
        return row is not None

    def build_once(self, *, persist: bool = False, start: datetime | None = None, end: datetime | None = None) -> dict[str, Any]:
        started = time.monotonic()
        query_seconds = 0.0
        queries_executed = 0
        config = self.config
        now = _floor_minute(self.now_fn())
        started_wall = _iso(self.now_fn())
        conn = self.connection_factory()
        try:
            if persist:
                # Schema DDL runs only in persist mode: a dry-run never
                # creates tables (production safety requirement).
                ensure_behavior_engine_schema(conn)
                conn.commit()
            entities = discover_entities(conn)
            if start is None:
                checkpoint = self._checkpoint(conn)
                start = checkpoint or (now - timedelta(hours=config.bootstrap_hours))
            if end is None:
                end = now - timedelta(minutes=config.closed_window_delay_minutes)
            report: dict[str, Any] = {
                "window_range": {"start": _iso(start), "end": _iso(end), "closed_delay_minutes": config.closed_window_delay_minutes},
                "entities": len(entities),
                "entities_by_type": {entity_type: sum(1 for item in entities if item["entity_type"] == entity_type) for entity_type in ENTITY_TYPES},
                "windows_processed": 0,
                "eligible": 0,
                "quarantined": 0,
                "rejected": 0,
                "insufficient": 0,
                "snapshots_to_upsert": 0,
                "payload_snapshots_to_upsert": 0,
                "audit_rows_to_insert": 0,
                "counter_rows_to_upsert": 0,
                "queries_executed": 0,
                "query_runtime_seconds": 0.0,
                "runtime_seconds": 0.0,
                "persisted": False,
                "chunk_status": CHUNK_STATUS_COMPLETED,
            }
            if start >= end:
                report["runtime_seconds"] = round(time.monotonic() - started, 2)
                return report
            if persist and self._chunk_completed(conn, start, end):
                report.update({
                    "chunk_status": SKIPPED_ALREADY_PROCESSED,
                    "runtime_seconds": round(time.monotonic() - started, 2),
                })
                return report

            # Attack signals: one SQLite query for the whole range, indexed by
            # window (avoids one query per minute). Entity matching is
            # precomputed once per run to avoid O(windows x entities x signals).
            signals = fetch_attack_signals_range(conn, start, end)
            signal_index = _index_signals_by_window(signals, start, end)
            entity_matched_ids = {
                entity["entity_key"]: {id(signal) for signal in signals if _signal_matches_entity(signal, entity)}
                for entity in entities
            }

            # Batch fetch: a FIXED number of queries for ALL entities (never
            # per entity). Interface/sensor = 2 queries; prefix = 2 queries.
            def counting_executor(sql, params=None):
                nonlocal queries_executed, query_seconds
                query_started = time.monotonic()
                queries_executed += 1
                try:
                    return self.query_executor(sql, params)
                finally:
                    query_seconds += time.monotonic() - query_started

            sensors_present = any(entity.get("sensor") for entity in entities)
            prefix_list = [entity["prefix"] for entity in entities if entity.get("prefix")]
            prefix_lookup = MultiIfPrefixLookup(prefix_list)
            try:
                proto_rows = fetch_batch_protocol_metrics(counting_executor, start, end) if sensors_present else []
                uniq_rows = fetch_batch_interface_uniques(counting_executor, start, end) if sensors_present else []
                prefix_metric_rows = fetch_batch_prefix_metrics(counting_executor, start, end, prefix_lookup) if prefix_list else []
                prefix_uniq_rows = fetch_batch_prefix_uniques(counting_executor, start, end, prefix_lookup) if prefix_list else []
                entity_minutes = fanout_entity_minutes(proto_rows, uniq_rows, prefix_metric_rows, prefix_uniq_rows, entities)
            except Exception:
                # A batch failure marks every window of every entity as
                # insufficient; the run remains retryable from the checkpoint.
                entity_minutes = {entity["entity_key"]: {} for entity in entities}

            snapshots = self._existing_snapshots(conn)
            accumulators: dict[tuple[str, str], dict[tuple[str, str, str], list[float]]] = {}
            payload_windows: dict[tuple[str, str], list[dict[str, Any]]] = {}
            counters: dict[tuple[str, str, str], dict[str, int]] = {}
            audit_rows: list[dict[str, Any]] = []
            eligible = quarantined = rejected = insufficient = processed = 0

            cursor = start
            while cursor < end:
                window_start = cursor
                window_end = cursor + timedelta(seconds=WINDOW_SECONDS)
                cursor = window_end
                minute_iso = _iso(window_start)
                hour = minute_iso[:13] + ":00:00Z"
                window_signals = signal_index.get(window_start, [])
                bucket = seasonal_bucket(window_start) or {"dow_hour_key": "global", "hour_key": "global", "global_key": "global"}
                for entity in entities:
                    entity_type = entity["entity_type"]
                    entity_key = entity["entity_key"]
                    counter_key = (hour, entity_type, entity_key)
                    counter = counters.setdefault(counter_key, {"eligible": 0, "quarantined": 0, "rejected": 0, "insufficient": 0})
                    metrics, payload = entity_minutes.get(entity_key, {}).get(minute_iso, ({}, {}))
                    processed += 1
                    if not metrics:
                        insufficient += 1
                        counter["insufficient"] += 1
                        continue
                    matched_ids = entity_matched_ids[entity_key]
                    entity_signals = [signal for signal in window_signals if id(signal) in matched_ids]
                    previous_snapshot = snapshots.get((entity_type, entity_key, "bps", "global", "global"))
                    classification, reason = classify_window(entity, metrics, entity_signals, previous_snapshot, config)
                    counter[classification.lower()] = counter.get(classification.lower(), 0) + 1
                    if classification == ELIGIBLE:
                        eligible += 1
                        # Anti-contamination: only ELIGIBLE windows feed the
                        # baseline; REJECTED/QUARANTINED never accumulate.
                        _accumulate_window(accumulators, entity, metrics, bucket, window_start)
                        payload_windows.setdefault((entity_type, entity_key), []).append({
                            "window_start": minute_iso,
                            "protocol_shares": payload.get("protocol_shares") or {},
                            "top_dst_ports": payload.get("top_dst_ports") or [],
                        })
                    elif classification == QUARANTINED:
                        quarantined += 1
                        audit_rows.append({
                            "window_start": minute_iso, "window_end": _iso(window_end),
                            "entity_type": entity_type, "entity_key": entity_key,
                            "classification": classification, "reason": reason,
                        })
                    else:
                        rejected += 1
                        audit_rows.append({
                            "window_start": minute_iso, "window_end": _iso(window_end),
                            "entity_type": entity_type, "entity_key": entity_key,
                            "classification": classification, "reason": reason,
                        })

            snapshot_rows: list[dict[str, Any]] = []
            for (entity_type, entity_key), metric_buckets in accumulators.items():
                for (metric_name, bucket_type, bucket_key), entry in metric_buckets.items():
                    values = entry["values"]
                    if len(values) < config.min_bucket_samples:
                        continue
                    distribution = baseline_distribution(values)
                    first = entry["first"]
                    last = entry["last"]
                    span = (last - first).total_seconds() if (first is not None and last is not None) else 0.0
                    snapshot_rows.append({
                        "entity_type": entity_type,
                        "entity_key": entity_key,
                        "metric": metric_name,
                        "bucket_type": bucket_type,
                        "bucket_key": bucket_key,
                        "distribution": distribution,
                        "confidence": baseline_confidence(span_seconds=span),
                        "first_sample_at": _iso(first) if first is not None else "",
                        "last_sample_at": _iso(last) if last is not None else "",
                    })
            payload_rows: list[dict[str, Any]] = []
            if config.include_payload_metrics:
                for (entity_type, entity_key), windows in payload_windows.items():
                    aggregated = _aggregate_payload(windows)
                    payload_rows.append({
                        "entity_type": entity_type,
                        "entity_key": entity_key,
                        "metric": "protocol_distribution",
                        "bucket_type": "global",
                        "bucket_key": "global",
                        "payload": aggregated,
                    })

            counter_rows = [
                {"hour": hour, "entity_type": entity_type, "entity_key": entity_key, **counts}
                for (hour, entity_type, entity_key), counts in counters.items()
            ]
            storage = estimate_snapshot_storage(len(snapshot_rows), len(audit_rows), len(counter_rows))

            report.update({
                "windows_processed": processed,
                "queries_executed": queries_executed,
                "eligible": eligible,
                "quarantined": quarantined,
                "rejected": rejected,
                "insufficient": insufficient,
                "snapshots_to_upsert": len(snapshot_rows),
                "payload_snapshots_to_upsert": len(payload_rows),
                "audit_rows_to_insert": len(audit_rows),
                "counter_rows_to_upsert": len(counter_rows),
                "storage_estimate": storage,
                "query_runtime_seconds": round(query_seconds, 2),
                "runtime_seconds": round(time.monotonic() - started, 2),
                "persisted": False,
            })

            if persist:
                self._persist(
                    conn, snapshot_rows, payload_rows, audit_rows, counter_rows, end,
                    chunk_start=start,
                    chunk_end=end,
                    started_at=started_wall,
                    runtime_seconds=round(time.monotonic() - started, 2),
                    windows_processed=processed,
                )
                report["persisted"] = True
            return report
        finally:
            conn.close()

    def _persist(
        self,
        conn: Any,
        snapshot_rows,
        payload_rows,
        audit_rows,
        counter_rows,
        last_minute: datetime,
        *,
        chunk_start: datetime,
        chunk_end: datetime,
        started_at: str = "",
        runtime_seconds: float = 0.0,
        windows_processed: int = 0,
    ) -> None:
        now_iso = _iso(self.now_fn())
        try:
            conn.execute("BEGIN IMMEDIATE")
            for row in snapshot_rows:
                distribution = row["distribution"]
                conn.execute(
                    """
                    INSERT INTO behavior_baselines_v1 (
                        entity_type, entity_key, metric, bucket_type, bucket_key,
                        samples, p50, p75, p90, p95, p99, mad, min, max, avg,
                        confidence, payload_json, first_sample_at, last_sample_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?)
                    ON CONFLICT(entity_type, entity_key, metric, bucket_type, bucket_key) DO UPDATE SET
                        samples = excluded.samples, p50 = excluded.p50, p75 = excluded.p75,
                        p90 = excluded.p90, p95 = excluded.p95, p99 = excluded.p99,
                        mad = excluded.mad, min = excluded.min, max = excluded.max,
                        avg = excluded.avg, confidence = excluded.confidence,
                        first_sample_at = excluded.first_sample_at,
                        last_sample_at = excluded.last_sample_at,
                        updated_at = excluded.updated_at
                    """,
                    (
                        row["entity_type"], row["entity_key"], row["metric"], row["bucket_type"], row["bucket_key"],
                        distribution["samples"], distribution["p50"], distribution["p75"],
                        distribution["p90"], distribution["p95"], distribution["p99"], distribution["mad"],
                        distribution["min"], distribution["max"], distribution["avg"], row["confidence"],
                        row.get("first_sample_at") or "", row.get("last_sample_at") or "",
                        now_iso,
                    ),
                )
            for row in payload_rows:
                conn.execute(
                    """
                    INSERT INTO behavior_baselines_v1 (
                        entity_type, entity_key, metric, bucket_type, bucket_key,
                        samples, p50, p75, p90, p95, p99, mad, min, max, avg,
                        confidence, payload_json, first_sample_at, last_sample_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'COLD', ?, '', '', ?)
                    ON CONFLICT(entity_type, entity_key, metric, bucket_type, bucket_key) DO UPDATE SET
                        payload_json = excluded.payload_json, updated_at = excluded.updated_at
                    """,
                    (
                        row["entity_type"], row["entity_key"], row["metric"], row["bucket_type"], row["bucket_key"],
                        json.dumps(row["payload"], sort_keys=True), now_iso,
                    ),
                )
            for row in audit_rows:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO behavior_baseline_window_audit (
                        window_start, window_end, entity_type, entity_key, classification, reason, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["window_start"], row["window_end"], row["entity_type"],
                        row["entity_key"], row["classification"], row["reason"], now_iso,
                    ),
                )
            for row in counter_rows:
                conn.execute(
                    """
                    INSERT INTO behavior_baseline_hour_counters (
                        hour, entity_type, entity_key, eligible, quarantined, rejected, insufficient, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(hour, entity_type, entity_key) DO UPDATE SET
                        eligible = eligible + excluded.eligible,
                        quarantined = quarantined + excluded.quarantined,
                        rejected = rejected + excluded.rejected,
                        insufficient = insufficient + excluded.insufficient,
                        updated_at = excluded.updated_at
                    """,
                    (
                        row["hour"], row["entity_type"], row["entity_key"],
                        row["eligible"], row["quarantined"], row["rejected"], row["insufficient"], now_iso,
                    ),
                )
            conn.execute(
                """
                INSERT INTO behavior_baseline_runtime_state (id, last_processed_minute, last_success_at, last_error, updated_at)
                VALUES (1, ?, ?, '', ?)
                ON CONFLICT(id) DO UPDATE SET
                    last_processed_minute = excluded.last_processed_minute,
                    last_success_at = excluded.last_success_at,
                    last_error = '',
                    updated_at = excluded.updated_at
                """,
                (_iso(last_minute), now_iso, now_iso),
            )
            conn.execute(
                """
                INSERT INTO behavior_baseline_processed_chunks (
                    chunk_id, chunk_start, chunk_end, status, started_at, completed_at,
                    windows_processed, runtime_seconds, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _chunk_id(chunk_start, chunk_end),
                    _iso(chunk_start),
                    _iso(chunk_end),
                    CHUNK_STATUS_COMPLETED,
                    started_at or now_iso,
                    now_iso,
                    int(windows_processed),
                    float(runtime_seconds),
                    now_iso,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


# --------------------------------------------------------------------------
# Incremental bootstrap (chunked, resumable, load-guarded).
# --------------------------------------------------------------------------

def _host_load_1() -> float:
    try:
        with open("/proc/loadavg", encoding="utf-8") as handle:
            return float(handle.read().split()[0])
    except Exception:
        return 0.0


def _host_disk_used_pct() -> float:
    # Prioriza o filesystem onde o SQLite do GMJ-FLOW vive (volume do host).
    # Dentro do container, "/" e o overlay e NAO reflete o disco real; o
    # volume de dados (ex.: /app/data) e o mount correto a monitorar.
    paths: list[str] = []
    db_path = os.getenv("GMJFLOW_DB_PATH")
    if db_path:
        parent = os.path.dirname(db_path)
        if parent:
            paths.append(parent)
    paths.append("/")
    for path in paths:
        try:
            stat = os.statvfs(path)
            total = stat.f_blocks
            used = total - stat.f_bfree
            return round(100.0 * used / total, 1) if total else 0.0
        except Exception:
            continue
    return 0.0


def _host_mem_available_mb() -> float:
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return float(line.split()[1]) / 1024.0
    except Exception:
        return 0.0
    return 0.0


def _host_iowait_pct() -> float:
    try:
        with open("/proc/stat", encoding="utf-8") as handle:
            first = handle.readline()
        parts = first.split()
        if len(parts) < 6 or parts[0] != "cpu":
            return 0.0
        values = [float(value) for value in parts[1:]]
        total = sum(values)
        if total <= 0:
            return 0.0
        return round(100.0 * values[4] / total, 1)
    except Exception:
        return 0.0


def _ch_has_heavy_query(executor: QueryExecutor, threshold_seconds: float = 30.0) -> bool:
    try:
        rows = executor(
            "SELECT count() AS n FROM system.processes "
            "WHERE query NOT LIKE '%system.processes%' AND elapsed > {t:Float64}",
            {"t": threshold_seconds},
        )
        if not rows:
            return False
        first = rows[0] if isinstance(rows, list) else rows
        value = first.get("n") if isinstance(first, dict) else first
        return bool(value and int(value) > 0)
    except Exception:
        return False


def bootstrap_load_guard(
    executor: QueryExecutor | None = None,
    *,
    max_load: float = 8.0,
    max_disk_used_pct: float = 88.0,
    min_free_memory_mb: float = 500.0,
    max_iowait_pct: float = 60.0,
) -> tuple[bool, str]:
    """Verifica se o host esta saudavel para processar mais um chunk.

    O Behavior Engine e background/shadow e deve ceder prioridade ao
    dataplane e a operacao do GMJ-FLOW.
    """
    load1 = _host_load_1()
    if load1 > max_load:
        return False, "load %.1f > %.1f" % (load1, max_load)
    disk_pct = _host_disk_used_pct()
    if disk_pct > max_disk_used_pct:
        return False, "disk %.1f%% > %.1f%%" % (disk_pct, max_disk_used_pct)
    free_mb = _host_mem_available_mb()
    if free_mb > 0 and free_mb < min_free_memory_mb:
        return False, "memoria disponivel %.0fMB < %.0fMB" % (free_mb, min_free_memory_mb)
    iowait = _host_iowait_pct()
    if iowait > max_iowait_pct:
        return False, "iowait %.1f%% > %.1f%%" % (iowait, max_iowait_pct)
    if executor is not None and _ch_has_heavy_query(executor):
        return False, "clickhouse com query pesada em andamento"
    return True, "ok"


def bootstrap_incremental(
    connection_factory: Callable[[], Any],
    query_executor: QueryExecutor,
    *,
    total_hours: int = 24,
    chunk_hours: int = 1,
    persist: bool = True,
    throttle_seconds: float = 5.0,
    max_load: float = 8.0,
    max_disk_used_pct: float = 88.0,
    now_fn: Callable[[], datetime] = _utc_now,
    closed_window_delay_minutes: int = DEFAULT_CLOSED_WINDOW_DELAY_MINUTES,
    max_chunks: int | None = None,
) -> list[dict[str, Any]]:
    """Bootstrap histórico em chunks de `chunk_hours`, resumível por checkpoint.

    - A origem é `now - total_hours` (primeira execução) ou o checkpoint
      `last_processed_minute` (retomada): chunks concluídos não são relidos.
    - Cada chunk roda build_once(persist=persist, start=..., end=...) e, com
      persist=True, grava o checkpoint via _persist (last_processed_minute).
    - `max_chunks` limita quantos chunks são processados nesta chamada
      (usado para simular uma interrupção controlada no teste de resume).
    - Entre chunks há load guard + pausa; se o host não estiver saudável,
      aborta sem processar os chunks restantes. Nunca roda um range monolítico.
    """
    results: list[dict[str, Any]] = []
    now = _floor_minute(now_fn())
    end_limit = now - timedelta(minutes=closed_window_delay_minutes)
    builder = BaselineBuilder(connection_factory, query_executor, BaselineBuilderConfig(), now_fn=now_fn)
    conn = connection_factory()
    try:
        checkpoint = builder._checkpoint(conn)
    finally:
        conn.close()
    resume_from = checkpoint if checkpoint is not None else (now - timedelta(hours=total_hours))
    resume_from = _floor_minute(resume_from)
    if resume_from >= end_limit:
        print(
            "bootstrap: nada a fazer (origem %s >= fim %s)"
            % (_iso(resume_from), _iso(end_limit)),
            flush=True,
        )
        return results
    cursor = resume_from
    processed = 0
    while cursor < end_limit:
        if max_chunks is not None and processed >= max_chunks:
            print("bootstrap: limite de %d chunks atingido (interrupcao simulada)" % max_chunks, flush=True)
            break
        chunk_start = cursor
        chunk_end = min(cursor + timedelta(hours=chunk_hours), end_limit)
        ok, reason = bootstrap_load_guard(query_executor, max_load=max_load, max_disk_used_pct=max_disk_used_pct)
        if not ok:
            print(
                "bootstrap load guard: %s (chunk [%s, %s] adiado)"
                % (reason, _iso(chunk_start), _iso(chunk_end)),
                flush=True,
            )
            time.sleep(throttle_seconds * 4)
            ok, reason = bootstrap_load_guard(query_executor, max_load=max_load, max_disk_used_pct=max_disk_used_pct)
            if not ok:
                print("bootstrap load guard: ainda bloqueado; abortando bootstrap (%s)" % reason, flush=True)
                break
        report = builder.build_once(persist=persist, start=chunk_start, end=chunk_end)
        results.append({"chunk_start": _iso(chunk_start), "chunk_end": _iso(chunk_end), **report})
        print(
            "bootstrap chunk [%s, %s]: queries=%s query_s=%ss runtime=%ss windows=%s eligible=%s"
            % (
                _iso(chunk_start),
                _iso(chunk_end),
                report.get("queries_executed"),
                report.get("query_runtime_seconds"),
                report.get("runtime_seconds"),
                report.get("windows_processed"),
                report.get("eligible"),
            ),
            flush=True,
        )
        cursor = chunk_end
        processed += 1
        if throttle_seconds > 0:
            time.sleep(throttle_seconds)
    return results


# --------------------------------------------------------------------------
# Continuous SHADOW (incremental, cadence-bound, load-guarded).
# --------------------------------------------------------------------------

def continuous_shadow_cycle(
    connection_factory: Callable[[], Any],
    query_executor: QueryExecutor,
    *,
    closed_window_delay_minutes: int = DEFAULT_CLOSED_WINDOW_DELAY_MINUTES,
    max_load: float = 8.0,
    max_disk_used_pct: float = 88.0,
    min_free_memory_mb: float = 500.0,
    max_iowait_pct: float = 60.0,
    now_fn: Callable[[], datetime] = _utc_now,
    persist: bool = True,
) -> dict[str, Any]:
    """One continuous SHADOW cycle.

    Processes ONLY closed minutes newer than the checkpoint (never re-queries a
    full hour). Returns a compact report whose `status` is one of:
    `completed` / `SKIPPED_ALREADY_PROCESSED` / `SKIPPED_LOAD_GUARD` /
    `NO_NEW_MINUTES`.
    """
    now = _floor_minute(now_fn())
    end = now - timedelta(minutes=closed_window_delay_minutes)
    builder = BaselineBuilder(
        connection_factory,
        query_executor,
        BaselineBuilderConfig(closed_window_delay_minutes=closed_window_delay_minutes),
        now_fn=now_fn,
    )
    conn = connection_factory()
    try:
        ensure_behavior_engine_schema(conn)
        conn.commit()
        checkpoint = builder._checkpoint(conn)
    finally:
        conn.close()

    if checkpoint is None:
        # No bootstrap checkpoint yet: process only the most recent closed
        # minute. Historical backfill belongs to bootstrap_incremental().
        start = end - timedelta(minutes=1)
        checkpoint_label = ""
    else:
        start = _floor_minute(checkpoint)
        checkpoint_label = _iso(checkpoint)

    base: dict[str, Any] = {
        "status": "",
        "checkpoint": checkpoint_label,
        "window_range": {"start": _iso(start), "end": _iso(end)},
    }
    if start >= end:
        base["status"] = NO_NEW_MINUTES
        return base

    ok, reason = bootstrap_load_guard(
        query_executor,
        max_load=max_load,
        max_disk_used_pct=max_disk_used_pct,
        min_free_memory_mb=min_free_memory_mb,
        max_iowait_pct=max_iowait_pct,
    )
    if not ok:
        base["status"] = SKIPPED_LOAD_GUARD
        base["reason"] = reason
        return base

    report = builder.build_once(persist=persist, start=start, end=end)
    report["status"] = report.get("chunk_status") or CHUNK_STATUS_COMPLETED
    report["checkpoint"] = checkpoint_label
    return report


def continuous_shadow(
    connection_factory: Callable[[], Any],
    query_executor: QueryExecutor,
    *,
    cadence_minutes: int = 5,
    max_cycles: int | None = None,
    closed_window_delay_minutes: int = DEFAULT_CLOSED_WINDOW_DELAY_MINUTES,
    max_load: float = 8.0,
    max_disk_used_pct: float = 88.0,
    min_free_memory_mb: float = 500.0,
    max_iowait_pct: float = 60.0,
    now_fn: Callable[[], datetime] = _utc_now,
    persist: bool = True,
) -> list[dict[str, Any]]:
    """SHADOW continuous loop with a fixed cadence.

    Each cycle processes only minutes newer than the checkpoint; a load-guard
    trigger simply skips the cycle (no aggressive retry) and the next cycle is
    tried after `cadence_minutes`.
    """
    results: list[dict[str, Any]] = []
    cycle = 0
    while max_cycles is None or cycle < max_cycles:
        report = continuous_shadow_cycle(
            connection_factory,
            query_executor,
            closed_window_delay_minutes=closed_window_delay_minutes,
            max_load=max_load,
            max_disk_used_pct=max_disk_used_pct,
            min_free_memory_mb=min_free_memory_mb,
            max_iowait_pct=max_iowait_pct,
            now_fn=now_fn,
            persist=persist,
        )
        results.append(report)
        print(
            "continuous cycle %d: status=%s [%s, %s] windows=%s eligible=%s queries=%s runtime=%ss"
            % (
                cycle + 1,
                report.get("status"),
                (report.get("window_range") or {}).get("start"),
                (report.get("window_range") or {}).get("end"),
                report.get("windows_processed"),
                report.get("eligible"),
                report.get("queries_executed"),
                report.get("runtime_seconds"),
            ),
            flush=True,
        )
        cycle += 1
        if max_cycles is not None and cycle >= max_cycles:
            break
        time.sleep(max(1, int(cadence_minutes)) * 60)
    return results


# --------------------------------------------------------------------------
# CLI (manual shadow execution; dry-run is the default).
# --------------------------------------------------------------------------

def build_report_from_args(argv: Sequence[str] | None = None) -> dict[str, Any]:
    parser = argparse.ArgumentParser(description="Behavior Baseline Builder (shadow) — E2.2")
    parser.add_argument("--build-once", action="store_true", help="run one build cycle")
    parser.add_argument("--bootstrap", action="store_true", help="run incremental chunked bootstrap (resumable)")
    parser.add_argument("--total-hours", type=int, default=DEFAULT_BOOTSTRAP_HOURS, help="total lookback hours for bootstrap")
    parser.add_argument("--chunk-hours", type=int, default=1, help="hours per bootstrap chunk")
    parser.add_argument("--throttle-seconds", type=float, default=5.0, help="pause between chunks")
    parser.add_argument("--max-load", type=float, default=8.0, help="abort chunk if 1-min load average exceeds this")
    parser.add_argument("--max-disk-pct", type=float, default=88.0, help="abort chunk if disk usage % exceeds this")
    parser.add_argument("--dry-run", action="store_true", help="compute without persisting (default)")
    parser.add_argument("--commit", action="store_true", help="persist snapshots/audit/checkpoint (explicit opt-in)")
    parser.add_argument("--hours", type=int, default=DEFAULT_BOOTSTRAP_HOURS, help="bootstrap lookback hours for --build-once")
    parser.add_argument("--closed-delay-minutes", type=int, default=DEFAULT_CLOSED_WINDOW_DELAY_MINUTES)
    parser.add_argument("--min-bucket-samples", type=int, default=DEFAULT_MIN_BUCKET_SAMPLES)
    parser.add_argument("--quarantine-z", type=float, default=DEFAULT_QUARANTINE_Z)
    parser.add_argument("--continuous", action="store_true", help="run the SHADOW continuous loop")
    parser.add_argument("--cadence-minutes", type=int, default=5, help="pause between continuous cycles")
    parser.add_argument("--max-cycles", type=int, default=None, help="stop continuous after N cycles")
    parser.add_argument("--min-free-memory-mb", type=float, default=500.0, help="skip cycle if free memory below this")
    parser.add_argument("--max-iowait-pct", type=float, default=60.0, help="skip cycle if iowait % exceeds this")
    args = parser.parse_args(argv)
    persist = bool(args.commit) and not args.dry_run
    config = BaselineBuilderConfig(
        bootstrap_hours=args.hours,
        closed_window_delay_minutes=args.closed_delay_minutes,
        min_bucket_samples=args.min_bucket_samples,
        quarantine_z=args.quarantine_z,
    )
    from app.services.clickhouse import query_clickhouse, sqlite_connection

    if args.continuous:
        results = continuous_shadow(
            sqlite_connection,
            query_clickhouse,
            cadence_minutes=args.cadence_minutes,
            max_cycles=args.max_cycles,
            closed_window_delay_minutes=args.closed_delay_minutes,
            max_load=args.max_load,
            max_disk_used_pct=args.max_disk_pct,
            min_free_memory_mb=args.min_free_memory_mb,
            max_iowait_pct=args.max_iowait_pct,
            persist=persist,
        )
        return {"continuous_cycles": results}

    if args.bootstrap:
        results = bootstrap_incremental(
            sqlite_connection,
            query_clickhouse,
            total_hours=args.total_hours,
            chunk_hours=args.chunk_hours,
            persist=persist,
            throttle_seconds=args.throttle_seconds,
            max_load=args.max_load,
            max_disk_used_pct=args.max_disk_pct,
            closed_window_delay_minutes=args.closed_delay_minutes,
        )
        return {"bootstrap_chunks": results}

    builder = BaselineBuilder(sqlite_connection, query_clickhouse, config)
    report = builder.build_once(persist=persist)
    return report


def main() -> None:
    report = build_report_from_args()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
