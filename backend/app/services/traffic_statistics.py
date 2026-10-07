"""Read-only ClickHouse analytics; isolated SQLite derived-data persistence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
import logging
import os
from pathlib import Path
import threading
import time
import zlib

import clickhouse_connect

from app.services.dashboard_cache import DashboardCacheConfig, MemoryDashboardCache
from app.services.sqlite_managed import open_managed
from app.services.traffic_statistics_math import (
    CONFIG,
    baseline,
    baseline_coverage,
    benford_test,
    entropy_from_aggregates,
    ks_test,
    overall,
)

WINDOWS = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600}
FIELDS = {
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "src_port": "src_port",
    "dst_port": "dst_port",
    "protocol": "proto",
    "tcp_flags": "tcp_flags",
    "src_asn": "src_asn",
    "src_country": "src_country",
    "input_interface": "input_if",
    "output_interface": "output_if",
}
METRICS = {
    "bytes_per_flow": "toFloat64(bytes)",
    "packets_per_flow": "toFloat64(packets)",
    "avg_packet_size": "bytes / nullIf(packets, 0)",
}
QUERY_SETTINGS = {
    "readonly": 1,
    "max_threads": 2,
    "max_execution_time": 15,
    "max_memory_usage": 536870912,
    "max_rows_to_read": 100000000,
    "read_overflow_mode": "throw",
    "timeout_overflow_mode": "throw",
}
LOGGER = logging.getLogger("gmj-flow.statistics")


@dataclass(frozen=True)
class Scope:
    type: str = "global"
    id: str = ""
    sensor: str = ""
    exporter: str = ""
    direction: str = "both"

    def __post_init__(self):
        if self.type not in {"global", "target", "interface"}:
            raise ValueError("scopeType must be global, target or interface")
        if len(self.sensor) > 128 or self.direction not in {"both", "input", "output"}:
            raise ValueError("Invalid sensor or direction")
        if self.type == "global" and self.id:
            raise ValueError("Global scope must not have scopeId")
        if self.type == "target":
            object.__setattr__(self, "id", str(ip_address(self.id)))
        if self.type == "interface":
            if (
                not self.sensor
                or not self.exporter
                or not self.id.isdecimal()
                or not 0 <= int(self.id) <= 4294967295
            ):
                raise ValueError(
                    "Interface requires sensor, exporter and UInt32 scopeId"
                )
            object.__setattr__(self, "id", str(int(self.id)))
        if self.exporter:
            object.__setattr__(self, "exporter", str(ip_address(self.exporter)))

    @property
    def key(self):
        return json.dumps(asdict(self), sort_keys=True)


def window_seconds(value):
    if value not in WINDOWS:
        raise ValueError("window must be 1m, 5m, 15m or 1h")
    return WINDOWS[value]


def create_client():
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "flowdb"),
        connect_timeout=5,
        send_receive_timeout=20,
    )


class StatisticsStore:
    def __init__(self, path=None):
        self.path = (
            path
            or os.getenv("GMJFLOW_STATISTICS_DB_PATH")
            or str(
                Path(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db")).with_name(
                    "traffic-statistics.db"
                )
            )
        )
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS threat_statistics_windows (
                    scope TEXT NOT NULL, seconds INTEGER NOT NULL, mode TEXT NOT NULL,
                    end INTEGER NOT NULL, payload TEXT NOT NULL,
                    PRIMARY KEY(scope, seconds, mode, end));
                CREATE TABLE IF NOT EXISTS threat_statistics_samples (
                    scope TEXT NOT NULL, seconds INTEGER NOT NULL, end INTEGER NOT NULL,
                    payload BLOB NOT NULL, PRIMARY KEY(scope, seconds, end));
                CREATE INDEX IF NOT EXISTS threat_statistics_windows_retention ON threat_statistics_windows(end);
                CREATE INDEX IF NOT EXISTS threat_statistics_samples_retention ON threat_statistics_samples(end);
                PRAGMA user_version=1;
            """)

    def connect(self):
        conn = open_managed(self.path)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def history(
        self, scope, seconds, mode, lower, upper, nonoverlapping=False, compact=False
    ):
        with self.connect() as conn:
            alignment = " AND end % seconds = 0" if nonoverlapping else ""
            projection = (
                "json_object('window',json_extract(payload,'$.window'),"
                "'scope',json_extract(payload,'$.scope'),'entropy',json_extract(payload,'$.entropy'))"
                if compact
                else "payload"
            )
            rows = conn.execute(
                f"SELECT {projection} FROM threat_statistics_windows WHERE scope=? AND seconds=? AND mode=? AND end>=? AND end<=?"
                + alignment
                + " ORDER BY end",
                (scope.key, seconds, mode, lower, upper),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def samples(self, scope, seconds, lower, upper):
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM threat_statistics_samples WHERE scope=? AND seconds=? AND end>=? AND end<=? ORDER BY end",
                (scope.key, seconds, lower, upper),
            ).fetchall()
        values = []
        for row in rows:
            values.extend(json.loads(zlib.decompress(row[0])))
        # Small persisted stratified reservoir, never historical raw-flow scans.
        values.sort(key=lambda x: hashlib.sha256(str(x[0]).encode()).digest())
        return values[: CONFIG.baseline_sample_limit]

    def save(self, scope, seconds, mode, end, payload, samples):
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO threat_statistics_windows VALUES(?,?,?,?,?)",
                (scope.key, seconds, mode, end, json.dumps(payload, allow_nan=False)),
            )
            # Persist only non-overlapping windows, at most 512 observations per window.
            if end % seconds == 0:
                rows = sorted(
                    samples, key=lambda x: hashlib.sha256(str(x[0]).encode()).digest()
                )[:512]
                conn.execute(
                    "INSERT OR IGNORE INTO threat_statistics_samples VALUES(?,?,?,?)",
                    (
                        scope.key,
                        seconds,
                        end,
                        zlib.compress(json.dumps(rows, allow_nan=False).encode()),
                    ),
                )
            cutoff = end - 8 * 86400
            conn.execute("DELETE FROM threat_statistics_windows WHERE end<?", (cutoff,))
            conn.execute("DELETE FROM threat_statistics_samples WHERE end<?", (cutoff,))


class StatisticsService:
    def __init__(self, store=None, client_factory=create_client):
        self.store = store or StatisticsStore()
        self.client_factory = client_factory
        self.lock = threading.Lock()
        self.cache = MemoryDashboardCache(
            DashboardCacheConfig(max_entries=64, max_item_bytes=8 * 1024 * 1024)
        )

    def summary(self, scope, window="5m", mode="PACKET_WEIGHTED", end=None):
        seconds = window_seconds(window)
        if mode not in {"PACKET_WEIGHTED", "FLOW_WEIGHTED"}:
            raise ValueError("Invalid weightMode")
        # Last completed minute; never label a partial minute as complete.
        end = int(end if end is not None else time.time()) // 60 * 60
        with self.lock:
            existing = self.store.history(scope, seconds, mode, end, end)
            if existing:
                return existing[0]
            return self._compute(scope, window, seconds, mode, end)

    def _compute(self, scope, window, seconds, mode, end):
        timings = {}
        client = self.client_factory()

        def query(name, sql, params=None):
            started = time.monotonic()
            try:
                return client.query(
                    sql, parameters=params or {}, settings=QUERY_SETTINGS
                ).result_rows
            finally:
                timings[name] = round((time.monotonic() - started) * 1000, 2)

        try:
            columns = {r[0]: r[1] for r in query("schema", "DESCRIBE TABLE flow_raw")}
            fields = {k: v for k, v in FIELDS.items() if v in columns}
            metrics = dict(METRICS)
            duration = None
            if "duration_ms" in columns:
                duration = "nullIf(toFloat64(duration_ms), 0) / 1000"
            if {"flow_start", "flow_end"} <= columns.keys():
                real = "if(flow_end > flow_start, dateDiff('millisecond', flow_start, flow_end)/1000., NULL)"
                duration = f"coalesce({duration}, {real})" if duration else real
            if duration:
                metrics.update(
                    flow_duration=duration,
                    bps_per_flow=f"bytes * 8. / ({duration})",
                    pps_per_flow=f"packets / ({duration})",
                )
            params = dict(
                start=end - seconds,
                end=end,
                sensor=scope.sensor,
                exporter=scope.exporter,
                target=scope.id,
            )
            filters = [
                "flow_time >= fromUnixTimestamp({start:UInt32})",
                "flow_time < fromUnixTimestamp({end:UInt32})",
            ]
            if "time_classification" in columns:
                filters.append("time_classification = 'VALID_TIME'")
            if scope.sensor:
                filters.append("sensor = {sensor:String}")
            if scope.exporter:
                filters.append("exporter_ip = toIPv6({exporter:String})")
            if scope.type == "target":
                filters.append(
                    "(src_ip = toIPv6({target:String}) OR dst_ip = toIPv6({target:String}))"
                )
            if scope.type == "interface":
                params["interface"] = int(scope.id)
                sides = (
                    ["input_if", "output_if"]
                    if scope.direction == "both"
                    else [scope.direction + "_if"]
                )
                filters.append(
                    "("
                    + " OR ".join(f"{s} = {{interface:UInt32}}" for s in sides)
                    + ")"
                )
            where = " AND ".join(filters)
            entropy = []
            # Do not let overlapping sliding windows dominate the robust baseline.
            history = self.store.history(
                scope,
                seconds,
                mode,
                end - CONFIG.baseline_days * 86400 + seconds,
                end - seconds,
                nonoverlapping=True,
                compact=True,
            )
            weights = (
                "sum(toFloat64(packets))"
                if mode == "PACKET_WEIGHTED"
                else "toFloat64(count())"
            )
            for field, column in fields.items():
                valid = f"isNotNull({column})"
                if field in {"src_asn", "input_interface", "output_interface"}:
                    valid += f" AND {column} > 0"
                if field == "src_country":
                    valid += f" AND {column} != ''"
                rows = query(
                    "entropy_" + field,
                    f"""SELECT sum(n), count(), sum(n*log2(n)) FROM
                    (SELECT {column}, {weights} AS n FROM flow_raw PREWHERE {where}
                     WHERE {valid} GROUP BY {column} HAVING n > 0)""",
                    params,
                )
                item = dict(
                    field=field, weight_mode=mode, **entropy_from_aggregates(*rows[0])
                )
                previous = [
                    x["entropy_normalized"]
                    for h in history
                    for x in h["entropy"]
                    if x["field"] == field
                ]
                item.update(baseline(item["entropy_normalized"], previous))
                entropy.append(item)
            count = query(
                "count", f"SELECT count() FROM flow_raw PREWHERE {where}", params
            )[0][0]
            # Hash filter followed by bounded top-k: deterministic and independent of storage order.
            threshold = min(
                2**64 - 1,
                int(
                    (2**64 - 1)
                    * min(1.0, 2 * CONFIG.current_sample_limit / max(count, 1))
                ),
            )
            params.update(threshold=threshold, limit=CONFIG.current_sample_limit)
            hash_expr = "cityHash64(flow_time, sensor, exporter_ip, src_ip, dst_ip, src_port, dst_port, proto, packets, bytes, tcp_flags, input_if, output_if)"
            projection = ", ".join(
                f"{expr} AS {name}" for name, expr in metrics.items()
            )
            samples = (
                query(
                    "sample",
                    f"""SELECT {hash_expr} AS sample_hash, {projection} FROM flow_raw
                PREWHERE {where} WHERE sample_hash <= {{threshold:UInt64}}
                ORDER BY sample_hash LIMIT {{limit:UInt32}}""",
                    params,
                )
                if count
                else []
            )
            samples = [[r[0], dict(zip(metrics, r[1:]))] for r in samples]
            # Reservoir is cached in five-minute epochs; excludes all overlapping current records.
            baseline_upper = (end - seconds) // 300 * 300
            cache_key = f"{scope.key}:{seconds}:{baseline_upper}"
            historical = self.cache.get_or_compute(
                cache_key,
                300,
                lambda: self.store.samples(
                    scope, seconds, end - CONFIG.baseline_days * 86400, baseline_upper
                ),
            )
            ks, benford = [], []
            for metric in metrics:
                current = [row[1].get(metric) for row in samples]
                old = [row[1].get(metric) for row in historical]
                ks.append(dict(metric=metric, **ks_test(current, old)))
                if metric != "avg_packet_size":
                    benford.append(dict(metric=metric, **benford_test(current)))

            def iso(t):
                return datetime.fromtimestamp(t, timezone.utc).isoformat()

            coverage = baseline_coverage(history, end, seconds)
            evidence_complete = all(
                x["anomaly_classification"] not in {"NO_DATA", "NO_BASELINE"}
                for x in entropy
            ) and all(x["statistic"] is not None for x in ks)
            payload = dict(
                window={
                    "name": window,
                    "from": iso(end - seconds),
                    "to": iso(end),
                    "end_epoch": end,
                },
                scope=asdict(scope),
                weight_mode=mode,
                entropy=entropy,
                ks=ks,
                benford=benford,
                overall={
                    "statisticalAnomaly": overall(entropy, ks, benford),
                    "partial_evidence": not evidence_complete,
                    "rule": "maximum_classification; no score; no automatic action",
                },
                baseline={
                    "days_requested": 7,
                    **coverage,
                    "windows": len(history),
                    "from": history[0]["window"]["from"] if history else None,
                    "to": history[-1]["window"]["to"] if history else None,
                },
                sampling={
                    "method": "deterministic_hash_top_k; historical_nonoverlapping_window_reservoir",
                    "flow_records": count,
                    "flow_weighted_definition": "COUNT of stored flow_raw records; not SUM(flow_count)",
                    "current_samples": len(samples),
                    "baseline_samples": len(historical),
                    "historical_per_window_limit": 512,
                    "historical_weighting": "equal time-window strata; not traffic-volume weighted",
                },
                unavailable_fields=sorted(set(FIELDS) - set(fields)),
                query_ms=timings,
                config=json.loads(json.dumps(asdict(CONFIG))),
                read_only=True,
            )
            self.store.save(scope, seconds, mode, end, payload, samples)
            return payload
        finally:
            client.close()


_service = None
_service_lock = threading.Lock()


def get_service():
    global _service
    with _service_lock:
        if _service is None:
            _service = StatisticsService()
    return _service
