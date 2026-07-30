from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, ip_address
from typing import Any


DASHBOARD_AGGREGATE_TABLES = {
    "series": "flow_dashboard_series_1m",
    "src_ip": "flow_dashboard_src_ip_1m",
    "dst_ip": "flow_dashboard_dst_ip_1m",
    "dst_port": "flow_dashboard_dst_port_1m",
    "protocol": "flow_dashboard_protocol_1m",
    "asn_src": "flow_dashboard_asn_src_1m",
    "asn_dst": "flow_dashboard_asn_dst_1m",
    # Versioned because the original aggregate mixed flags from non-TCP
    # traffic. A new table avoids serving already-contaminated historical
    # rows while the corrected materialized view is populated.
    "tcp_flags": "flow_dashboard_tcp_flags_tcp_1m",
    # Prefix-aware aggregate keeps the minimum dimensions required to apply
    # source/destination CIDR or range predicates before ranking/grouping.
    # It is minute-granular and does not duplicate individual flow rows.
    "prefix": "flow_dashboard_prefix_1m",
    "syn": "flow_dashboard_syn_1m",
    "conversations": "flow_dashboard_conversations_1m",
}


def _summable_table(name: str, dimensions: list[tuple[str, str]]) -> str:
    columns = [
        "minute DateTime('UTC')",
        "sensor LowCardinality(String)",
        "exporter_ip String",
        "input_if UInt32",
        "output_if UInt32",
        "sample_rate UInt32",
        *[f"{column} {data_type}" for column, data_type in dimensions],
        "bytes UInt64",
        "packets UInt64",
        "flows UInt64",
    ]
    order = [
        "sensor",
        "minute",
        "exporter_ip",
        "input_if",
        "output_if",
        "sample_rate",
        *[column for column, _data_type in dimensions],
    ]
    return f"""
    CREATE TABLE IF NOT EXISTS {name}
    (
        {", ".join(columns)}
    )
    ENGINE = SummingMergeTree((bytes, packets, flows))
    PARTITION BY toYYYYMM(minute)
    ORDER BY ({", ".join(order)})
    TTL toDateTime(minute) + INTERVAL 30 DAY DELETE
    """


def _summable_view(
    view_name: str,
    table_name: str,
    dimensions: list[tuple[str, str]],
    *,
    where: str = "",
) -> str:
    dimension_selects = [expression for _name, expression in dimensions]
    dimension_names = [name for name, _expression in dimensions]
    where_sql = f"WHERE {where}" if where else ""
    return f"""
    CREATE MATERIALIZED VIEW IF NOT EXISTS {view_name} TO {table_name} AS
    SELECT
        toStartOfMinute(flow_time) AS minute,
        sensor,
        toString(exporter_ip) AS exporter_ip,
        input_if,
        output_if,
        sample_rate,
        {", ".join(dimension_selects)},
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flow_count) AS flows
    FROM flow_raw
    {where_sql}
    GROUP BY
        minute, sensor, exporter_ip, input_if, output_if, sample_rate,
        {", ".join(dimension_names)}
    """


def dashboard_aggregate_schema_statements() -> tuple[str, ...]:
    definitions: list[str] = [
        """
        CREATE TABLE IF NOT EXISTS dashboard_sample_rate_config
        (
            exporter_ip String,
            if_index UInt32,
            direction UInt8,
            sample_rate UInt32,
            active UInt8,
            updated_at DateTime64(6, 'UTC')
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY (exporter_ip, if_index, direction)
        """,
        """
        CREATE VIEW IF NOT EXISTS dashboard_sample_rate_current AS
        SELECT
            exporter_ip,
            if_index,
            direction,
            argMax(sample_rate, updated_at) AS sample_rate
        FROM dashboard_sample_rate_config
        GROUP BY exporter_ip, if_index, direction
        HAVING argMax(active, updated_at) = 1
        """,
    ]
    layouts = {
        "series": [("proto", "UInt8"), ("tcp_flags", "UInt16")],
        "src_ip": [("src_ip", "IPv6")],
        "dst_ip": [("dst_ip", "IPv6")],
        "dst_port": [("dst_port", "UInt16"), ("proto", "UInt8")],
        "protocol": [("proto", "UInt8")],
        "asn_src": [("src_asn", "UInt32"), ("src_as_name", "String"), ("src_ip", "IPv6")],
        "asn_dst": [("dst_asn", "UInt32"), ("dst_as_name", "String"), ("dst_ip", "IPv6")],
        "tcp_flags": [("tcp_flags", "UInt16"), ("proto", "UInt8")],
        "prefix": [
            ("src_ip", "IPv6"),
            ("dst_ip", "IPv6"),
            ("src_port", "UInt16"),
            ("dst_port", "UInt16"),
            ("proto", "UInt8"),
            ("tcp_flags", "UInt16"),
            ("src_asn", "UInt32"),
            ("dst_asn", "UInt32"),
            ("src_as_name", "String"),
            ("dst_as_name", "String"),
        ],
        "syn": [
            ("src_ip", "IPv6"),
            ("dst_ip", "IPv6"),
            ("proto", "UInt8"),
            ("src_asn", "UInt32"),
            ("dst_asn", "UInt32"),
            ("src_as_name", "String"),
            ("dst_as_name", "String"),
            ("tcp_flags", "UInt16"),
        ],
    }
    view_expressions = {
        "series": [("proto", "proto AS proto"), ("tcp_flags", "tcp_flags AS tcp_flags")],
        "src_ip": [("src_ip", "src_ip AS src_ip")],
        "dst_ip": [("dst_ip", "dst_ip AS dst_ip")],
        "dst_port": [("dst_port", "dst_port AS dst_port"), ("proto", "proto AS proto")],
        "protocol": [("proto", "proto AS proto")],
        "asn_src": [
            ("src_asn", "src_asn AS src_asn"),
            ("src_as_name", "src_as_name AS src_as_name"),
            ("src_ip", "src_ip AS src_ip"),
        ],
        "asn_dst": [
            ("dst_asn", "dst_asn AS dst_asn"),
            ("dst_as_name", "dst_as_name AS dst_as_name"),
            ("dst_ip", "dst_ip AS dst_ip"),
        ],
        "tcp_flags": [
            ("tcp_flags", "tcp_flags AS tcp_flags"),
            ("proto", "proto AS proto"),
        ],
        "prefix": [
            ("src_ip", "src_ip AS src_ip"),
            ("dst_ip", "dst_ip AS dst_ip"),
            ("src_port", "src_port AS src_port"),
            ("dst_port", "dst_port AS dst_port"),
            ("proto", "proto AS proto"),
            ("tcp_flags", "tcp_flags AS tcp_flags"),
            ("src_asn", "src_asn AS src_asn"),
            ("dst_asn", "dst_asn AS dst_asn"),
            ("src_as_name", "src_as_name AS src_as_name"),
            ("dst_as_name", "dst_as_name AS dst_as_name"),
        ],
        "syn": [
            ("src_ip", "src_ip AS src_ip"),
            ("dst_ip", "dst_ip AS dst_ip"),
            ("proto", "proto AS proto"),
            ("src_asn", "src_asn AS src_asn"),
            ("dst_asn", "dst_asn AS dst_asn"),
            ("src_as_name", "src_as_name AS src_as_name"),
            ("dst_as_name", "dst_as_name AS dst_as_name"),
            ("tcp_flags", "tcp_flags AS tcp_flags"),
        ],
    }
    for key, dimensions in layouts.items():
        table = DASHBOARD_AGGREGATE_TABLES[key]
        definitions.append(_summable_table(table, dimensions))
        definitions.append(
            _summable_view(
                f"mv_{table}",
                table,
                view_expressions[key],
                where=(
                    "proto = 6 AND bitAnd(tcp_flags, 2) != 0 "
                    "AND bitAnd(tcp_flags, 16) = 0"
                    if key == "syn"
                    else "proto = 6"
                    if key == "tcp_flags"
                    else ""
                ),
            )
        )

    conversation_table = DASHBOARD_AGGREGATE_TABLES["conversations"]
    definitions.extend(
        [
            f"""
            CREATE TABLE IF NOT EXISTS {conversation_table}
            (
                minute DateTime('UTC'),
                sensor LowCardinality(String),
                exporter_ip String,
                input_if UInt32,
                output_if UInt32,
                sample_rate UInt32,
                src_ip IPv6,
                dst_ip IPv6,
                src_port UInt16,
                dst_port UInt16,
                proto UInt8,
                src_asn UInt32,
                dst_asn UInt32,
                src_as_name String,
                dst_as_name String,
                bytes SimpleAggregateFunction(sum, UInt64),
                packets SimpleAggregateFunction(sum, UInt64),
                flows SimpleAggregateFunction(sum, UInt64),
                first_seen SimpleAggregateFunction(min, DateTime64(3, 'UTC')),
                last_seen SimpleAggregateFunction(max, DateTime64(3, 'UTC'))
            )
            ENGINE = AggregatingMergeTree
            PARTITION BY toYYYYMM(minute)
            ORDER BY (
                sensor, minute, exporter_ip, input_if, output_if, sample_rate,
                src_ip, dst_ip, src_port, dst_port, proto,
                src_asn, dst_asn, src_as_name, dst_as_name
            )
            TTL toDateTime(minute) + INTERVAL 30 DAY DELETE
            """,
            f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS mv_{conversation_table}
            TO {conversation_table} AS
            SELECT
                toStartOfMinute(flow_time) AS minute,
                sensor,
                toString(exporter_ip) AS exporter_ip,
                input_if,
                output_if,
                sample_rate,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto,
                src_asn,
                dst_asn,
                src_as_name,
                dst_as_name,
                sum(bytes) AS bytes,
                sum(packets) AS packets,
                sum(flow_count) AS flows,
                min(flow_time) AS first_seen,
                max(flow_time) AS last_seen
            FROM flow_raw
            GROUP BY
                minute, sensor, exporter_ip, input_if, output_if, sample_rate,
                src_ip, dst_ip, src_port, dst_port, proto,
                src_asn, dst_asn, src_as_name, dst_as_name
            """,
        ]
    )
    return tuple(" ".join(statement.split()) for statement in definitions)


def aggregate_boundaries(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    start_utc = start.astimezone(timezone.utc)
    end_utc = end.astimezone(timezone.utc)
    floor_start = start_utc.replace(second=0, microsecond=0)
    interior_start = floor_start if start_utc == floor_start else floor_start + timedelta(minutes=1)
    interior_end = end_utc.replace(second=0, microsecond=0)
    return interior_start, interior_end


def dashboard_sample_rate_join_sql(source_alias: str = "source") -> str:
    return f"""
    LEFT ANY JOIN dashboard_sample_rate_current AS sr_input
        ON sr_input.exporter_ip = toString({source_alias}.exporter_ip)
       AND sr_input.if_index = {source_alias}.input_if
       AND sr_input.direction = 1
    LEFT ANY JOIN dashboard_sample_rate_current AS sr_input_default
        ON sr_input_default.exporter_ip = toString({source_alias}.exporter_ip)
       AND sr_input_default.if_index = 0
       AND sr_input_default.direction = 1
    LEFT ANY JOIN dashboard_sample_rate_current AS sr_output
        ON sr_output.exporter_ip = toString({source_alias}.exporter_ip)
       AND sr_output.if_index = {source_alias}.output_if
       AND sr_output.direction = 2
    LEFT ANY JOIN dashboard_sample_rate_current AS sr_output_default
        ON sr_output_default.exporter_ip = toString({source_alias}.exporter_ip)
       AND sr_output_default.if_index = 0
       AND sr_output_default.direction = 2
    """


def dashboard_effective_sample_rate_expr(
    direction: str,
    source_alias: str = "source",
) -> str:
    fallback = f"greatest(toFloat64({source_alias}.sample_rate), 1.0)"
    nullable_zero = "CAST(NULL, 'Nullable(Float64)')"
    input_rate = (
        f"coalesce(nullIf(toFloat64(sr_input.sample_rate), 0.0), "
        f"nullIf(toFloat64(sr_input_default.sample_rate), 0.0), {fallback})"
    )
    output_rate = (
        f"coalesce(nullIf(toFloat64(sr_output.sample_rate), 0.0), "
        f"nullIf(toFloat64(sr_output_default.sample_rate), 0.0), {fallback})"
    )
    if direction == "input":
        return input_rate
    if direction == "output":
        return output_rate
    return (
        "coalesce("
        f"if({source_alias}.input_if > 0, {input_rate}, {nullable_zero}), "
        f"if({source_alias}.output_if > 0, {output_rate}, {nullable_zero}), "
        f"{fallback})"
    )


def effective_sample_rate_from_rows(
    sample_rate: int,
    input_if: int,
    output_if: int,
    direction: str,
    rows: dict[tuple[int, int], int],
) -> int:
    """Python reference for the SQL join expression used by equivalence tests.

    ``rows`` uses ``(if_index, direction)`` where direction is 1=input and
    2=output. Index zero stores the sensor default.
    """
    fallback = max(1, int(sample_rate or 1))
    if direction in {"input", "auto"} and input_if > 0:
        return max(1, int(rows.get((input_if, 1), rows.get((0, 1), fallback))))
    if direction in {"output", "auto"} and output_if > 0:
        return max(1, int(rows.get((output_if, 2), rows.get((0, 2), fallback))))
    return fallback


def sample_rate_config_rows(configs: list[dict[str, Any]]) -> list[tuple[str, int, int, int, int]]:
    rows: list[tuple[str, int, int, int, int]] = []
    for config in configs:
        exporter_ip = str(config.get("exporter_ip") or "").strip()
        if not exporter_ip:
            continue
        try:
            parsed_exporter = ip_address(exporter_ip)
        except ValueError:
            continue
        if isinstance(parsed_exporter, IPv4Address):
            exporter_ip = f"::ffff:{parsed_exporter}"
        elif getattr(parsed_exporter, "ipv4_mapped", None):
            exporter_ip = f"::ffff:{parsed_exporter.ipv4_mapped}"
        else:
            exporter_ip = str(parsed_exporter)
        rows.append((exporter_ip, 0, 1, max(1, int(config.get("default_in") or 1)), 1))
        rows.append((exporter_ip, 0, 2, max(1, int(config.get("default_out") or 1)), 1))
        interfaces = config.get("interfaces") if isinstance(config.get("interfaces"), dict) else {}
        for if_index, interface in interfaces.items():
            default_in = max(1, int(config.get("default_in") or 1))
            default_out = max(1, int(config.get("default_out") or 1))
            override = bool(interface.get("override")) or config.get("mode") == "per_interface"
            rows.append(
                (
                    exporter_ip,
                    int(if_index),
                    1,
                    max(1, int(interface.get("in") or default_in)) if override else default_in,
                    1,
                )
            )
            rows.append(
                (
                    exporter_ip,
                    int(if_index),
                    2,
                    max(1, int(interface.get("out") or default_out)) if override else default_out,
                    1,
                )
            )
    return rows
