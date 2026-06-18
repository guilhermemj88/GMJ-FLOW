CREATE DATABASE IF NOT EXISTS flowdb;

USE flowdb;

CREATE TABLE IF NOT EXISTS flow_raw
(
    flow_time DateTime64(3, 'UTC'),
    received_at DateTime DEFAULT now(),
    sensor LowCardinality(String),
    exporter_ip IPv4,
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    proto UInt8,
    tcp_flags UInt16,
    input_if UInt32,
    output_if UInt32,
    bytes UInt64,
    packets UInt64,
    flow_count UInt64 DEFAULT 1
)
ENGINE = MergeTree
PARTITION BY toDate(flow_time)
ORDER BY (sensor, flow_time, src_ip, dst_ip, proto, dst_port)
TTL toDateTime(flow_time) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS flow_1m
(
    minute DateTime('UTC'),
    sensor LowCardinality(String),
    exporter_ip IPv4,
    input_if UInt32,
    output_if UInt32,
    proto UInt8,
    bytes UInt64,
    packets UInt64,
    flows UInt64
)
ENGINE = SummingMergeTree((bytes, packets, flows))
PARTITION BY toYYYYMM(minute)
ORDER BY (sensor, minute, exporter_ip, input_if, output_if, proto);

CREATE TABLE IF NOT EXISTS flow_tops_1m
(
    minute DateTime('UTC'),
    sensor LowCardinality(String),
    dimension LowCardinality(String),
    key String,
    bytes UInt64,
    packets UInt64,
    flows UInt64
)
ENGINE = SummingMergeTree((bytes, packets, flows))
PARTITION BY toYYYYMM(minute)
ORDER BY (dimension, sensor, minute, key);

CREATE TABLE IF NOT EXISTS prefix_traffic_1m
(
    minute DateTime('UTC'),
    sensor LowCardinality(String),
    customer_id String,
    customer_name String,
    prefix String,
    direction LowCardinality(String),
    bytes UInt64,
    packets UInt64,
    flows UInt64
)
ENGINE = SummingMergeTree((bytes, packets, flows))
PARTITION BY toYYYYMM(minute)
ORDER BY (sensor, minute, customer_id, prefix, direction);

CREATE TABLE IF NOT EXISTS anomaly_events
(
    id UUID DEFAULT generateUUIDv4(),
    event_time DateTime('UTC'),
    sensor LowCardinality(String),
    severity LowCardinality(String),
    kind LowCardinality(String),
    message String,
    metric_name String,
    metric_value Float64,
    threshold Float64,
    src_ip Nullable(IPv4),
    dst_ip Nullable(IPv4),
    status LowCardinality(String) DEFAULT 'open',
    created_at DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (sensor, event_time, severity, kind);

CREATE TABLE IF NOT EXISTS sensors
(
    sensor String,
    description String,
    exporter_ip IPv4,
    enabled UInt8 DEFAULT 1,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY sensor;

CREATE TABLE IF NOT EXISTS sensor_interfaces
(
    sensor String,
    if_index UInt32,
    if_name String,
    if_alias String,
    speed_bps UInt64,
    enabled UInt8 DEFAULT 1,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (sensor, if_index);

CREATE TABLE IF NOT EXISTS customer_prefixes
(
    customer_id String,
    customer_name String,
    prefix String,
    description String,
    enabled UInt8 DEFAULT 1,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (customer_id, prefix);

CREATE TABLE IF NOT EXISTS retention_settings
(
    table_name String,
    retention_days UInt16,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY table_name;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flow_raw_to_1m TO flow_1m AS
SELECT
    toStartOfMinute(flow_time) AS minute,
    sensor,
    exporter_ip,
    input_if,
    output_if,
    proto,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flow_count) AS flows
FROM flow_raw
GROUP BY
    minute,
    sensor,
    exporter_ip,
    input_if,
    output_if,
    proto;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flow_tops_src_ip TO flow_tops_1m AS
SELECT
    toStartOfMinute(flow_time) AS minute,
    sensor,
    'src_ip' AS dimension,
    toString(src_ip) AS key,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flow_count) AS flows
FROM flow_raw
GROUP BY minute, sensor, key;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flow_tops_dst_ip TO flow_tops_1m AS
SELECT
    toStartOfMinute(flow_time) AS minute,
    sensor,
    'dst_ip' AS dimension,
    toString(dst_ip) AS key,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flow_count) AS flows
FROM flow_raw
GROUP BY minute, sensor, key;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flow_tops_dst_port TO flow_tops_1m AS
SELECT
    toStartOfMinute(flow_time) AS minute,
    sensor,
    'dst_port' AS dimension,
    toString(dst_port) AS key,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flow_count) AS flows
FROM flow_raw
GROUP BY minute, sensor, key;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flow_tops_proto TO flow_tops_1m AS
SELECT
    toStartOfMinute(flow_time) AS minute,
    sensor,
    'proto' AS dimension,
    toString(proto) AS key,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flow_count) AS flows
FROM flow_raw
GROUP BY minute, sensor, key;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flow_tops_tcp_flags TO flow_tops_1m AS
SELECT
    toStartOfMinute(flow_time) AS minute,
    sensor,
    'tcp_flags' AS dimension,
    toString(tcp_flags) AS key,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flow_count) AS flows
FROM flow_raw
WHERE proto = 6
GROUP BY minute, sensor, key;

INSERT INTO retention_settings (table_name, retention_days)
SELECT 'flow_raw', 30
WHERE NOT EXISTS (SELECT 1 FROM retention_settings WHERE table_name = 'flow_raw');

INSERT INTO retention_settings (table_name, retention_days)
SELECT 'flow_1m', 180
WHERE NOT EXISTS (SELECT 1 FROM retention_settings WHERE table_name = 'flow_1m');

INSERT INTO sensors (sensor, description, exporter_ip)
SELECT 'edge-01', 'Sensor fake inicial', toIPv4('192.0.2.10')
WHERE NOT EXISTS (SELECT 1 FROM sensors WHERE sensor = 'edge-01');

INSERT INTO sensor_interfaces (sensor, if_index, if_name, if_alias, speed_bps)
SELECT 'edge-01', 1, 'wan0', 'Upstream', 10000000000
WHERE NOT EXISTS (SELECT 1 FROM sensor_interfaces WHERE sensor = 'edge-01' AND if_index = 1);

INSERT INTO sensor_interfaces (sensor, if_index, if_name, if_alias, speed_bps)
SELECT 'edge-01', 2, 'lan0', 'Clientes', 10000000000
WHERE NOT EXISTS (SELECT 1 FROM sensor_interfaces WHERE sensor = 'edge-01' AND if_index = 2);
