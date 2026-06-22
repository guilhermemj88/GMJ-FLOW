from __future__ import annotations

import csv
import json
import os
import time
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import clickhouse_connect


COLUMN_NAMES = [
    "flow_time",
    "sensor",
    "exporter_ip",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "tcp_flags",
    "input_if",
    "output_if",
    "bytes",
    "packets",
    "flow_count",
    "flow_type",
    "sample_rate",
    "src_asn",
    "dst_asn",
    "src_as_name",
    "dst_as_name",
]

DEFAULT_CSV_FIELDS = [
    "src_host",
    "dst_host",
    "src_port",
    "dst_port",
    "proto",
    "tcpflags",
    "in_iface",
    "out_iface",
    "src_as",
    "dst_as",
    "timestamp",
    "packets",
    "bytes",
    "flows",
]

ALIASES = {
    "src_host": ("src_host", "src_ip", "ip_src", "srcaddr", "ipv4_src_addr", "ipv6_src_addr", "srcaddr6"),
    "dst_host": ("dst_host", "dst_ip", "ip_dst", "dstaddr", "ipv4_dst_addr", "ipv6_dst_addr", "dstaddr6"),
    "src_port": ("src_port", "l4_src_port", "srcport", "source_port"),
    "dst_port": ("dst_port", "l4_dst_port", "dstport", "destination_port"),
    "proto": ("proto", "protocol", "ip_proto", "protocol_identifier"),
    "tcpflags": ("tcpflags", "tcp_flags", "tcpflags_sum", "tcp_flags_sum"),
    "in_iface": ("in_iface", "input_if", "input_snmp", "ingress_if", "ifindex_in"),
    "out_iface": ("out_iface", "output_if", "output_snmp", "egress_if", "ifindex_out"),
    "packets": ("packets", "pkt", "pkts", "packet_count", "in_packets"),
    "bytes": ("bytes", "octets", "in_bytes", "byte_count"),
    "flows": ("flows", "flow_count", "records"),
    "timestamp": ("timestamp", "timestamp_start", "stamp_inserted", "stamp_updated", "first_switched", "flow_start"),
    "sample_rate": ("sample_rate", "sampling_rate", "samplinginterval"),
    "src_as": ("src_as", "src_asn", "src_as_number", "src_asnum", "peer_src_as"),
    "dst_as": ("dst_as", "dst_asn", "dst_as_number", "dst_asnum", "peer_dst_as"),
    "src_as_name": ("src_as_name", "src_as_org", "src_as_description"),
    "dst_as_name": ("dst_as_name", "dst_as_org", "dst_as_description"),
}

PROTO_BY_NAME = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "icmpv6": 58,
}

PROTO_NAMES = {value: name.upper() for name, value in PROTO_BY_NAME.items()}

TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)

TCP_FLAG_BY_NAME = {name.lower(): bit for bit, name in TCP_FLAG_BITS}


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def get_client():
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=env_int("CLICKHOUSE_PORT", 8123),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "flowdb"),
    )


def normalize_key(value: str) -> str:
    return value.strip().strip('"').strip("'").lower().replace("-", "_").replace(" ", "_")


def normalize_record_keys(record: dict[str, Any]) -> dict[str, Any]:
    return {normalize_key(str(key)): value for key, value in record.items()}


def pick(record: dict[str, Any], field: str, default: Any = None) -> Any:
    for alias in ALIASES[field]:
        key = normalize_key(alias)
        if key in record and record[key] not in (None, "", "null", "NULL"):
            return record[key]
    return default


def safe_int(value: Any, default: int = 0, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            number = int(value, 16)
        else:
            number = int(float(value))
    except (TypeError, ValueError):
        number = default
    number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


def safe_ip(value: Any, default: str = "::") -> str:
    try:
        return str(ip_address(str(value).strip()))
    except ValueError:
        return default


def parse_proto(value: Any) -> int:
    if value is None:
        return 0
    text = str(value).strip().lower()
    if text in PROTO_BY_NAME:
        return PROTO_BY_NAME[text]
    return safe_int(text, default=0, minimum=0, maximum=255)


def proto_name(proto: int) -> str:
    return PROTO_NAMES.get(proto, f"PROTO-{proto}")


def parse_tcp_flags(value: Any) -> int:
    if value is None:
        return 0
    text = str(value).strip().lower()
    if not text:
        return 0
    if text.startswith("0x") or text.replace(".", "", 1).isdigit():
        return safe_int(text, default=0, minimum=0, maximum=65535)

    flags = 0
    for token in text.replace("+", " ").replace("|", " ").replace(",", " ").split():
        flags |= TCP_FLAG_BY_NAME.get(token, 0)
    return flags


def tcp_flags_name(flags: int) -> str:
    names = [name for bit, name in TCP_FLAG_BITS if flags & bit]
    return "+".join(names) if names else "NONE"


def parse_timestamp(value: Any) -> datetime:
    if value not in (None, "", "null", "NULL"):
        text = str(value).strip()
        try:
            if text.replace(".", "", 1).isdigit():
                number = float(text)
                if number > 10_000_000_000:
                    number /= 1000
                return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, ValueError):
            pass

        iso_text = text.replace("Z", "+00:00")
        for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                if fmt is None:
                    parsed = datetime.fromisoformat(iso_text)
                else:
                    parsed = datetime.strptime(text, fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except ValueError:
                continue

    return datetime.now(timezone.utc)


def normalize_flow(record: dict[str, Any], sensor: str, exporter_ip: str, sample_rate_default: int) -> tuple:
    normalized = normalize_record_keys(record)
    proto = parse_proto(pick(normalized, "proto", 0))
    tcp_flags = parse_tcp_flags(pick(normalized, "tcpflags", 0))
    sample_rate = safe_int(pick(normalized, "sample_rate", sample_rate_default), default=sample_rate_default, minimum=1)
    flow_count = safe_int(pick(normalized, "flows", 1), default=1, minimum=1)

    # Names are kept here for debugging/future enrichment; flow_raw stores compact numeric values.
    _ = (proto_name(proto), tcp_flags_name(tcp_flags))

    return (
        parse_timestamp(pick(normalized, "timestamp")),
        sensor,
        safe_ip(exporter_ip),
        safe_ip(pick(normalized, "src_host")),
        safe_ip(pick(normalized, "dst_host")),
        safe_int(pick(normalized, "src_port", 0), minimum=0, maximum=65535),
        safe_int(pick(normalized, "dst_port", 0), minimum=0, maximum=65535),
        proto,
        tcp_flags,
        safe_int(pick(normalized, "in_iface", 0), minimum=0),
        safe_int(pick(normalized, "out_iface", 0), minimum=0),
        safe_int(pick(normalized, "bytes", 0), minimum=0),
        safe_int(pick(normalized, "packets", 0), minimum=0),
        flow_count,
        "netflow-v9",
        sample_rate,
        safe_int(pick(normalized, "src_as", 0), minimum=0),
        safe_int(pick(normalized, "dst_as", 0), minimum=0),
        str(pick(normalized, "src_as_name", "") or "")[:255],
        str(pick(normalized, "dst_as_name", "") or "")[:255],
    )


class Tailer:
    def __init__(self, path: Path, state_path: Path):
        self.path = path
        self.state_path = state_path
        self.offset = 0
        self.inode = 0
        self.pending_offset = 0
        self.load_state()

    def load_state(self) -> None:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return
        if payload.get("file") == str(self.path):
            self.offset = safe_int(payload.get("offset"), default=0, minimum=0)
            self.inode = safe_int(payload.get("inode"), default=0, minimum=0)

    def commit(self, last_line_ts: str = "") -> None:
        if self.pending_offset <= 0:
            return
        self.offset = self.pending_offset
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "file": str(self.path),
            "inode": self.inode,
            "offset": self.offset,
            "last_line_ts": last_line_ts,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        self.state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def read_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        stat = self.path.stat()
        size = stat.st_size
        inode = getattr(stat, "st_ino", 0)
        if inode and self.inode and inode != self.inode:
            self.offset = 0
        self.inode = inode
        if size < self.offset:
            self.offset = 0
        with self.path.open("rb") as handle:
            handle.seek(self.offset)
            data = handle.read()
        if not data:
            return []
        if not data.endswith(b"\n"):
            last_newline = data.rfind(b"\n")
            if last_newline < 0:
                self.pending_offset = self.offset
                return []
            process = data[: last_newline + 1]
        else:
            process = data
        self.pending_offset = self.offset + len(process)
        return process.decode("utf-8", errors="ignore").splitlines()


def parse_json_line(line: str) -> list[dict[str, Any]]:
    payload = json.loads(line)
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def header_like(row: list[str]) -> bool:
    known = {normalize_key(alias) for aliases in ALIASES.values() for alias in aliases}
    return any(normalize_key(value) in known for value in row)


def csv_fields_from_env() -> list[str]:
    raw = os.getenv("PMACCT_CSV_FIELDS", "")
    if not raw.strip():
        return DEFAULT_CSV_FIELDS
    return [normalize_key(field) for field in raw.split(",") if field.strip()]


def parse_csv_line(line: str, delimiter: str, fallback_fields: list[str], headers: list[str] | None) -> tuple[list[dict[str, Any]], list[str] | None]:
    row = next(csv.reader([line], delimiter=delimiter))
    if not row:
        return [], headers
    if header_like(row):
        return [], [normalize_key(value) for value in row]

    fields = headers if headers else fallback_fields
    if len(row) < len(fields):
        missing = set(fields[len(row):])
        if not missing.issubset({"flows", "flow_count", "records"}):
            return [], headers
    record = dict(zip(fields[: len(row)], row))
    return [record], headers


def insert_batch(client, rows: list[tuple]):
    client.insert("flow_raw", rows, column_names=COLUMN_NAMES)


def main():
    output_file = Path(os.getenv("PMACCT_OUTPUT_FILE", "/var/spool/pmacct/nfacctd.csv"))
    output_format = os.getenv("PMACCT_OUTPUT_FORMAT", "csv").lower()
    delimiter = os.getenv("PMACCT_CSV_DELIMITER", ",")
    sensor = os.getenv("PMACCT_SENSOR", "mikrotik-lab")
    exporter_ip = os.getenv("PMACCT_EXPORTER_IP", "192.168.0.157")
    sample_rate = env_int("PMACCT_SAMPLE_RATE", 1)
    batch_size = env_int("PMACCT_PARSER_BATCH_SIZE", 1000)
    flush_seconds = env_int("PMACCT_PARSER_FLUSH_SECONDS", 5)
    poll_seconds = float(os.getenv("PMACCT_PARSER_POLL_SECONDS", "1"))
    state_dir = Path(os.getenv("PMACCT_STATE_DIR", "/var/spool/pmacct/state"))
    state_file = Path(os.getenv("PMACCT_STATE_FILE", state_dir / f"{output_file.name}.offset.json"))

    fallback_fields = csv_fields_from_env()
    headers: list[str] | None = None
    batch: list[tuple] = []
    last_flush = time.monotonic()
    tailer = Tailer(output_file, state_file)
    client = get_client()
    lines_read = 0
    lines_inserted = 0
    lines_skipped = 0
    last_line_ts = ""

    print(f"Reading pmacct {output_format} from {output_file}; state={state_file}; offset={tailer.offset}", flush=True)
    while True:
        for raw_line in tailer.read_lines():
            line = raw_line.strip()
            if not line or line.startswith("!"):
                lines_skipped += 1
                continue
            lines_read += 1
            try:
                if output_format == "json" or line.startswith("{") or line.startswith("["):
                    records = parse_json_line(line)
                else:
                    records, headers = parse_csv_line(line, delimiter, fallback_fields, headers)
                for record in records:
                    flow = normalize_flow(record, sensor, exporter_ip, sample_rate)
                    batch.append(flow)
                    last_line_ts = flow[0].isoformat().replace("+00:00", "Z")
                if not records:
                    lines_skipped += 1
            except Exception as exc:
                lines_skipped += 1
                print(f"Skipping pmacct line: {exc}: {line[:200]}", flush=True)

        elapsed = time.monotonic() - last_flush
        if batch and (len(batch) >= batch_size or elapsed >= flush_seconds):
            rows = batch[:]
            insert_batch(client, rows)
            batch.clear()
            tailer.commit(last_line_ts)
            last_flush = time.monotonic()
            lines_inserted += len(rows)
            print(
                "pmacct parser stats: "
                f"file={output_file} read={lines_read} inserted={lines_inserted} "
                f"skipped={lines_skipped} offset={tailer.offset}",
                flush=True,
            )

        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
