import argparse
import os
import random
import time
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network

import clickhouse_connect


CUSTOMER_NETS = [
    IPv4Network("100.64.0.0/18"),
    IPv4Network("100.64.64.0/18"),
    IPv4Network("198.51.100.0/24"),
]

INTERNET_NETS = [
    IPv4Network("8.8.8.0/24"),
    IPv4Network("1.1.1.0/24"),
    IPv4Network("9.9.9.0/24"),
    IPv4Network("203.0.113.0/24"),
    IPv4Network("45.60.0.0/16"),
    IPv4Network("151.101.0.0/16"),
]

COMMON_PORTS = [53, 80, 123, 443, 993, 995, 8080, 8443, 22, 25, 110, 143, 3389]
TCP_FLAGS = [0x10, 0x12, 0x02, 0x18, 0x11, 0x04]


def get_client():
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "flowdb"),
    )


def random_ip(networks: list[IPv4Network]) -> str:
    net = random.choice(networks)
    first = int(net.network_address) + 1
    last = int(net.broadcast_address) - 1
    return str(IPv4Address(random.randint(first, last)))


def random_port(common_bias: float = 0.75) -> int:
    if random.random() < common_bias:
        return random.choice(COMMON_PORTS)
    return random.randint(1024, 65535)


def make_flow(sensor: str, exporter_ip: str) -> tuple:
    proto = random.choices([6, 17, 1], weights=[62, 33, 5], k=1)[0]
    outbound = random.random() < 0.65

    if outbound:
        src_ip = random_ip(CUSTOMER_NETS)
        dst_ip = random_ip(INTERNET_NETS)
        input_if, output_if = 2, 1
    else:
        src_ip = random_ip(INTERNET_NETS)
        dst_ip = random_ip(CUSTOMER_NETS)
        input_if, output_if = 1, 2

    if proto == 1:
        src_port = 0
        dst_port = 0
        tcp_flags = 0
    else:
        src_port = random.randint(1024, 65535)
        dst_port = random_port()
        tcp_flags = random.choice(TCP_FLAGS) if proto == 6 else 0

    packets = random.randint(1, 250)
    avg_packet_size = random.randint(72, 1400)
    bytes_value = packets * avg_packet_size
    flow_time = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 75))

    return (
        flow_time,
        sensor,
        exporter_ip,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        tcp_flags,
        input_if,
        output_if,
        bytes_value,
        packets,
        'fake',
        1,
    )


def insert_batch(client, rows: list[tuple]):
    client.insert(
        "flow_raw",
        rows,
        column_names=[
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
            "flow_type",
            "sample_rate",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description="Gerador fake de flows para o GMJ-FLOW")
    parser.add_argument("--batch-size", type=int, default=int(os.getenv("FAKE_FLOW_BATCH_SIZE", "1000")))
    parser.add_argument("--interval", type=float, default=float(os.getenv("FAKE_FLOW_INTERVAL_SECONDS", "5")))
    parser.add_argument("--sensor", default=os.getenv("FAKE_FLOW_SENSOR", "edge-01"))
    parser.add_argument("--exporter-ip", default=os.getenv("FAKE_FLOW_EXPORTER_IP", "192.0.2.10"))
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    client = get_client()
    while True:
        rows = [make_flow(args.sensor, args.exporter_ip) for _ in range(args.batch_size)]
        insert_batch(client, rows)
        print(f"Inseridos {len(rows)} flows fake em {datetime.now(timezone.utc).isoformat()}", flush=True)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
