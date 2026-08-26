#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Baixa e converte o dataset CAIDA RouteViews prefix2as para o dicionario ASN.

Fonte: https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/
Arquivos:
  routeviews-rv2-<YYYYMMDD>-0000.pfx2as.gz   (IPv4)
  routeviews-rv6-<YYYYMMDD>-0000.pfx2as.gz   (IPv6)
Formato (TAB-separado, 1 linha por prefixo):
  IP prefix \t prefix length \t AS number
  Ex.: 1.2.3.0 \t 24 \t 1234
MOAS (multi-origin AS): AS number pode vir "30_10_20" (ordenado por frequencia).
  Regra adotada (documentada no dataset): escolher o PRIMEIRO ASN.

Conversao adotada (evita problema de endianess e lookup por row no ClickHouse):
  - IPv4 1.2.3.0/24  -> IPv4-mapped IPv6  ::ffff:1.2.3.0/120
  - IPv6 2001:db8::/32 -> mantido
  Assim o dicionario ip_trie tem UMA chave (IPv6) e o dictGet usa o dst_ip/src_ip
  (ja IPv6) diretamente, sem substring/reverse/regex por linha.

Nao insere nada por padrao (validacao primeiro).

Uso:
  python asn_prefix_loader.py download --date 20260825 --out-dir ./asn_data
  python asn_prefix_loader.py load --tsv ./asn_data/asn_prefixes_ch.tsv \
         --clickhouse-url http://127.0.0.1:8123
"""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE_URL = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/"

CH_COLUMNS = ["prefix", "asn", "as_name", "country", "source"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_prefix_v4(addr: str, length: str) -> str | None:
    """Converte IPv4 1.2.3.0/24 -> ::ffff:1.2.3.0/120."""
    try:
        net = ipaddress.ip_network(f"{addr.strip()}/{length.strip()}", strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    mapped = ipaddress.IPv6Address(f"::ffff:{net.network_address}")
    return f"{mapped}/{net.prefixlen + 96}"


def normalize_prefix_v6(addr: str, length: str) -> str | None:
    """Normaliza um CIDR IPv6."""
    try:
        net = ipaddress.ip_network(f"{addr.strip()}/{length.strip()}", strict=False)
    except ValueError:
        return None
    if net.version != 6:
        return None
    return str(net)


def first_asn(raw: str) -> int | None:
    """MOAS: pega o primeiro ASN (regra do dataset). Retorna None se invalido."""
    text = raw.strip()
    if not text:
        return None
    head = text.split("_")[0].split(",")[0]
    try:
        value = int(head)
    except ValueError:
        return None
    return value if value > 0 else None


def parse_line(line: str, is_v4: bool, stats: dict) -> tuple[str, int] | None:
    parts = line.rstrip("\n").split("\t")
    if len(parts) >= 3:
        addr, length, asn_raw = parts[0], parts[1], parts[2]
    elif len(parts) == 2 and "/" in parts[0]:
        # tolera a variante prefix/len ja embutido no campo 0
        addr_len, asn_raw = parts[0], parts[1]
        addr, _, length = addr_len.partition("/")
    else:
        stats["malformed_lines"] += 1
        return None
    asn = first_asn(asn_raw)
    if asn is None:
        stats["asn_invalid"] += 1
        return None
    if raw_has_moas(asn_raw):
        stats["moas_collapsed"] += 1
    prefix = normalize_prefix_v4(addr, length) if is_v4 else normalize_prefix_v6(addr, length)
    if prefix is None:
        stats["cidr_invalid"] += 1
        return None
    return prefix, asn


def raw_has_moas(raw: str) -> bool:
    return "_" in raw or "," in raw


def download_one(url: str, dest: str) -> None:
    print(f"  baixando {url}", flush=True)
    with urllib.request.urlopen(url, timeout=120) as resp, open(dest, "wb") as out:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)


def iter_gz_lines(path: str):
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line


def build_tsv(date: str, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    files = {
        "v4": os.path.join(out_dir, f"routeviews-rv2-{date}-0000.pfx2as.gz"),
        "v6": os.path.join(out_dir, f"routeviews-rv6-{date}-0000.pfx2as.gz"),
    }
    for key, local in files.items():
        if not os.path.exists(local):
            download_one(f"{BASE_URL}{os.path.basename(local)}", local)

    stats = {
        "date": date,
        "v4_count": 0,
        "v6_count": 0,
        "asn_invalid": 0,
        "cidr_invalid": 0,
        "malformed_lines": 0,
        "moas_collapsed": 0,
        "duplicates": 0,
        "generated_at": utc_now(),
    }
    seen: set[str] = set()
    tsv_path = os.path.join(out_dir, "asn_prefixes_ch.tsv")
    with open(tsv_path, "w", encoding="utf-8") as out:
        for key, is_v4, label in (("v4", True, "v4"), ("v6", False, "v6")):
            count = 0
            for line in iter_gz_lines(files[key]):
                parsed = parse_line(line, is_v4, stats)
                if parsed is None:
                    continue
                prefix, asn = parsed
                if prefix in seen:
                    stats["duplicates"] += 1
                    continue
                seen.add(prefix)
                count += 1
                # prefix \t asn \t as_name \t country \t source
                out.write(f"{prefix}\t{asn}\t\t\tcaida-pfx2as\n")
            stats[f"{label}_count"] = count
    report_path = os.path.join(out_dir, "loader_report.json")
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(stats, handle, indent=2, sort_keys=True)
    print(json.dumps(stats, indent=2, sort_keys=True))
    print(f"TSV: {tsv_path}")
    return stats


def load_tsv(tsv_path: str, ch_url: str, db: str = "flowdb", batch: int = 100_000) -> None:
    table = f"{db}.asn_prefixes_ch"
    query = f"INSERT INTO {table} ({','.join(CH_COLUMNS)}) FORMAT TabSeparated"
    rows: list[str] = []
    total = 0
    started = datetime.now(timezone.utc)

    def flush():
        nonlocal rows, total
        if not rows:
            return
        payload = "\n".join(rows).encode("utf-8")
        req = urllib.request.Request(
            f"{ch_url}/?query={urllib.parse.quote(query)}",
            data=payload,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=600) as resp:
            resp.read()
        total += len(rows)
        rows = []
        print(f"  inseridas {total} linhas ...", flush=True)

    with open(tsv_path, "r", encoding="utf-8") as handle:
        for line in handle:
            rows.append(line.rstrip("\n"))
            if len(rows) >= batch:
                flush()
    flush()
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    print(f"total={total} elapsed={elapsed:.1f}s rows/s={total / max(elapsed, 0.1):.0f}")


def main() -> int:
    parser = argparse.ArgumentParser(description="CAIDA pfx2as -> asn_prefixes_ch")
    sub = parser.add_subparsers(dest="command", required=True)

    dl = sub.add_parser("download", help="baixa, converte e valida (nao insere)")
    dl.add_argument("--date", default=datetime.utcnow().strftime("%Y%m%d"))
    dl.add_argument("--out-dir", default="./asn_data")

    ld = sub.add_parser("load", help="insere o TSV validado no ClickHouse")
    ld.add_argument("--tsv", required=True)
    ld.add_argument("--clickhouse-url", default="http://127.0.0.1:8123")
    ld.add_argument("--db", default="flowdb")
    ld.add_argument("--batch", type=int, default=100_000)

    args = parser.parse_args()
    if args.command == "download":
        build_tsv(args.date, args.out_dir)
    elif args.command == "load":
        load_tsv(args.tsv, args.clickhouse_url, args.db, args.batch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
