from __future__ import annotations

from typing import Any


def _number(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _trim(value: float) -> str:
    text = f"{value:.1f}" if abs(value) < 1000 and value != int(value) else f"{value:.0f}"
    return text.rstrip("0").rstrip(".") if "." in text else text


def _scaled(value: Any, units: tuple[tuple[str, float], ...], base_unit: str) -> str:
    number = _number(value)
    if number is None:
        return "-"
    absolute = abs(number)
    for suffix, divisor in units:
        if absolute >= divisor:
            return f"{_trim(number / divisor)} {suffix}"
    return f"{_trim(number)} {base_unit}".strip()


def format_bits_per_second(value: Any) -> str:
    return _scaled(value, (("Gbps", 1_000_000_000), ("Mbps", 1_000_000), ("Kbps", 1_000)), "bps")


def format_packets_per_second(value: Any) -> str:
    return _scaled(value, (("Mpps", 1_000_000), ("Kpps", 1_000)), "pps")


def format_bytes(value: Any) -> str:
    return _scaled(value, (("GB", 1_000_000_000), ("MB", 1_000_000), ("KB", 1_000)), "B")


def format_packets(value: Any) -> str:
    return _scaled(value, (("G", 1_000_000_000), ("M", 1_000_000), ("K", 1_000)), "")


def format_flows(value: Any) -> str:
    return format_packets(value)


PDF_RATE_FIELDS = {
    "bits_s",
    "bps",
    "avg_bits_s",
    "peak_value",
    "baseline_p95",
    "baseline_p99",
    "threshold",
    "warning",
    "critical",
    "rate_limit",
    "rate-limit",
}
PDF_PACKET_RATE_FIELDS = {"packets_s", "pps", "avg_packets_s"}
PDF_BYTE_FIELDS = {"bytes", "total_bytes"}
PDF_PACKET_FIELDS = {"packets", "total_packets"}
PDF_FLOW_FIELDS = {"flows", "flow_count"}


def format_pdf_metric(field: str, value: Any) -> str:
    key = field.lower().replace("-", "_")
    if key in PDF_PACKET_RATE_FIELDS:
        return format_packets_per_second(value)
    if key in PDF_RATE_FIELDS:
        return format_bits_per_second(value)
    if key in PDF_BYTE_FIELDS:
        return format_bytes(value)
    if key in PDF_PACKET_FIELDS:
        return format_packets(value)
    if key in PDF_FLOW_FIELDS:
        return format_flows(value)
    return "" if value is None else str(value)
