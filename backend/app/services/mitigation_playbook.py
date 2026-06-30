from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any


PLAYBOOK_PATH = Path(__file__).resolve().parents[1] / "playbook" / "playbook_mitigacao.yaml"


def _load_mapping_text(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Playbook YAML is not JSON-compatible and PyYAML is not installed.") from exc
        loaded = yaml.safe_load(text)
    if not isinstance(loaded, dict):
        raise RuntimeError("Mitigation playbook must be a mapping.")
    return loaded


@lru_cache(maxsize=4)
def load_playbook(path: str | None = None) -> dict[str, Any]:
    playbook_path = Path(path) if path else PLAYBOOK_PATH
    return _load_mapping_text(playbook_path)


def ttl_to_seconds(value: Any) -> int:
    if value is None:
        return 0
    text = str(value).strip().lower()
    match = re.fullmatch(r"(\d+)\s*([smhd])", text)
    if not match:
        return 0
    amount = int(match.group(1))
    unit = match.group(2)
    if unit == "s":
        return amount
    if unit == "m":
        return amount * 60
    if unit == "h":
        return amount * 3600
    if unit == "d":
        return amount * 86400
    return 0


def minimum_ttl_for_template(playbook: dict[str, Any], template_name: str | None) -> str:
    template = (playbook.get("attack_templates") or {}).get(str(template_name or ""), {})
    ttl = template.get("ttl") if isinstance(template, dict) else {}
    minimum = ttl.get("minimum") if isinstance(ttl, dict) else None
    return str(minimum or "30m")


def infer_attack_template(incident: dict[str, Any], playbook: dict[str, Any] | None = None) -> str:
    protocol = str(incident.get("protocol") or "").strip().lower()
    dst_port = _to_int(incident.get("dst_port"))
    direction = str(incident.get("direction") or "").strip().lower()
    tcp_flags = str(incident.get("tcp_flags") or incident.get("flags") or "").strip().lower()

    if protocol == "tcp" and ("syn" in tcp_flags or incident.get("tcp_flag_syn") is True):
        return "tcp_syn_flood"
    if protocol == "tcp" and dst_port in {80, 443}:
        return "possible_l7_http_https"
    if protocol == "udp" and dst_port == 53 and direction == "outbound":
        return "dns_udp_abuse_outbound"
    if protocol == "icmp":
        return "icmp_flood"
    if protocol == "udp" and direction == "outbound" and incident.get("src_is_customer"):
        return "udp_flood_outbound_cpe"
    return str(incident.get("suspected_template") or "udp_flood_outbound_cpe")


def _to_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
