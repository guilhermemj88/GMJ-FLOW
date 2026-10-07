"""Midia / Alertas por Webhook.

Envio best-effort de eventos do GMJ-FLOW para destinos HTTP configurados pelo
operador (n8n, e futuramente outros tipos).

Principios desta camada:
  - dispara SOMENTE depois da persistencia do evento (quem chama passa ids ja
    commitados);
  - nunca levanta excecao para o chamador: falha de webhook nao pode quebrar
    deteccao, mitigacao nem qualquer outro pipeline;
  - nao bloqueia o detector: o envio acontece em thread propria com fila interna;
  - o segredo do destino e cifrado com o cofre ja existente do projeto
    (app.services.ai_integration), nunca gravado em texto aberto.

Payload publico: envelope versionado

    {"version": 1, "event": "anomaly_detected", "sent_at": "...", "data": {...}}

Os nomes internos (packets_s/bits_s/threshold_value...) sao preservados no
`data` junto da serializacao publica `pps`/`bps` para o consumidor (n8n).

O disparo real (anomaly_detected) e as ferramentas administrativas de teste
(preview/test-event) aplicam o MESMO enriquecimento CGNAT usado pelo Grafana
(enrich_anomaly_event_with_cgnat). Quando ha match, o payload ganha campos
aditivos `cgnat_*` e o objeto `data.cgnat`; quando nao ha match, nada e
alterado (payload legado intacto).

A correlacao canonica de anomalias e apenas PROPAGADA: quando o resolver do
core (anomaly_correlation) devolve `correlation`, o payload ganha
`data.correlation` com a estrutura original preservada; nenhum recalculo ou
consulta propria de ocorrencias acontece nesta camada.
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Iterable

MEDIA_TYPE_WEBHOOK = "webhook"
MEDIA_TYPES = (MEDIA_TYPE_WEBHOOK,)

MEDIA_EVENT_TYPES = (
    "anomaly_detected",
    "anomaly_closed",
    "mitigation_applied",
    "mitigation_withdrawn",
)

MEDIA_SEVERITY_ORDER = ("info", "warning", "critical")

MEDIA_PAYLOAD_VERSION = 1

# Placeholders suportados pelo template editavel de payload. Cobrem os campos
# do envelope + anomaly_event_data, o marcador `test` e os campos CGNAT
# aditivos preenchidos no disparo real e no test/preview (ver
# enrich_payload_with_cgnat). Substituicao declarativa: nada de expressoes/eval.
MEDIA_PLACEHOLDERS = (
    "version",
    "event",
    "sent_at",
    "test",
    "event_id",
    "public_id",
    "target_ip",
    "target_cidr",
    "target_port",
    "target_role",
    "protocol",
    "vector_name",
    "display_name",
    "severity",
    "direction",
    "status",
    "pps",
    "bps",
    "packets_s",
    "bits_s",
    "flows",
    "packets",
    "bytes",
    "metric_unit",
    "observed_value",
    "threshold_value",
    "peak_value",
    "unique_src_ips",
    "unique_dst_ips",
    "unique_dst_ports",
    "top_src_ip",
    "top_dst_ip",
    "top_src_port",
    "top_dst_port",
    "top_packets",
    "top_bytes",
    "started_at",
    "last_seen_at",
    "ended_at",
    "sensor",
    "sensor_id",
    "sensor_name",
    "exporter_ip",
    "sensor_resolution",
    "source_name",
    "source_engine",
    "source_id",
    "decoder",
    "classification",
    "mitigation_basis",
    "mitigation_reason",
    "mitigation_status",
    "zone_name",
    "summary",
    "dedupe_key",
    # CGNAT: preenchidos apenas quando o disparo real resolve o assinante.
    "cgnat_resolved",
    "cgnat_public_ip",
    "cgnat_public_port",
    "cgnat_private_ip",
    "cgnat_pool_name",
    "cgnat_device_name",
    "cgnat_confidence",
)

# Template padrao: reproduz 1:1 o payload que o GMJ-FLOW envia hoje. Campos
# numericos/booleanos/anulaveis ficam SEM aspas para preservar o tipo JSON.
# Obs.: nenhum payload recebe a chave "test" automaticamente. Ela so aparece se
# o template do destino declarar explicitamente "test": {{test}} (entao vira
# true no teste e false em producao).
DEFAULT_PAYLOAD_TEMPLATE = """{
  "version": {{version}},
  "event": "{{event}}",
  "sent_at": "{{sent_at}}",
  "data": {
    "event_id": {{event_id}},
    "public_id": "{{public_id}}",
    "target_ip": "{{target_ip}}",
    "target_cidr": "{{target_cidr}}",
    "target_port": {{target_port}},
    "target_role": "{{target_role}}",
    "protocol": "{{protocol}}",
    "vector_name": "{{vector_name}}",
    "display_name": "{{display_name}}",
    "severity": "{{severity}}",
    "direction": "{{direction}}",
    "status": "{{status}}",
    "pps": {{pps}},
    "bps": {{bps}},
    "packets_s": {{packets_s}},
    "bits_s": {{bits_s}},
    "flows": {{flows}},
    "packets": {{packets}},
    "bytes": {{bytes}},
    "metric_unit": "{{metric_unit}}",
    "observed_value": {{observed_value}},
    "threshold_value": {{threshold_value}},
    "peak_value": {{peak_value}},
    "unique_src_ips": {{unique_src_ips}},
    "unique_dst_ips": {{unique_dst_ips}},
    "unique_dst_ports": {{unique_dst_ports}},
    "top_src_ip": "{{top_src_ip}}",
    "top_dst_ip": "{{top_dst_ip}}",
    "top_src_port": {{top_src_port}},
    "top_dst_port": {{top_dst_port}},
    "top_packets": {{top_packets}},
    "top_bytes": {{top_bytes}},
    "started_at": "{{started_at}}",
    "last_seen_at": "{{last_seen_at}}",
    "ended_at": "{{ended_at}}",
    "sensor": "{{sensor}}",
    "sensor_id": {{sensor_id}},
    "sensor_name": {{sensor_name}},
    "exporter_ip": "{{exporter_ip}}",
    "sensor_resolution": "{{sensor_resolution}}",
    "source_name": "{{source_name}}",
    "source_engine": "{{source_engine}}",
    "source_id": "{{source_id}}",
    "decoder": "{{decoder}}",
    "classification": "{{classification}}",
    "mitigation_basis": "{{mitigation_basis}}",
    "mitigation_reason": "{{mitigation_reason}}",
    "mitigation_status": "{{mitigation_status}}",
    "zone_name": "{{zone_name}}",
    "summary": "{{summary}}",
    "dedupe_key": "{{dedupe_key}}"
  }
}"""

# Dados simulados para o teste: preenchem TODOS os placeholders para que
# qualquer template seja renderizavel e testavel.
TEST_SAMPLE_EVENT = {
    "event_id": 0,
    "public_id": "TEST-0000",
    "target_ip": "100.64.17.245",
    "target_cidr": "100.64.17.245/32",
    "target_port": 443,
    "target_role": "internal",
    "protocol": "udp",
    "vector_name": "TEST_UDP_FLOOD",
    "display_name": "Teste UDP Flood",
    "severity": "critical",
    "direction": "receives",
    "status": "test",
    "pps": 420000.0,
    "bps": 3800000000.0,
    "packets_s": 420000.0,
    "bits_s": 3800000000.0,
    "flows": 12.0,
    "packets": 420000,
    "bytes": 3800000000,
    "metric_unit": "packets_s",
    "observed_value": 420000.0,
    "threshold_value": 100000.0,
    "peak_value": 430000.0,
    "unique_src_ips": 1,
    "unique_dst_ips": 1,
    "unique_dst_ports": 1,
    "top_src_ip": "100.64.0.10",
    "top_dst_ip": "100.64.17.245",
    "top_src_port": 40000,
    "top_dst_port": 443,
    "top_packets": 420000,
    "top_bytes": 3800000000,
    "started_at": "2026-10-02T12:00:00Z",
    "last_seen_at": "2026-10-02T12:05:00Z",
    "ended_at": "",
    "sensor": "SENSOR-BHE-F1A",
    "sensor_id": 1,
    "sensor_name": "SENSOR-BHE-F1A",
    "exporter_ip": "179.189.80.0",
    "sensor_resolution": "single",
    "source_name": "Evento manual de teste",
    "source_engine": "gmjflow",
    "source_id": "test",
    "decoder": "",
    "classification": "",
    "mitigation_basis": "",
    "mitigation_reason": "",
    "mitigation_status": "not_executed",
    "zone_name": "",
    "summary": "Teste UDP Flood",
    "dedupe_key": "TEST-0000",
}

# Correlation controlada do sample do botao "Testar destino": existe SOMENTE
# para exercitar o contrato do webhook (data.correlation), com a MESMA
# estrutura canonica devolvida pelo core. Nao representa historico real.
TEST_SAMPLE_CORRELATION: dict[str, Any] = {
    "subject_type": "cgnat_private_ip",
    "subject_key": "100.64.9.50",
    "subject_confidence": "high",
    "subject_context": {"public_ip": "179.189.80.242", "public_port": 20486},
    "is_recurrence": True,
    "occurrence_number_today": 4,
    "occurrences_today": 4,
    "previous_occurrences_today": 3,
    "last_previous_occurrence_at": "2026-10-06T12:05:00Z",
    "previous_occurrences": [
        {
            "occurrence_id": 3,
            "anomaly_id": 4681,
            "anomaly_table": "anomaly_events",
            "first_seen": "2026-10-06T12:05:00Z",
            "last_seen": "2026-10-06T12:10:00Z",
            "ended_at": "2026-10-06T12:10:00Z",
            "severity": "warning",
            "metric": "packets_s",
            "metric_value": 420000.0,
        }
    ],
    "previous_occurrences_truncated": True,
    "operational_day": "2026-10-06",
    "timezone": "America/Sao_Paulo",
    "schema_version": 1,
}

# Sample padrao do botao "Testar destino" (test_media_integration). Usa os
# mesmos nomes de campo do builder do preview administrativo
# (media_test_event_data, em main.py) e reproduz o formato logico de uma
# anomalia real de saida (direction=transmits) com coordenada CGNAT
# resolvivel: 179.189.80.242:20486 -> 100.64.9.50. O lookup correto e
# top_src_ip/top_src_port; target_port=53 NAO participa da resolucao.
# A correlation embutida e o contrato de exemplo (ver TEST_SAMPLE_CORRELATION)
# e NAO representa historico real.
TEST_DESTINATION_SAMPLE: dict[str, Any] = {
    **TEST_SAMPLE_EVENT,
    "target_ip": "179.189.80.242",
    "target_cidr": "179.189.80.242/32",
    "target_port": 53,
    "target_role": "src_ip",
    "direction": "transmits",
    "top_src_ip": "179.189.80.242",
    "top_src_port": 20486,
    "top_dst_ip": "54.233.253.229",
    "top_dst_port": 53,
    "protocol": "udp",
    "source_name": "Evento manual de teste",
    "source_engine": "gmjflow",
    "source_id": "test",
    "status": "test",
    "correlation": TEST_SAMPLE_CORRELATION,
}

# Endpoints de metadata de cloud que jamais devem ser alvo de um webhook.
_BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}
_BLOCKED_IPS = {
    "169.254.169.254",  # AWS/GCP/Azure metadata
    "169.254.170.2",    # ECS task metadata
    "100.100.100.200",  # Alibaba Cloud metadata
    "192.0.0.192",      # Oracle Cloud metadata
    "fd00:ec2::254",    # AWS IMDS IPv6
}

DEFAULT_TIMEOUT_SECONDS = 5.0
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 4096

_LOG_LIMIT = 200

_QUEUE: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=1000)
_WORKER_LOCK = threading.Lock()
_WORKER_THREAD: threading.Thread | None = None
_WORKER_STOP = threading.Event()
_LAST_DISPATCH: dict[str, Any] = {}
_PENDING = threading.local()
_PENDING_LIMIT = 500


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clean_text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def severity_rank(value: Any) -> int:
    """Ordenacao real do projeto: info < warning < critical."""
    return MEDIA_SEVERITY_ORDER.index(clean_text(value).lower()) if clean_text(value).lower() in MEDIA_SEVERITY_ORDER else 0


def normalize_timeout(value: Any) -> float:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        seconds = DEFAULT_TIMEOUT_SECONDS
    return max(MIN_TIMEOUT_SECONDS, min(MAX_TIMEOUT_SECONDS, seconds))


def env_flag(name: str, default: bool) -> bool:
    raw = clean_text(os.getenv(name)).lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "sim"}


class MediaUrlError(ValueError):
    """URL recusada pela politica anti-SSRF."""


def _ip_is_allowed(address: ipaddress._BaseAddress) -> tuple[bool, str]:
    if address.is_multicast:
        return False, "endereco multicast"
    if address.is_unspecified:
        return False, "endereco nao especificado"
    if address.is_loopback and not env_flag("GMJFLOW_MEDIA_ALLOW_LOOPBACK", False):
        return False, "loopback (defina GMJFLOW_MEDIA_ALLOW_LOOPBACK=1 para permitir)"
    if address.is_link_local and not env_flag("GMJFLOW_MEDIA_ALLOW_LINK_LOCAL", False):
        return False, "link-local (defina GMJFLOW_MEDIA_ALLOW_LINK_LOCAL=1 para permitir)"
    # Redes privadas sao o caso de uso real (n8n na rede interna), portanto
    # liberadas por padrao e restringiveis por ambiente.
    if address.is_private and not address.is_loopback and not address.is_link_local:
        if not env_flag("GMJFLOW_MEDIA_ALLOW_PRIVATE", True):
            return False, "rede privada (GMJFLOW_MEDIA_ALLOW_PRIVATE=0)"
    if address.is_reserved and not address.is_private:
        return False, "faixa reservada"
    return True, ""


def validate_webhook_url(url: Any) -> str:
    """Valida esquema/host e aplica a politica anti-SSRF. Levanta MediaUrlError."""
    text = clean_text(url)
    if not text:
        raise MediaUrlError("url obrigatoria")
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError as exc:
        raise MediaUrlError(f"url invalida: {exc}") from exc
    if parsed.scheme not in {"http", "https"}:
        raise MediaUrlError("url deve usar http ou https")
    host = clean_text(parsed.hostname)
    if not host:
        raise MediaUrlError("url sem host")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise MediaUrlError("porta invalida")
    lowered = host.lower().strip("[]")
    if lowered in _BLOCKED_HOSTS:
        raise MediaUrlError(f"host bloqueado pela politica de seguranca: {lowered}")
    if lowered in _BLOCKED_IPS:
        raise MediaUrlError(f"endpoint de metadata bloqueado: {lowered}")

    candidates: list[ipaddress._BaseAddress] = []
    try:
        candidates.append(ipaddress.ip_address(lowered))
    except ValueError:
        if lowered in {"localhost", "localhost.localdomain"}:
            raise MediaUrlError("host local bloqueado pela politica de seguranca")
        try:
            info = socket.getaddrinfo(lowered, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise MediaUrlError(f"nao foi possivel resolver o host: {exc}") from exc
        for entry in info:
            raw = entry[4][0]
            try:
                candidates.append(ipaddress.ip_address(raw))
            except ValueError:
                continue
        if not candidates:
            raise MediaUrlError("host sem endereco IP resolvivel")

    for address in candidates:
        if str(address) in _BLOCKED_IPS:
            raise MediaUrlError(f"endpoint de metadata bloqueado: {address}")
        allowed, reason = _ip_is_allowed(address)
        if not allowed:
            raise MediaUrlError(f"destino recusado ({address}): {reason}")
    return text


def sensor_detection_from_row(row: Any) -> dict[str, Any]:
    """Le o bloco sensor_detection persistido em source_details_json."""
    item = dict(row) if row is not None else {}
    detection: dict[str, Any] = {}
    try:
        details = json.loads(clean_text(item.get("source_details_json")) or "{}")
        if isinstance(details, dict) and isinstance(details.get("sensor_detection"), dict):
            detection = dict(details["sensor_detection"])
    except Exception:
        detection = {}
    return detection


def _sensor_payload_fields(item: dict[str, Any]) -> dict[str, Any]:
    """Campos de sensor do payload: diretos do evento ou do bloco sensor_detection."""
    detection = sensor_detection_from_row(item)
    sensor_id = item.get("sensor_id")
    if sensor_id is None:
        sensor_id = detection.get("detected_sensor_id")
    name = clean_text(item.get("sensor_name")) or clean_text(detection.get("detected_sensor_name"))
    exporter = clean_text(item.get("exporter_ip")) or clean_text(detection.get("detected_exporter_ip"))
    resolution = clean_text(item.get("sensor_resolution")) or clean_text(detection.get("sensor_resolution"))
    if not resolution:
        resolution = "single" if sensor_id is not None else "unresolved"
    return {
        "sensor_id": int(sensor_id) if sensor_id is not None else None,
        "sensor_name": name or None,
        "exporter_ip": exporter or None,
        "sensor_resolution": resolution,
    }


def with_sensor_fields(conn: sqlite3.Connection, row: Any) -> dict[str, Any]:
    """Acrescenta sensor_name/exporter_ip/sensor_resolution ao evento antes do payload."""
    item = dict(row) if row is not None else {}
    detection = sensor_detection_from_row(item)
    sensor_id = item.get("sensor_id")
    if sensor_id is None:
        sensor_id = detection.get("detected_sensor_id")
    name = clean_text(detection.get("detected_sensor_name"))
    exporter = clean_text(detection.get("detected_exporter_ip"))
    if sensor_id is not None and (not name or not exporter):
        try:
            sensor = conn.execute(
                "SELECT name, exporter_ip FROM sensors WHERE id = ? LIMIT 1", (int(sensor_id),)
            ).fetchone()
            if sensor is not None:
                name = name or clean_text(sensor["name"])
                exporter = exporter or clean_text(sensor["exporter_ip"])
        except Exception:
            pass
    resolution = clean_text(detection.get("sensor_resolution"))
    if not resolution:
        resolution = "single" if sensor_id is not None else "unresolved"
    item["sensor_id"] = int(sensor_id) if sensor_id is not None else None
    item["sensor_name"] = name
    item["exporter_ip"] = exporter
    item["sensor_resolution"] = resolution
    return item


def normalize_event_types(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        items: Iterable[Any] = value
    else:
        raw = clean_text(value)
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except (TypeError, ValueError):
                parsed = []
            items = parsed if isinstance(parsed, list) else []
        else:
            items = [part for part in raw.replace(";", ",").split(",")]
    result: list[str] = []
    for item in items:
        key = clean_text(item).lower()
        if key in MEDIA_EVENT_TYPES and key not in result:
            result.append(key)
    return result


def normalize_severity(value: Any) -> str:
    key = clean_text(value).lower()
    return key if key in MEDIA_SEVERITY_ORDER else "info"


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _as_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def normalize_sensor_id(value: Any) -> int | None:
    """Converte um sensor_id em inteiro positivo. Invalido/ausente => None."""
    try:
        sensor_id = int(float(value))
    except (TypeError, ValueError):
        return None
    return sensor_id if sensor_id > 0 else None


def normalize_sensor_ids(value: Any) -> list[int]:
    """Normaliza uma lista/CSV/JSON de sensor ids, sem duplicar e mantendo ordem."""
    if isinstance(value, (list, tuple, set)):
        items: Iterable[Any] = value
    else:
        raw = clean_text(value)
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except (TypeError, ValueError):
                parsed = []
            items = parsed if isinstance(parsed, list) else []
        else:
            items = [part for part in raw.replace(";", ",").split(",")] if raw else []
    result: list[int] = []
    for item in items:
        sensor_id = normalize_sensor_id(item)
        if sensor_id is not None and sensor_id not in result:
            result.append(sensor_id)
    return result


def destination_all_sensors(integration: Any) -> bool:
    """Le a flag all_sensors. Ausencia/None significa "todos" (destino legado)."""
    item = dict(integration) if integration is not None else {}
    raw = item.get("all_sensors")
    if raw is None:
        return True
    return bool(_as_int(raw))


def load_destination_sensor_map(conn: sqlite3.Connection) -> dict[int, set[int]]:
    """Le a associacao destino -> sensores num unico SELECT.

    Tolerante a schema ausente (banco antigo antes da migration): nesse caso
    devolve mapa vazio e a flag all_sensors continua decidindo o roteamento.
    """
    result: dict[int, set[int]] = {}
    try:
        rows = conn.execute("SELECT media_id, sensor_id FROM media_destination_sensors").fetchall()
    except Exception:
        return result
    for row in rows:
        try:
            result.setdefault(int(row["media_id"]), set()).add(int(row["sensor_id"]))
        except (TypeError, ValueError, KeyError, IndexError):
            continue
    return result


def sensor_filter_matches(integration: Any, sensor_id: Any, sensor_ids: Iterable[int] | None) -> bool:
    """Regra de sensor: all_sensors OU event.sensor_id entre os selecionados."""
    if destination_all_sensors(integration):
        return True
    event_sensor = normalize_sensor_id(sensor_id)
    if event_sensor is None:
        return False
    allowed = {int(value) for value in (sensor_ids or [])}
    return event_sensor in allowed


def anomaly_event_data(row: Any) -> dict[str, Any]:
    """Serializa uma anomalia real (anomaly_events / security_anomalies) para o webhook.

    Aceita sqlite3.Row ou dict e tolera colunas ausentes, sem inventar taxonomia:
    os nomes internos do GMJ-FLOW sao preservados e apenas ganham aliases
    publicos `pps` / `bps`.
    """
    item = dict(row) if row is not None else {}

    def pick(*names: str) -> Any:
        for name in names:
            if name in item and item[name] is not None:
                return item[name]
        return None

    packets_s = _as_float(pick("packets_s", "packets_per_second"))
    bits_s = _as_float(pick("bits_s", "bits_per_second"))
    metric_unit = clean_text(pick("metric_unit"))
    observed = _as_float(pick("observed_value", "peak_value"))
    if not packets_s and metric_unit.lower() in {"packets_s", "pps"}:
        packets_s = observed
    if not bits_s and metric_unit.lower() in {"bits_s", "bps"}:
        bits_s = observed

    data: dict[str, Any] = {
        "event_id": _as_int(pick("id", "event_id")),
        "public_id": clean_text(pick("public_id")),
        "target_ip": clean_text(pick("target_ip")),
        "target_cidr": clean_text(pick("target_cidr", "target_prefix")),
        "target_port": _as_int(pick("target_port")) if pick("target_port") is not None else None,
        "target_role": clean_text(pick("target_role", "dst_role")),
        "protocol": clean_text(pick("protocol")).lower(),
        "vector_name": clean_text(pick("vector_name", "vector", "attack_type")),
        "display_name": clean_text(pick("display_name", "attack_vector_display_name", "attack_family", "message")),
        "severity": clean_text(pick("severity")).lower(),
        "direction": clean_text(pick("direction")),
        "status": clean_text(pick("status")),
        "pps": packets_s,
        "bps": bits_s,
        "packets_s": packets_s,
        "bits_s": bits_s,
        "flows": _as_float(pick("flows", "flow_count")),
        "packets": _as_int(pick("packets", "estimated_packets", "top_packets")),
        "bytes": _as_int(pick("bytes", "estimated_bytes", "top_bytes")),
        "metric_unit": metric_unit,
        "observed_value": observed,
        "threshold_value": _as_float(pick("threshold_value")),
        "peak_value": _as_float(pick("peak_value")),
        "unique_src_ips": _as_int(pick("unique_src_ips", "unique_sources")),
        "unique_dst_ips": _as_int(pick("unique_dst_ips", "unique_destinations")),
        "unique_dst_ports": _as_int(pick("unique_dst_ports")),
        "top_src_ip": clean_text(pick("top_src_ip", "src_ip")),
        "top_dst_ip": clean_text(pick("top_dst_ip", "dst_ip")),
        "top_src_port": _as_int(pick("top_src_port")) if pick("top_src_port") is not None else None,
        "top_dst_port": _as_int(pick("top_dst_port")) if pick("top_dst_port") is not None else None,
        "top_packets": _as_int(pick("top_packets")),
        "top_bytes": _as_int(pick("top_bytes")),
        "started_at": clean_text(pick("started_at", "first_seen")),
        "last_seen_at": clean_text(pick("last_seen_at", "last_seen")),
        "ended_at": clean_text(pick("ended_at")),
        "sensor": clean_text(pick("sensor", "sensor_name")),
        **_sensor_payload_fields(item),
        "exporter_ip": clean_text(pick("exporter_ip", "exporter")),
        "source_name": clean_text(pick("source_name")),
        "source_engine": clean_text(pick("source_engine", "detector")),
        "source_id": clean_text(pick("source_id")),
        "decoder": clean_text(pick("decoder")),
        "classification": clean_text(pick("classification", "attack_family", "verdict")),
        "mitigation_basis": clean_text(pick("mitigation_basis", "recommended_action")),
        "mitigation_reason": clean_text(pick("mitigation_reason")),
        "mitigation_status": clean_text(pick("mitigation_status", "auto_mitigation_status")),
        "zone_name": clean_text(pick("zone_name")),
        "summary": clean_text(pick("summary", "message")),
        "dedupe_key": clean_text(pick("dedupe_key", "event_key")),
    }
    return data


def build_envelope(event_type: str, data: dict[str, Any], *, sent_at: str | None = None) -> dict[str, Any]:
    return {
        "version": MEDIA_PAYLOAD_VERSION,
        "event": clean_text(event_type),
        "sent_at": sent_at or utc_now_iso(),
        "data": data,
    }


class MediaTemplateError(ValueError):
    """Template de payload invalido (placeholder desconhecido ou JSON quebrado)."""


def payload_context(
    data: dict[str, Any] | None,
    *,
    event_type: str,
    is_test: bool = False,
    sent_at: str | None = None,
    version: int = MEDIA_PAYLOAD_VERSION,
) -> dict[str, Any]:
    """Monta o contexto de placeholders. Somente nomes suportados entram."""
    context: dict[str, Any] = {name: None for name in MEDIA_PLACEHOLDERS}
    context["version"] = version
    context["event"] = clean_text(event_type)
    context["sent_at"] = sent_at or utc_now_iso()
    context["test"] = bool(is_test)
    for key, value in (data or {}).items():
        if key in context:
            context[key] = value
    return context


def _placeholder_text(value: Any) -> str:
    """Valor bruto como literal JSON (sem aspas extras): 1, true, null, "x"."""
    return json.dumps(value, ensure_ascii=False, default=str)


def _placeholder_embedded(value: Any) -> str:
    """Valor para uso DENTRO de uma string JSON ja existente (sem as aspas)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_payload_template(template: str, context: dict[str, Any] | None = None) -> str:
    """Substitui {{placeholders}} de forma declarativa. Nao executa nada.

    Placeholder fora de string vira literal JSON (preserva number/bool/null);
    placeholder dentro de string vira o conteudo escapado (preserva string).
    Levanta MediaTemplateError para placeholder desconhecido ou sintaxe quebrada.
    """
    text = template if template is not None else DEFAULT_PAYLOAD_TEMPLATE
    values = dict(context or {})
    output: list[str] = []
    length = len(text)
    index = 0
    in_string = False
    escaped = False
    while index < length:
        char = text[index]
        if in_string:
            if escaped:
                output.append(char)
                escaped = False
                index += 1
                continue
            if char == "\\":
                output.append(char)
                escaped = True
                index += 1
                continue
            if char == '"':
                in_string = False
                output.append(char)
                index += 1
                continue
        else:
            if char == '"':
                in_string = True
                output.append(char)
                index += 1
                continue
        if char == "{" and index + 1 < length and text[index + 1] == "{":
            end = text.find("}}", index + 2)
            if end == -1:
                raise MediaTemplateError("placeholder sem fechamento '}}'")
            name = text[index + 2 : end].strip()
            if name not in MEDIA_PLACEHOLDERS:
                raise MediaTemplateError(f"placeholder desconhecido: {{{{{name}}}}}")
            value = values.get(name)
            output.append(_placeholder_embedded(value) if in_string else _placeholder_text(value))
            index = end + 2
            continue
        output.append(char)
        index += 1
    return "".join(output)


def validate_payload_template(template: str) -> str:
    """Valida o template renderizando com dados de exemplo. Devolve o JSON final."""
    context = payload_context(TEST_SAMPLE_EVENT, event_type="anomaly_detected", is_test=True)
    rendered = render_payload_template(template, context)
    try:
        json.loads(rendered)
    except (TypeError, ValueError) as exc:
        raise MediaTemplateError(f"JSON invalido apos render: {exc}") from exc
    return rendered


def format_payload_template(template: str) -> str:
    """Reindenta o template preservando os placeholders. Levanta se invalido."""
    text = template if template is not None else DEFAULT_PAYLOAD_TEMPLATE
    output: list[str] = []
    tokens: list[tuple[str, str, bool]] = []
    length = len(text)
    index = 0
    in_string = False
    escaped = False
    while index < length:
        char = text[index]
        if in_string:
            if escaped:
                output.append(char)
                escaped = False
                index += 1
                continue
            if char == "\\":
                output.append(char)
                escaped = True
                index += 1
                continue
            if char == '"':
                in_string = False
                output.append(char)
                index += 1
                continue
        else:
            if char == '"':
                in_string = True
                output.append(char)
                index += 1
                continue
        if char == "{" and index + 1 < length and text[index + 1] == "{":
            end = text.find("}}", index + 2)
            if end == -1:
                raise MediaTemplateError("placeholder sem fechamento '}}'")
            name = text[index + 2 : end].strip()
            if name not in MEDIA_PLACEHOLDERS:
                raise MediaTemplateError(f"placeholder desconhecido: {{{{{name}}}}}")
            token = f"__GMJFLOW_PLACEHOLDER_{len(tokens)}__"
            tokens.append((token, name, in_string))
            output.append(token if in_string else json.dumps(token))
            index = end + 2
            continue
        output.append(char)
        index += 1
    try:
        parsed = json.loads("".join(output))
    except (TypeError, ValueError) as exc:
        raise MediaTemplateError(f"JSON invalido apos render: {exc}") from exc
    formatted = json.dumps(parsed, ensure_ascii=False, indent=2)
    for token, name, embedded in tokens:
        if embedded:
            formatted = formatted.replace(token, "{{" + name + "}}")
        else:
            formatted = formatted.replace(json.dumps(token), "{{" + name + "}}")
    return formatted


def render_payload_from_template(
    template: str,
    data: dict[str, Any] | None,
    *,
    event_type: str,
    is_test: bool = False,
    sent_at: str | None = None,
) -> Any:
    """Renderiza o template com os dados informados e devolve o JSON parseado."""
    context = payload_context(data, event_type=event_type, is_test=is_test, sent_at=sent_at)
    rendered = render_payload_template(template or DEFAULT_PAYLOAD_TEMPLATE, context)
    try:
        payload = json.loads(rendered)
    except (TypeError, ValueError) as exc:
        raise MediaTemplateError(f"JSON invalido apos render: {exc}") from exc
    return payload


def integration_matches(
    integration: Any,
    event_type: str,
    severity: str,
    sensor_id: Any = None,
    sensor_ids: Iterable[int] | None = None,
) -> bool:
    item = dict(integration)
    if not _as_int(item.get("active")):
        return False
    if clean_text(item.get("type") or MEDIA_TYPE_WEBHOOK) != MEDIA_TYPE_WEBHOOK:
        return False
    event_types = normalize_event_types(item.get("event_types"))
    if clean_text(event_type).lower() not in event_types:
        return False
    if severity_rank(severity) < severity_rank(normalize_severity(item.get("minimum_severity"))):
        return False
    return sensor_filter_matches(item, sensor_id, sensor_ids)


def integration_headers(integration: Any) -> dict[str, str]:
    """Monta os headers do POST; o segredo nunca aparece em log."""
    item = dict(integration)
    headers = {"Content-Type": "application/json", "User-Agent": "GMJ-FLOW-Media/1"}
    encrypted = clean_text(item.get("secret_encrypted"))
    if encrypted:
        secret = decrypt_secret(encrypted)
        if secret:
            header_name = clean_text(item.get("secret_header")) or "X-GMJ-Flow-Token"
            headers[header_name] = secret
    return headers


def _crypto():
    from app.services import ai_integration

    return ai_integration


def encrypt_secret(value: str) -> str:
    return _crypto().encrypt_secret(value) if clean_text(value) else ""


def decrypt_secret(value: str) -> str:
    if not clean_text(value):
        return ""
    try:
        return _crypto().decrypt_secret(value)
    except Exception:
        return ""


def mask_secret(value: str) -> str:
    return _crypto().mask_secret(value) if clean_text(value) else ""


def connect() -> sqlite3.Connection:
    from app.services.sqlite_managed import open_managed

    conn = open_managed(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def post_json(url: str, envelope: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    """Executa um POST. Nunca levanta: devolve sempre o resultado da tentativa."""
    started = time.monotonic()
    body = json.dumps(envelope, ensure_ascii=False, default=str).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL validada por validate_webhook_url
            response.read(MAX_RESPONSE_BYTES)
            return {
                "ok": 200 <= int(response.status) < 300,
                "http_status": int(response.status),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "error": "" if 200 <= int(response.status) < 300 else f"HTTP {response.status}",
            }
    except urllib.error.HTTPError as exc:
        try:
            exc.read(MAX_RESPONSE_BYTES)
        except Exception:
            pass
        return {
            "ok": False,
            "http_status": int(exc.code),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": f"HTTP {exc.code} {clean_text(exc.reason)}".strip(),
        }
    except Exception as exc:  # timeout, DNS, refused, TLS, etc.
        return {
            "ok": False,
            "http_status": 0,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}"[:500],
        }


def record_delivery(
    media_id: int,
    event_id: int | None,
    event_type: str,
    result: dict[str, Any],
) -> None:
    """Grava o log de entrega. Falha aqui tambem nao pode propagar."""
    try:
        conn = connect()
        try:
            conn.execute(
                """
                INSERT INTO media_delivery_logs
                    (media_id, event_id, event_type, status, http_status, duration_ms, error, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(media_id),
                    int(event_id) if event_id else None,
                    clean_text(event_type),
                    "success" if result.get("ok") else "error",
                    int(result.get("http_status") or 0),
                    int(result.get("duration_ms") or 0),
                    clean_text(result.get("error"))[:500],
                    utc_now_iso(),
                ),
            )
            conn.execute(
                """
                DELETE FROM media_delivery_logs
                WHERE id NOT IN (SELECT id FROM media_delivery_logs ORDER BY id DESC LIMIT ?)
                """,
                (_LOG_LIMIT,),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def _deliver(job: dict[str, Any]) -> None:
    result = post_json(job["url"], job["envelope"], job["headers"], job["timeout"])
    record_delivery(job["media_id"], job.get("event_id"), job.get("event_type", ""), result)


def _worker_loop() -> None:
    while not _WORKER_STOP.is_set():
        try:
            job = _QUEUE.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            _deliver(job)
        except Exception:
            pass
        finally:
            _QUEUE.task_done()


def start_media_worker() -> None:
    global _WORKER_THREAD
    with _WORKER_LOCK:
        if _WORKER_THREAD is not None and _WORKER_THREAD.is_alive():
            return
        _WORKER_STOP.clear()
        _WORKER_THREAD = threading.Thread(target=_worker_loop, name="media-dispatch", daemon=True)
        _WORKER_THREAD.start()


def stop_media_worker() -> None:
    _WORKER_STOP.set()


def pending_jobs() -> int:
    return _QUEUE.qsize()


def last_dispatch() -> dict[str, Any]:
    return dict(_LAST_DISPATCH)


def track_created(kind: str, entity_id: int) -> None:
    """Marca um evento recem-criado para disparo APOS o commit.

    Chamado pelos pontos de persistencia (upsert_*). O disparo efetivo acontece
    em flush_pending_created(), sempre depois do commit. Nunca levanta excecao.
    """
    try:
        bucket = getattr(_PENDING, "items", None)
        if bucket is None:
            bucket = []
            _PENDING.items = bucket
        if len(bucket) < _PENDING_LIMIT:
            bucket.append((clean_text(kind) or "anomaly_event", int(entity_id or 0)))
    except Exception:
        pass


def pending_created() -> list[tuple[str, int]]:
    return list(getattr(_PENDING, "items", []) or [])


def flush_pending_created(conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Dispara os eventos marcados por track_created. SOMENTE apos o commit.

    Best-effort: qualquer falha e absorvida para nao interromper o detector.
    """
    summary: dict[str, Any] = {"dispatched": 0, "errors": []}
    try:
        bucket = pending_created()
        _PENDING.items = []
        if not bucket:
            return summary
        own_conn = None
        if conn is None:
            own_conn = connect()
            conn = own_conn
        try:
            anomaly_ids = [entity_id for kind, entity_id in bucket if kind == "anomaly_event" and entity_id]
            security_ids = [entity_id for kind, entity_id in bucket if kind == "security_anomaly" and entity_id]
            for ids, dispatcher in (
                (anomaly_ids, dispatch_anomaly_detected),
                (security_ids, dispatch_security_anomaly_detected),
            ):
                if not ids:
                    continue
                result = dispatcher(conn, ids)
                summary["dispatched"] += int(result.get("sent") or 0)
                summary["errors"].extend(result.get("errors") or [])
        finally:
            if own_conn is not None:
                own_conn.close()
    except Exception as exc:
        summary["errors"].append(f"{type(exc).__name__}: {exc}")
    return summary


# ---------------------------------------------------------------------------
# CGNAT: enriquecimento aditivo reutilizando o MESMO resolver do Grafana
# ---------------------------------------------------------------------------
# O resolver canonico (enrich_anomaly_event_with_cgnat ->
# resolve_cgnat_subscriber) vive no modulo principal e e exatamente o mesmo
# usado pelas rotas do Grafana. O import e tardio (via sys.modules) porque o
# modulo principal importa este modulo durante o startup.
_CGNAT_ENRICHER_MODULES = ("app.main", "backend.app.main", "main", "backend_main")


def _cgnat_enricher():
    """Devolve enrich_anomaly_event_with_cgnat sem criar import circular."""
    import sys

    for name in _CGNAT_ENRICHER_MODULES:
        module = sys.modules.get(name)
        if module is None:
            continue
        enricher = getattr(module, "enrich_anomaly_event_with_cgnat", None)
        if callable(enricher):
            return enricher
    return None


def enrich_payload_with_cgnat(
    conn: sqlite3.Connection,
    data: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Aplica o enrichment CGNAT do Grafana ao payload de midia (best-effort).

    Nenhuma regra de lookup e duplicada: a resolucao public_ip/porta -> IP
    privado fica inteiramente em enrich_anomaly_event_with_cgnat. Devolve
    (payload_data, cgnat_block):
      - sem match ou enricher indisponivel: copia intacta de `data` + None,
        preservando o payload legado;
      - com match unico: copia de `data` + campos cgnat_* (para os placeholders)
        + bloco canonico para injetar no envelope.
    Nunca levanta excecao.
    """
    original = dict(data or {})
    enricher = _cgnat_enricher()
    if enricher is None:
        return original, None
    try:
        enriched = enricher(conn, dict(original))
    except Exception:
        return original, None
    if not enriched.get("cgnat_matched") or enriched.get("cgnat_ambiguous"):
        return original, None
    private_ip = clean_text(enriched.get("private_ip"))
    if not private_ip:
        return original, None
    public_port = None
    if enriched.get("public_port") not in (None, ""):
        try:
            public_port = int(enriched.get("public_port"))
        except (TypeError, ValueError):
            public_port = None
    cgnat_block = {
        "resolved": True,
        "public_ip": clean_text(enriched.get("public_ip")),
        "public_port": public_port,
        "private_ip": private_ip,
        "device_name": clean_text(enriched.get("cgnat_device_name")),
        "pool_name": clean_text(enriched.get("cgnat_pool_name")),
        "confidence": _as_float(enriched.get("cgnat_confidence")),
    }
    payload_data = dict(original)
    payload_data.update(
        {
            "cgnat_resolved": True,
            "cgnat_public_ip": cgnat_block["public_ip"],
            "cgnat_public_port": public_port,
            "cgnat_private_ip": private_ip,
            "cgnat_pool_name": cgnat_block["pool_name"],
            "cgnat_device_name": cgnat_block["device_name"],
            "cgnat_confidence": cgnat_block["confidence"],
        }
    )
    return payload_data, cgnat_block


def inject_cgnat_block(envelope: Any, cgnat_block: dict[str, Any] | None) -> Any:
    """Acrescenta `data.cgnat` ao envelope renderizado, de forma aditiva.

    Age somente com match CGNAT e quando o envelope possui um objeto `data`
    (template padrao ou template customizado que mantem a secao `data`).
    Templates que reestruturam o payload podem optar pelos placeholders
    {{cgnat_*}}; sem match CGNAT nada e alterado.
    """
    if not cgnat_block or not isinstance(envelope, dict):
        return envelope
    section = envelope.get("data")
    if isinstance(section, dict) and "cgnat" not in section:
        section["cgnat"] = cgnat_block
    return envelope


def enrich_payload_with_correlation(
    conn: sqlite3.Connection,
    data: dict[str, Any],
    *,
    table: str,
    anomaly_id: int | None,
    anomaly: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Propaga a correlation canonica do core para o payload de midia.

    Nenhuma logica de correlacao vive aqui: quando o payload ja traz
    `correlation`, ele e mantido sem nova consulta (nao re-resolve); caso
    contrario, reutiliza o MESMO resolver das APIs
    (anomaly_correlation.resolve_anomaly_correlation) e copia o dict devolvido
    sem alterar a estrutura. Sem resultado, devolve o payload intacto.
    Nunca levanta excecao.
    """
    payload = dict(data or {})
    if payload.get("correlation") is not None:
        return payload
    try:
        from app.services import anomaly_correlation

        correlation = anomaly_correlation.resolve_anomaly_correlation(
            conn, table, anomaly_id, anomaly=anomaly if anomaly is not None else payload
        )
    except Exception:
        return payload
    if isinstance(correlation, dict) and correlation:
        payload["correlation"] = correlation
    return payload


def inject_correlation_block(envelope: Any, correlation: Any) -> Any:
    """Acrescenta `data.correlation` ao envelope renderizado, de forma aditiva.

    So age com `correlation` (dict do core) e quando o envelope possui um
    objeto `data` (template padrao ou template customizado que mantem a
    secao `data`). Sem correlation, nada e alterado; a estrutura interna do
    dict nao e modificada nem flattenada.
    """
    if not isinstance(correlation, dict) or not correlation or not isinstance(envelope, dict):
        return envelope
    section = envelope.get("data")
    if isinstance(section, dict) and "correlation" not in section:
        section["correlation"] = correlation
    return envelope


def dispatch_media_event(
    event_type: str,
    data: dict[str, Any],
    *,
    event_id: int | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    """Ponto unico de disparo. Best-effort: nunca levanta excecao.

    Deve ser chamado DEPOIS do commit do evento. Retorna sempre um resumo.
    """
    summary: dict[str, Any] = {"event_type": clean_text(event_type), "matched": 0, "queued": 0, "skipped": 0, "errors": []}
    try:
        start_media_worker()
        event_key = clean_text(event_type).lower()
        if event_key not in MEDIA_EVENT_TYPES:
            summary["errors"].append(f"evento nao suportado: {event_key}")
            return summary
        event_severity = clean_text(severity) or clean_text((data or {}).get("severity")) or "info"
        event_sensor_id = (data or {}).get("sensor_id")
        conn = connect()
        try:
            rows = conn.execute("SELECT * FROM media_integrations ORDER BY id").fetchall()
            sensor_map = load_destination_sensor_map(conn)
            payload_data = dict(data or {})
            if event_id and not _as_int(payload_data.get("event_id")):
                payload_data["event_id"] = _as_int(event_id)
            cgnat_block: dict[str, Any] | None = None
            if rows:
                # Enriquecimento aditivo com o MESMO resolver CGNAT do Grafana.
                payload_data, cgnat_block = enrich_payload_with_cgnat(conn, payload_data)
        finally:
            conn.close()
        for row in rows:
            item = dict(row)
            if not integration_matches(
                item,
                event_key,
                event_severity,
                sensor_id=event_sensor_id,
                sensor_ids=sensor_map.get(int(item["id"])),
            ):
                continue
            summary["matched"] += 1
            try:
                # Defesa em profundidade: a URL ja e validada ao salvar o destino,
                # mas revalidamos no disparo para nunca postar em alvo perigoso.
                url = validate_webhook_url(item.get("url"))
                template = clean_text(item.get("payload_template")) or DEFAULT_PAYLOAD_TEMPLATE
                try:
                    envelope = render_payload_from_template(template, payload_data, event_type=event_key)
                except MediaTemplateError as exc:
                    summary["errors"].append(
                        f"destino {item.get('id')}: template invalido ({exc}); usando padrao"
                    )
                    envelope = render_payload_from_template(
                        DEFAULT_PAYLOAD_TEMPLATE, payload_data, event_type=event_key
                    )
                envelope = inject_cgnat_block(envelope, cgnat_block)
                envelope = inject_correlation_block(envelope, payload_data.get("correlation"))
                job = {
                    "media_id": int(item["id"]),
                    "event_id": int(event_id) if event_id else None,
                    "event_type": event_key,
                    "url": url,
                    "headers": integration_headers(item),
                    "timeout": normalize_timeout(item.get("timeout_seconds")),
                    "envelope": envelope,
                }
                _QUEUE.put_nowait(job)
                summary["queued"] += 1
            except queue.Full:
                summary["errors"].append(f"fila cheia; destino {item.get('id')} ignorado")
            except Exception as exc:
                summary["errors"].append(f"destino {item.get('id')}: {type(exc).__name__}")
    except Exception as exc:  # barreira final: o detector jamais quebra por causa da midia
        summary["errors"].append(f"{type(exc).__name__}: {exc}")
    _LAST_DISPATCH.clear()
    _LAST_DISPATCH.update({**summary, "at": utc_now_iso()})
    return summary


def dispatch_anomaly_detected(conn: sqlite3.Connection, anomaly_ids: Iterable[int]) -> dict[str, Any]:
    """Dispara `anomaly_detected` para ids de anomaly_events ja persistidos."""
    result: dict[str, Any] = {"event_type": "anomaly_detected", "sent": 0, "errors": []}
    for anomaly_id in list(anomaly_ids or []):
        try:
            row = conn.execute("SELECT * FROM anomaly_events WHERE id = ?", (int(anomaly_id),)).fetchone()
            if row is not None:
                row = with_sensor_fields(conn, row)
            if row is None:
                continue
            data = anomaly_event_data(row)
            # Correlation canonica do core: apenas propagada (sem recalculo).
            data = enrich_payload_with_correlation(
                conn, data, table="anomaly_events", anomaly_id=int(anomaly_id), anomaly=dict(row)
            )
            dispatch_media_event("anomaly_detected", data, event_id=int(anomaly_id), severity=data.get("severity"))
            result["sent"] += 1
        except Exception as exc:
            result["errors"].append(f"{anomaly_id}: {type(exc).__name__}")
    return result


def dispatch_security_anomaly_detected(conn: sqlite3.Connection, anomaly_ids: Iterable[int]) -> dict[str, Any]:
    """Variante para security_anomalies (mesmo evento publico)."""
    result: dict[str, Any] = {"event_type": "anomaly_detected", "sent": 0, "errors": []}
    for anomaly_id in list(anomaly_ids or []):
        try:
            row = conn.execute("SELECT * FROM security_anomalies WHERE id = ?", (int(anomaly_id),)).fetchone()
            if row is not None:
                row = with_sensor_fields(conn, row)
            if row is None:
                continue
            data = anomaly_event_data(row)
            # Correlation canonica do core: apenas propagada (sem recalculo).
            data = enrich_payload_with_correlation(
                conn, data, table="security_anomalies", anomaly_id=int(anomaly_id), anomaly=dict(row)
            )
            dispatch_media_event("anomaly_detected", data, event_id=int(anomaly_id), severity=data.get("severity"))
            result["sent"] += 1
        except Exception as exc:
            result["errors"].append(f"{anomaly_id}: {type(exc).__name__}")
    return result


def test_media_integration(integration: Any, *, sample_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Envia um payload de exemplo para um destino. Sincrono, para a tela de teste.

    O sample padrao (TEST_DESTINATION_SAMPLE) segue o mesmo formato logico de
    uma anomalia real e passa pelo MESMO enriquecimento CGNAT do envio real e
    do preview (enrich_payload_with_cgnat -> enrich_anomaly_event_with_cgnat);
    nenhuma regra de lookup e duplicada aqui.
    """
    item = dict(integration)
    try:
        url = validate_webhook_url(item.get("url"))
    except MediaUrlError as exc:
        return {"ok": False, "http_status": 0, "duration_ms": 0, "error": str(exc)}
    sample = dict(TEST_DESTINATION_SAMPLE)
    if sample_data:
        sample.update({key: value for key, value in dict(sample_data).items() if value is not None})
    else:
        sample["severity"] = normalize_severity(item.get("minimum_severity"))
    cgnat_block: dict[str, Any] | None = None
    try:
        conn = connect()
        try:
            # Mesmo enriquecimento CGNAT do envio real/preview (reuso; nada duplicado).
            sample, cgnat_block = enrich_payload_with_cgnat(conn, sample)
        finally:
            conn.close()
    except Exception:
        cgnat_block = None
    template = clean_text(item.get("payload_template")) or DEFAULT_PAYLOAD_TEMPLATE
    try:
        envelope = render_payload_from_template(template, sample, event_type="anomaly_detected", is_test=True)
    except MediaTemplateError:
        envelope = render_payload_from_template(
            DEFAULT_PAYLOAD_TEMPLATE, sample, event_type="anomaly_detected", is_test=True
        )
    envelope = inject_cgnat_block(envelope, cgnat_block)
    envelope = inject_correlation_block(envelope, sample.get("correlation"))
    return post_json(url, envelope, integration_headers(item), normalize_timeout(item.get("timeout_seconds")))


# ---------------------------------------------------------------------------
# Ferramentas administrativas de teste (nao entram no pipeline de deteccao)
# ---------------------------------------------------------------------------
TELEGRAM_API_BASE = "https://api.telegram.org"
TELEGRAM_TIMEOUT_SECONDS = 10.0


def scrub_secret(value: Any, secret: str) -> str:
    """Remove qualquer ocorrencia do segredo de um texto que possa ser exibido."""
    text = clean_text(value)
    secret = clean_text(secret)
    if secret and secret in text:
        text = text.replace(secret, "***")
    return text


def send_test_event(data: dict[str, Any]) -> dict[str, Any]:
    """Envia um evento de TESTE para os destinos ativos.

    Uso administrativo: NAO grava anomalia, NAO passa pelo detector e NAO aciona
    mitigacao. Reaproveita exatamente o mesmo envio dos eventos reais, incluindo
    o MESMO enriquecimento CGNAT (enrich_payload_with_cgnat): o envelope
    devolvido expoe `data.cgnat` e os placeholders {{cgnat_*}} quando ha match.

    A chave "test" NAO e injetada: se o template do destino declarar
    "test": {{test}}, ela vira true aqui (e false em producao); se nao declarar,
    nao aparece no JSON.

    O dicionario recebido vence o sample (inclusive valores None), para que o
    chamador possa representar explicitamente "sem sensor" sem que o sample
    invente um sensor.
    """
    # Contrato publico do evento de teste: sempre event_id=0 e status="test".
    payload_data: dict[str, Any] = dict(TEST_SAMPLE_EVENT)
    payload_data["event_id"] = 0
    payload_data["status"] = "test"
    payload_data.update(dict(data or {}))
    results: list[dict[str, Any]] = []
    representative: Any = None
    cgnat_block: dict[str, Any] | None = None
    severity = clean_text(payload_data.get("severity")) or "info"
    sensor_id = payload_data.get("sensor_id")

    def _representative(template_value: str) -> Any:
        try:
            envelope = render_payload_from_template(
                template_value or DEFAULT_PAYLOAD_TEMPLATE,
                payload_data,
                event_type="anomaly_detected",
                is_test=True,
            )
        except MediaTemplateError:
            envelope = render_payload_from_template(
                DEFAULT_PAYLOAD_TEMPLATE, payload_data, event_type="anomaly_detected", is_test=True
            )
        envelope = inject_cgnat_block(envelope, cgnat_block)
        return inject_correlation_block(envelope, payload_data.get("correlation"))

    try:
        conn = connect()
        try:
            rows = conn.execute("SELECT * FROM media_integrations ORDER BY id").fetchall()
            sensor_map = load_destination_sensor_map(conn)
            # Mesmo enriquecimento CGNAT do envio real (reuso; nada duplicado).
            payload_data, cgnat_block = enrich_payload_with_cgnat(conn, payload_data)
        finally:
            conn.close()
        for row in rows:
            item = dict(row)
            if not integration_matches(
                item,
                "anomaly_detected",
                severity,
                sensor_id=sensor_id,
                sensor_ids=sensor_map.get(int(item["id"])),
            ):
                continue
            entry: dict[str, Any] = {
                "media_id": int(item["id"]),
                "name": clean_text(item.get("name")),
                "ok": False,
                "http_status": 0,
                "duration_ms": 0,
                "error": None,
            }
            try:
                url = validate_webhook_url(item.get("url"))
                envelope = _representative(clean_text(item.get("payload_template")))
                if representative is None:
                    representative = envelope
                result = post_json(url, envelope, integration_headers(item), normalize_timeout(item.get("timeout_seconds")))
                entry["ok"] = bool(result.get("ok"))
                entry["http_status"] = int(result.get("http_status") or 0)
                entry["duration_ms"] = int(result.get("duration_ms") or 0)
                entry["error"] = clean_text(result.get("error")) or None
                record_delivery(int(item["id"]), None, "test", result)
            except Exception as exc:
                entry["error"] = f"{type(exc).__name__}: {exc}"[:300]
            results.append(entry)
    except Exception as exc:
        if representative is None:
            representative = _representative(DEFAULT_PAYLOAD_TEMPLATE)
        return {"envelope": representative, "results": results, "errors": [f"{type(exc).__name__}: {exc}"]}
    if representative is None:
        representative = _representative(DEFAULT_PAYLOAD_TEMPLATE)
    return {"envelope": representative, "results": results}


def send_telegram_message(bot_token: str, chat_id: str, text: str) -> dict[str, Any]:
    """Envia UMA mensagem pela Bot API. O token nunca e persistido nem logado."""
    token = clean_text(bot_token)
    if not token:
        return {"ok": False, "http_status": 0, "duration_ms": 0, "error": "bot token vazio"}
    url = f"{TELEGRAM_API_BASE}/bot{token}/sendMessage"
    body = {"chat_id": clean_text(chat_id), "text": clean_text(text)}
    try:
        result = post_json(url, body, {"Content-Type": "application/json"}, TELEGRAM_TIMEOUT_SECONDS)
    except Exception as exc:  # post_json nao levanta, mas a barreira fica explicita
        result = {"ok": False, "http_status": 0, "duration_ms": 0, "error": f"{type(exc).__name__}"}
    result["error"] = scrub_secret(result.get("error"), token)
    return result
