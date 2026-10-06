"""Correlacao canonica de anomalias: sujeito real, ocorrencias e reincidencia.

Este modulo implementa o CORE de correlacao (fase "reincidencia por sujeito
real") sem dependencia do ``app.main`` para permitir testes puros:

- schema idempotente da tabela ``anomaly_occurrences`` (historico de ocorrencias);
- derivacao canonica do sujeito da anomalia (``ip``, ``prefix``, ``cgnat_*``);
- resolucao CGNAT reutilizando ``resolve_cgnat_subscriber`` (semantica canonica
  ``public_ip + port + protocol + timestamp``);
- registro/atualizacao de ocorrencias distinguindo CONTINUACAO (novo match da
  mesma ocorrencia) de REINCIDENCIA (encerramento real ou gap relevante);
- summary de correlacao para API (``correlation``), backward-compatible.

Conceitos:
- Ocorrencia: ciclo de vida continuo de deteccao (1 row de ``security_anomalies``
  ou ``anomaly_events`` pode conter varias ocorrencias ao longo do tempo).
- Continuacao: mesmo ciclo, ``last_seen`` avanca. Nao incrementa reincidencia.
- Reincidencia: a ocorrencia anterior encerrou (``ended_at``) ou houve gap
  maior que ``GMJFLOW_OCCURRENCE_GAP_SECONDS`` (default:
  ``GMJFLOW_ANOMALY_CLOSE_AFTER_SECONDS`` ou 300s).
- Dia operacional: data local em ``America/Sao_Paulo`` (mesma constante
  canonica ``ANOMALY_TIME_ZONE_NAME`` usada pelo restante do sistema).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

try:  # pragma: no cover - fallback defensivo para ambientes sem tzdata
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore[assignment]

from app.services.cgnat_mapping import ensure_cgnat_schema, resolve_cgnat_subscriber

logger = logging.getLogger(__name__)

OPERATIONAL_TIME_ZONE_NAME = "America/Sao_Paulo"
if ZoneInfo is not None:
    try:
        OPERATIONAL_TIME_ZONE = ZoneInfo(OPERATIONAL_TIME_ZONE_NAME)
    except Exception:  # pragma: no cover - ambientes sem tzdata
        OPERATIONAL_TIME_ZONE = timezone(timedelta(hours=-3), OPERATIONAL_TIME_ZONE_NAME)
else:  # pragma: no cover
    OPERATIONAL_TIME_ZONE = timezone(timedelta(hours=-3), OPERATIONAL_TIME_ZONE_NAME)

ANOMALY_OCCURRENCES_SCHEMA_VERSION = 1
BACKFILL_FLAG_KEY = "anomaly_correlation_backfill_v1"
DEFAULT_DETAILS_LIMIT = 3
DEFAULT_GAP_SECONDS = 300
SEVERITY_RANK = {"critical": 3, "warning": 2, "info": 1}

SUBJECT_TYPE_IP = "ip"
SUBJECT_TYPE_PREFIX = "prefix"
SUBJECT_TYPE_CGNAT_SUBSCRIBER = "cgnat_subscriber"
SUBJECT_TYPE_CGNAT_PRIVATE_IP = "cgnat_private_ip"
SUBJECT_TYPE_CGNAT_PUBLIC_IP = "cgnat_public_ip"

# Cache por processo/DB: o DDL roda uma unica vez por banco para nao disparar
# commit implicito do pysqlite no meio das transacoes de deteccao.
_SCHEMA_READY_PATHS: set[str] = set()


def _clean(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _clean_ip(value: Any) -> str:
    text = _clean(value)
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _float_or_none(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_datetime_text(value: Any) -> datetime | None:
    """Converte texto ISO (com 'Z' ou offset) para datetime UTC aware."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        text = _clean(value)
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _iso(_now())


def operational_day(value: Any) -> str:
    """Dia operacional (America/Sao_Paulo) de um timestamp; '' se invalido."""
    parsed = parse_datetime_text(value)
    if parsed is None:
        return ""
    return parsed.astimezone(OPERATIONAL_TIME_ZONE).date().isoformat()


def occurrence_gap_seconds() -> int:
    raw = os.getenv("GMJFLOW_OCCURRENCE_GAP_SECONDS") or os.getenv("GMJFLOW_ANOMALY_CLOSE_AFTER_SECONDS") or str(DEFAULT_GAP_SECONDS)
    try:
        return max(5, int(raw))
    except ValueError:
        return DEFAULT_GAP_SECONDS


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    try:
        row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (name,)).fetchone()
    except sqlite3.Error:
        return False
    return row is not None


def _connection_database_key(conn: sqlite3.Connection) -> str:
    try:
        row = conn.execute("PRAGMA database_list").fetchone()
        value = row["file"] if isinstance(row, sqlite3.Row) else row[2]
        return _clean(value) or f"connection:{id(conn)}"
    except Exception:
        return f"connection:{id(conn)}"


def reset_schema_cache() -> None:
    """Limpa o cache de schema por processo (uso em testes e migracoes)."""
    _SCHEMA_READY_PATHS.clear()


def ensure_anomaly_correlation_schema(conn: sqlite3.Connection) -> None:
    """Cria (idempotente) a tabela de ocorrencias e executa o backfill one-time."""
    database_key = _connection_database_key(conn)
    if database_key in _SCHEMA_READY_PATHS:
        return
    try:
        ensure_cgnat_schema(conn)
    except Exception:
        logger.warning("Schema CGNAT indisponivel ao preparar correlacao de anomalias", exc_info=True)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS anomaly_occurrences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_table TEXT NOT NULL,
            anomaly_id INTEGER NOT NULL,
            vector_key TEXT NOT NULL,
            dedupe_key TEXT NOT NULL DEFAULT '',
            subject_type TEXT NOT NULL,
            subject_key TEXT NOT NULL,
            subject_confidence TEXT NOT NULL DEFAULT 'high',
            subject_context_json TEXT NOT NULL DEFAULT '{}',
            operational_day TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            ended_at TEXT,
            severity TEXT NOT NULL DEFAULT '',
            metric TEXT NOT NULL DEFAULT '',
            metric_peak REAL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_anomaly_occurrences_lookup "
        "ON anomaly_occurrences(vector_key, subject_key, operational_day, first_seen)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_anomaly_occurrences_row "
        "ON anomaly_occurrences(anomaly_table, anomaly_id, first_seen)"
    )
    backfill_anomaly_occurrences(conn)
    _SCHEMA_READY_PATHS.add(database_key)


# ---------------------------------------------------------------------------
# Sujeito canonico
# ---------------------------------------------------------------------------


def _anomaly_vector_name(anomaly: Mapping[str, Any], table: str = "") -> str:
    return _clean(
        anomaly.get("vector")
        or anomaly.get("vector_name")
        or anomaly.get("attack_vector_name")
        or anomaly.get("rule_name")
        or anomaly.get("decoder")
    )


def anomaly_vector_key(anomaly: Mapping[str, Any], table: str = "") -> str:
    """Chave normalizada do vetor/regra usada no escopo de correlacao (V1)."""
    return _anomaly_vector_name(anomaly, table).upper()


def _subject_ip_candidate(anomaly: Mapping[str, Any], table: str) -> dict[str, Any]:
    """Deriva o IP/porta canonicos do sujeito conforme direcao/papel da regra."""
    src_ip = _clean_ip(anomaly.get("top_src_ip") or anomaly.get("src_ip"))
    dst_ip = _clean_ip(anomaly.get("top_dst_ip") or anomaly.get("dst_ip"))
    target_ip = _clean_ip(anomaly.get("target_ip"))
    role = _clean(anomaly.get("target_role")).lower()
    direction = _clean(anomaly.get("direction")).lower()
    src_port = _int_or_none(anomaly.get("top_src_port") or anomaly.get("src_port"))
    dst_port = _int_or_none(anomaly.get("top_dst_port") or anomaly.get("target_port") or anomaly.get("dst_port"))
    if direction in ("receives", "inbound") or role == "dst_ip":
        return {"ip": target_ip or dst_ip, "port": dst_port, "role": "dst"}
    if direction in ("transmits", "sends", "outbound") or role == "src_ip":
        return {"ip": target_ip or src_ip or dst_ip, "port": src_port, "role": "src"}
    if src_ip:
        return {"ip": src_ip, "port": src_port, "role": "src"}
    if dst_ip or target_ip:
        return {"ip": target_ip or dst_ip, "port": dst_port, "role": "dst"}
    return {"ip": "", "port": None, "role": ""}


def _prefix_candidate(anomaly: Mapping[str, Any], table: str) -> str:
    domain = _clean(anomaly.get("domain")).lower()
    if table == "security_anomalies" and domain not in ("subnet", "prefix"):
        return ""
    if domain in ("subnet", "prefix"):
        cidr = _clean(anomaly.get("prefix_cidr") or anomaly.get("target_cidr"))
        if cidr:
            try:
                return str(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                return ""
    return ""


def _active_pool_networks(conn: sqlite3.Connection) -> list[Any]:
    try:
        rows = conn.execute("SELECT prefix FROM cgnat_pools WHERE active = 1").fetchall()
    except sqlite3.Error:
        return []
    networks: list[Any] = []
    for row in rows:
        prefix = _clean(row[0] if not isinstance(row, sqlite3.Row) else row["prefix"])
        try:
            networks.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            continue
    return networks


def _cgnat_pool_matches(
    conn: sqlite3.Connection,
    ip_text: str,
    *,
    pool_networks: list[Any] | None = None,
) -> list[str]:
    if not ip_text:
        return []
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError:
        return []
    networks = _active_pool_networks(conn) if pool_networks is None else pool_networks
    matches: list[str] = []
    for network in networks:
        if address.version == network.version and address in network:
            matches.append(str(network))
    return matches


def resolve_subject_for_anomaly(
    conn: sqlite3.Connection,
    anomaly: Mapping[str, Any],
    *,
    table: str,
    resolve_cgnat: bool = True,
    pool_networks: list[Any] | None = None,
) -> dict[str, Any]:
    """Resolve o sujeito canonico de uma anomalia (persistivel).

    Retorna ``subject_type``, ``subject_key``, ``subject_confidence`` e
    ``subject_context``. Quando o IP sujeito pertence a um pool CGNAT ativo,
    tenta a resolucao canonica (public_ip + porta + protocolo + timestamp);
    se nao resolver, usa o IP publico como fallback com confianca menor.
    """
    direction = _clean(anomaly.get("direction")).lower()
    protocol = _clean(anomaly.get("protocol")).lower()
    prefix_key = _prefix_candidate(anomaly, table)
    candidate = _subject_ip_candidate(anomaly, table)
    ip_text = candidate["ip"]
    port = candidate["port"]
    ts_text = _clean(anomaly.get("first_seen") or anomaly.get("started_at") or anomaly.get("last_seen") or anomaly.get("last_seen_at"))

    context: dict[str, Any] = {
        "role": candidate["role"],
        "direction": direction,
        "ip": ip_text,
        "port": port,
        "protocol": protocol,
    }
    if prefix_key:
        return {
            "subject_type": SUBJECT_TYPE_PREFIX,
            "subject_key": prefix_key,
            "subject_confidence": "high",
            "subject_context": {**context, "prefix": prefix_key},
        }
    if not ip_text:
        return {
            "subject_type": SUBJECT_TYPE_IP,
            "subject_key": "",
            "subject_confidence": "low",
            "subject_context": {**context, "reason": "subject_unresolved"},
        }
    pool_matches = _cgnat_pool_matches(conn, ip_text, pool_networks=pool_networks) if resolve_cgnat else []
    if not pool_matches:
        return {
            "subject_type": SUBJECT_TYPE_IP,
            "subject_key": ip_text,
            "subject_confidence": "high",
            "subject_context": context,
        }
    cgnat_context: dict[str, Any] = {
        "in_pool": True,
        "pool": pool_matches[0],
        "pools": pool_matches,
        "resolved": False,
        "public_ip": ip_text,
        "public_port": port,
    }
    if port is None or not (0 <= int(port) <= 65535):
        cgnat_context["reason"] = "no_public_port"
    elif protocol not in ("tcp", "udp", "icmp", "any"):
        cgnat_context["reason"] = "no_protocol"
    else:
        try:
            lookup = resolve_cgnat_subscriber(conn, ip_text, port, protocol, ts_text, ensure_schema=False)
        except Exception as exc:  # pragma: no cover - defensivo
            lookup = {"matched": False, "error": f"resolver_error:{exc}"}
        if lookup.get("matched") and not lookup.get("ambiguous"):
            private_ip = _clean(lookup.get("private_ip"))
            subscriber_id = _clean(lookup.get("subscriber_id"))
            mapping_confidence = _float_or_none(lookup.get("confidence")) or 0.0
            confidence = "high" if mapping_confidence >= 0.9 else ("medium" if mapping_confidence >= 0.5 else "low")
            if not private_ip and not subscriber_id:
                cgnat_context["reason"] = "empty_identity"
            else:
                cgnat_context.update(
                    {
                        "resolved": True,
                        "private_ip": private_ip,
                        "subscriber_id": subscriber_id,
                        "subscriber_name": _clean(lookup.get("subscriber_name")),
                        "pool_name": _clean(lookup.get("pool_name")),
                        "device_name": _clean(lookup.get("device_name")),
                        "source_type": _clean(lookup.get("source_type")),
                        "batch_id": _int_or_none(lookup.get("batch_id")),
                        "port_start": _int_or_none(lookup.get("port_start")),
                        "port_end": _int_or_none(lookup.get("port_end")),
                        "mapping_confidence": mapping_confidence,
                    }
                )
                if subscriber_id:
                    return {
                        "subject_type": SUBJECT_TYPE_CGNAT_SUBSCRIBER,
                        "subject_key": subscriber_id,
                        "subject_confidence": confidence,
                        "subject_context": {**context, "cgnat": cgnat_context},
                    }
                return {
                    "subject_type": SUBJECT_TYPE_CGNAT_PRIVATE_IP,
                    "subject_key": private_ip,
                    "subject_confidence": confidence,
                    "subject_context": {**context, "cgnat": cgnat_context},
                }
        elif lookup.get("ambiguous"):
            cgnat_context["reason"] = "ambiguous_mapping"
        else:
            cgnat_context["reason"] = _clean(lookup.get("error")) or "no_mapping"
    return {
        "subject_type": SUBJECT_TYPE_CGNAT_PUBLIC_IP,
        "subject_key": ip_text,
        "subject_confidence": "low",
        "subject_context": {**context, "cgnat": cgnat_context, "fallback": True},
    }


# ---------------------------------------------------------------------------
# Metricas e severidade
# ---------------------------------------------------------------------------


def _severity_rank(severity: Any) -> int:
    return SEVERITY_RANK.get(_clean(severity).lower(), 0)


def _max_severity(current: Any, incoming: Any) -> str:
    if _severity_rank(incoming) > _severity_rank(current):
        return _clean(incoming).lower()
    return _clean(current).lower()


def _metric_from_anomaly(anomaly: Mapping[str, Any]) -> str:
    explicit = _clean(anomaly.get("metric") or anomaly.get("metric_unit") or anomaly.get("threshold_unit"))
    if explicit:
        return explicit
    for key in ("packets_s", "bits_s", "flows_s", "flows", "pps", "bps", "packets", "bytes"):
        if anomaly.get(key) not in (None, ""):
            return key
    return ""


def _metric_value_from_anomaly(anomaly: Mapping[str, Any], metric: str, explicit: Any = None) -> float | None:
    if explicit is not None:
        value = _float_or_none(explicit)
        if value is not None:
            return value
    for key in (metric, "peak_value", "observed_value", "packets_s", "bits_s", "flows_s", "flows", "packets", "bytes"):
        if not key:
            continue
        value = _float_or_none(anomaly.get(key))
        if value is not None:
            return value
    return None


# ---------------------------------------------------------------------------
# Registro de ocorrencias
# ---------------------------------------------------------------------------


def _latest_occurrence(conn: sqlite3.Connection, table: str, anomaly_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT *
        FROM anomaly_occurrences
        WHERE anomaly_table = ? AND anomaly_id = ?
        ORDER BY first_seen DESC, id DESC
        LIMIT 1
        """,
        (table, anomaly_id),
    ).fetchone()


def record_anomaly_occurrence(
    conn: sqlite3.Connection,
    *,
    anomaly_table: str,
    anomaly_id: int,
    anomaly: Mapping[str, Any],
    first_seen: Any = None,
    last_seen: Any = None,
    severity: Any = None,
    metric: Any = None,
    metric_value: Any = None,
    gap_seconds: int | None = None,
) -> str:
    """Registra um match de anomalia como continuacao ou nova ocorrencia.

    Retorna ``"continued"``, ``"started"`` ou ``"skipped"``.
    """
    anomaly_id = _int_or_none(anomaly_id)
    if anomaly_id is None or anomaly_id <= 0 or not anomaly_table:
        return "skipped"
    ensure_anomaly_correlation_schema(conn)
    vector_key = anomaly_vector_key(anomaly, anomaly_table)
    if not vector_key:
        return "skipped"
    last_dt = parse_datetime_text(last_seen) or _now()
    start_dt = parse_datetime_text(first_seen) or last_dt
    if start_dt > last_dt:
        start_dt = last_dt
    resolved_severity = _clean(severity).lower() or _clean(anomaly.get("severity")).lower()
    resolved_metric = _clean(metric) or _metric_from_anomaly(anomaly)
    resolved_metric_value = _metric_value_from_anomaly(anomaly, resolved_metric, metric_value)
    gap = occurrence_gap_seconds() if gap_seconds is None else max(1, int(gap_seconds))
    existing = _latest_occurrence(conn, anomaly_table, anomaly_id)
    now_iso = _now_iso()
    if existing is not None and not _clean(existing["ended_at"]):
        previous_last = parse_datetime_text(existing["last_seen"])
        if previous_last is not None and (last_dt - previous_last) <= timedelta(seconds=gap):
            new_last = max(previous_last, last_dt)
            peak = _float_or_none(existing["metric_peak"])
            if resolved_metric_value is not None:
                peak = resolved_metric_value if peak is None else max(peak, resolved_metric_value)
            kept_metric = _clean(existing["metric"]) or resolved_metric
            conn.execute(
                """
                UPDATE anomaly_occurrences
                SET last_seen = ?, severity = ?, metric = ?, metric_peak = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    _iso(new_last),
                    _max_severity(existing["severity"], resolved_severity),
                    kept_metric,
                    peak,
                    now_iso,
                    int(existing["id"]),
                ),
            )
            return "continued"
    subject = resolve_subject_for_anomaly(conn, anomaly, table=anomaly_table)
    conn.execute(
        """
        INSERT INTO anomaly_occurrences (
            anomaly_table, anomaly_id, vector_key, dedupe_key,
            subject_type, subject_key, subject_confidence, subject_context_json,
            operational_day, first_seen, last_seen, ended_at,
            severity, metric, metric_peak, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
        """,
        (
            anomaly_table,
            anomaly_id,
            vector_key,
            _clean(anomaly.get("dedupe_key")),
            subject["subject_type"],
            subject["subject_key"],
            subject["subject_confidence"],
            json.dumps(subject["subject_context"], sort_keys=True, default=str),
            operational_day(start_dt),
            _iso(start_dt),
            _iso(last_dt),
            resolved_severity,
            resolved_metric,
            resolved_metric_value,
            now_iso,
            now_iso,
        ),
    )
    return "started"


def record_occurrence_safe(conn: sqlite3.Connection, **kwargs: Any) -> str:
    """Versao fail-safe usada nos caminhos de deteccao (nunca derruba o ciclo).

    O schema e preparado ANTES do savepoint: DDL dispara commit implicito no
    pysqlite e liberaria o savepoint no meio da transacao de deteccao.
    """
    try:
        ensure_anomaly_correlation_schema(conn)
    except Exception:
        logger.exception("Falha ao preparar schema de correlacao de anomalias")
        return "error"
    try:
        conn.execute("SAVEPOINT anomaly_occurrence_record")
        try:
            action = record_anomaly_occurrence(conn, **kwargs)
        except Exception:
            conn.execute("ROLLBACK TO SAVEPOINT anomaly_occurrence_record")
            raise
        finally:
            try:
                conn.execute("RELEASE SAVEPOINT anomaly_occurrence_record")
            except sqlite3.OperationalError:
                logger.debug("Savepoint de ocorrencia ja liberado por commit implicito")
        return action
    except Exception:
        logger.exception("Falha ao registrar ocorrencia de anomalia (tabela=%s)", kwargs.get("anomaly_table"))
        return "error"


def mark_occurrences_ended(
    conn: sqlite3.Connection,
    anomaly_table: str,
    anomaly_ids: list[int] | tuple[int, ...],
    ended_at: Any = None,
) -> int:
    """Marca a ocorrencia ATUAL (aberta) das anomalias como encerrada."""
    ids = [int(value) for value in anomaly_ids if _int_or_none(value) is not None and int(value) > 0]
    if not ids or not anomaly_table:
        return 0
    ensure_anomaly_correlation_schema(conn)
    ended_iso = _iso(parse_datetime_text(ended_at) or _now())
    updated = 0
    for anomaly_id in ids:
        row = conn.execute(
            """
            SELECT id
            FROM anomaly_occurrences
            WHERE anomaly_table = ? AND anomaly_id = ? AND (ended_at IS NULL OR ended_at = '')
            ORDER BY first_seen DESC, id DESC
            LIMIT 1
            """,
            (anomaly_table, anomaly_id),
        ).fetchone()
        if row is None:
            continue
        conn.execute(
            "UPDATE anomaly_occurrences SET ended_at = ?, updated_at = ? WHERE id = ?",
            (ended_iso, _now_iso(), int(row["id"])),
        )
        updated += 1
    return updated


# ---------------------------------------------------------------------------
# Correlacao (leitura / API)
# ---------------------------------------------------------------------------


def _occurrence_to_previous_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "occurrence_id": int(row["id"]),
        "anomaly_id": int(row["anomaly_id"]),
        "anomaly_table": _clean(row["anomaly_table"]),
        "first_seen": _clean(row["first_seen"]),
        "last_seen": _clean(row["last_seen"]),
        "ended_at": _clean(row["ended_at"]) or None,
        "severity": _clean(row["severity"]),
        "metric": _clean(row["metric"]),
        "metric_value": _float_or_none(row["metric_peak"]),
    }


def _correlation_payload(
    conn: sqlite3.Connection,
    *,
    vector_key: str,
    subject_type: str,
    subject_key: str,
    subject_confidence: str,
    subject_context: Mapping[str, Any] | None,
    day: str,
    exclude_id: int | None = None,
    details_limit: int = DEFAULT_DETAILS_LIMIT,
) -> dict[str, Any]:
    clauses = ["vector_key = ?", "subject_key = ?", "operational_day = ?"]
    params: list[Any] = [vector_key, subject_key, day]
    if exclude_id is not None:
        clauses.append("id <> ?")
        params.append(int(exclude_id))
    where = " AND ".join(clauses)
    previous_count = int(
        conn.execute(f"SELECT COUNT(*) AS count FROM anomaly_occurrences WHERE {where}", params).fetchone()["count"] or 0
    )
    limit = max(0, int(details_limit))
    previous: list[dict[str, Any]] = []
    if limit > 0 and previous_count > 0:
        rows = conn.execute(
            f"""
            SELECT *
            FROM anomaly_occurrences
            WHERE {where}
            ORDER BY first_seen DESC, id DESC
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
        previous = [_occurrence_to_previous_dict(row) for row in rows]
    return {
        "subject_type": subject_type,
        "subject_key": subject_key,
        "subject_confidence": subject_confidence or "low",
        "subject_context": dict(subject_context or {}),
        "is_recurrence": previous_count > 0,
        "occurrence_number_today": previous_count + 1,
        "occurrences_today": previous_count + 1,
        "previous_occurrences_today": previous_count,
        "last_previous_occurrence_at": previous[0]["first_seen"] if previous else "",
        "previous_occurrences": previous,
        "previous_occurrences_truncated": previous_count > len(previous),
        "operational_day": day,
        "timezone": OPERATIONAL_TIME_ZONE_NAME,
        "schema_version": ANOMALY_OCCURRENCES_SCHEMA_VERSION,
    }


def _subject_context_from_json(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(_clean(value) or "{}")
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _correlation_from_occurrence_row(
    conn: sqlite3.Connection,
    occurrence: sqlite3.Row,
    *,
    details_limit: int = DEFAULT_DETAILS_LIMIT,
) -> dict[str, Any]:
    return _correlation_payload(
        conn,
        vector_key=_clean(occurrence["vector_key"]),
        subject_type=_clean(occurrence["subject_type"]),
        subject_key=_clean(occurrence["subject_key"]),
        subject_confidence=_clean(occurrence["subject_confidence"]),
        subject_context=_subject_context_from_json(occurrence["subject_context_json"]),
        day=_clean(occurrence["operational_day"]),
        exclude_id=int(occurrence["id"]),
        details_limit=details_limit,
    )


def resolve_anomaly_correlation(
    conn: sqlite3.Connection,
    anomaly_table: str,
    anomaly_id: int | None,
    *,
    details_limit: int = DEFAULT_DETAILS_LIMIT,
    anomaly: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Summary canonico de correlacao de uma anomalia (por row).

    Usa a ocorrencia persistida mais recente da row; se ainda nao existir
    (janela entre a criacao da anomalia e o proximo hook), calcula o sujeito
    em memoria sem persistir. ``anomaly`` e o dict da anomalia (row_to_dict)
    usado nesse fallback.
    """
    parsed_id = _int_or_none(anomaly_id)
    if parsed_id is None or parsed_id <= 0 or not anomaly_table:
        return None
    ensure_anomaly_correlation_schema(conn)
    occurrence = _latest_occurrence(conn, anomaly_table, parsed_id)
    if occurrence is not None:
        return _correlation_from_occurrence_row(conn, occurrence, details_limit=details_limit)
    if anomaly is None:
        return None
    vector_key = anomaly_vector_key(anomaly, anomaly_table)
    if not vector_key:
        return None
    subject = resolve_subject_for_anomaly(conn, anomaly, table=anomaly_table)
    start_text = _clean(
        anomaly.get("first_seen")
        or anomaly.get("started_at")
        or anomaly.get("last_seen")
        or anomaly.get("last_seen_at")
        or anomaly.get("created_at")
    )
    day = operational_day(start_text)
    if not day:
        return None
    return _correlation_payload(
        conn,
        vector_key=vector_key,
        subject_type=subject["subject_type"],
        subject_key=subject["subject_key"],
        subject_confidence=subject["subject_confidence"],
        subject_context=subject["subject_context"],
        day=day,
        exclude_id=None,
        details_limit=details_limit,
    )


def _security_ids_from_item(item: Mapping[str, Any]) -> list[int]:
    ids: list[int] = []
    for value in item.get("security_anomaly_ids") or []:
        parsed = _int_or_none(value)
        if parsed is not None and parsed > 0:
            ids.append(parsed)
    return ids


def attach_correlation_to_anomaly_items(
    conn: sqlite3.Connection,
    items: list[dict[str, Any]] | None,
    *,
    table: str | None = None,
    details_limit: int = DEFAULT_DETAILS_LIMIT,
) -> list[dict[str, Any]] | None:
    """Anexa ``correlation`` a cada item de anomalia (lista/backward-compatible).

    ``table`` explicita a origem dos itens (``security_anomalies`` ou
    ``anomaly_events``); sem ela, itens consolidados de ``security_anomalies``
    (API de eventos) usam a ocorrencia mais recente do grupo e os demais sao
    tratados como ``anomaly_events``. Falhas por item sao logadas e nao
    derrubam a resposta.
    """
    if not items:
        return items
    for item in items:
        if not isinstance(item, dict) or item.get("correlation") is not None:
            continue
        try:
            if table is None and _clean(item.get("source")).lower() == "security_anomalies":
                ids = _security_ids_from_item(item)
                if ids:
                    placeholders = ",".join("?" for _ in ids)
                    occurrence = conn.execute(
                        f"""
                        SELECT *
                        FROM anomaly_occurrences
                        WHERE anomaly_table = 'security_anomalies' AND anomaly_id IN ({placeholders})
                        ORDER BY last_seen DESC, id DESC
                        LIMIT 1
                        """,
                        ids,
                    ).fetchone()
                    if occurrence is not None:
                        item["correlation"] = _correlation_from_occurrence_row(conn, occurrence, details_limit=details_limit)
                        continue
                correlation = resolve_anomaly_correlation(
                    conn,
                    "security_anomalies",
                    _int_or_none(item.get("id")),
                    anomaly=item,
                    details_limit=details_limit,
                )
            else:
                correlation = resolve_anomaly_correlation(
                    conn,
                    table or "anomaly_events",
                    _int_or_none(item.get("id")),
                    anomaly=item,
                    details_limit=details_limit,
                )
            if correlation is not None:
                item["correlation"] = correlation
        except Exception:
            logger.exception("Falha ao anexar correlation a item de anomalia id=%s", item.get("id"))
    return items


# ---------------------------------------------------------------------------
# Backfill one-time (historico existente = 1 ocorrencia por row)
# ---------------------------------------------------------------------------


def _backfill_one_table(conn: sqlite3.Connection, table: str, first_column: str, last_column: str) -> int:
    if not _table_exists(conn, table):
        return 0
    rows = conn.execute(
        f"""
        SELECT r.*
        FROM {table} r
        WHERE NOT EXISTS (
            SELECT 1 FROM anomaly_occurrences o
            WHERE o.anomaly_table = ? AND o.anomaly_id = r.id
        )
        """,
        (table,),
    ).fetchall()
    pool_networks = _active_pool_networks(conn)
    inserted = 0
    for row in rows:
        anomaly = dict(row)
        vector_key = anomaly_vector_key(anomaly, table)
        if not vector_key:
            continue
        first_dt = parse_datetime_text(anomaly.get(first_column))
        last_dt = parse_datetime_text(anomaly.get(last_column)) or first_dt or _now()
        if first_dt is None:
            first_dt = last_dt
        subject = resolve_subject_for_anomaly(conn, anomaly, table=table, pool_networks=pool_networks)
        metric = _metric_from_anomaly(anomaly)
        metric_value = _metric_value_from_anomaly(anomaly, metric)
        ended_at = _clean(anomaly.get("ended_at")) or None
        now_iso = _now_iso()
        conn.execute(
            """
            INSERT INTO anomaly_occurrences (
                anomaly_table, anomaly_id, vector_key, dedupe_key,
                subject_type, subject_key, subject_confidence, subject_context_json,
                operational_day, first_seen, last_seen, ended_at,
                severity, metric, metric_peak, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                table,
                int(anomaly.get("id") or 0),
                vector_key,
                _clean(anomaly.get("dedupe_key")),
                subject["subject_type"],
                subject["subject_key"],
                subject["subject_confidence"],
                json.dumps(subject["subject_context"], sort_keys=True, default=str),
                operational_day(first_dt),
                _iso(first_dt),
                _iso(last_dt),
                ended_at,
                _clean(anomaly.get("severity")).lower(),
                metric,
                metric_value,
                now_iso,
                now_iso,
            ),
        )
        inserted += 1
    return inserted


def backfill_anomaly_occurrences(conn: sqlite3.Connection) -> dict[str, Any]:
    """Backfill idempotente: 1 ocorrencia por row historica sem ocorrencia."""
    if not _table_exists(conn, "system_settings"):
        return {"skipped": "system_settings_ausente"}
    try:
        flag = conn.execute("SELECT value FROM system_settings WHERE key = ?", (BACKFILL_FLAG_KEY,)).fetchone()
    except sqlite3.Error:
        return {"skipped": "flag_indisponivel"}
    if flag is not None:
        return {"already": True}
    inserted = 0
    inserted += _backfill_one_table(conn, "security_anomalies", "first_seen", "last_seen")
    inserted += _backfill_one_table(conn, "anomaly_events", "started_at", "last_seen_at")
    conn.execute(
        "INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)",
        (
            BACKFILL_FLAG_KEY,
            json.dumps({"inserted": inserted, "schema_version": ANOMALY_OCCURRENCES_SCHEMA_VERSION, "at": _now_iso()}),
            _now_iso(),
        ),
    )
    if inserted:
        logger.info("Backfill de ocorrencias de anomalia concluido: %s registro(s)", inserted)
    return {"inserted": inserted}
