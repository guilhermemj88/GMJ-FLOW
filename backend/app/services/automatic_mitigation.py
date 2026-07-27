from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network
from typing import Any, Callable, Mapping

try:
    from typing import Protocol
except ImportError:  # pragma: no cover - Python 3.7 compatibility for maintenance tooling.
    class Protocol:  # type: ignore[no-redef]
        pass


AUTOMATIC_PRIMARY = "automatic_primary"
MANUAL_ALTERNATIVE = "manual_alternative"
INFORMATIONAL = "informational"
CANDIDATE_KINDS = {AUTOMATIC_PRIMARY, MANUAL_ALTERNATIVE, INFORMATIONAL}

EXECUTION_STATUSES = {
    "generated",
    "queued",
    "applying",
    "active",
    "failed",
    "withdraw_pending",
    "withdrawn",
    "expired",
    "blocked",
    "cancelled",
}
RESERVING_STATUSES = {"generated", "queued", "applying", "active", "withdraw_pending"}

AUDIT_EVALUATION_STARTED = "AUTO_MITIGATION_EVALUATION_STARTED"
AUDIT_EVALUATED = "AUTO_MITIGATION_EVALUATED"
AUDIT_QUEUED = "AUTO_MITIGATION_QUEUED"
AUDIT_APPLY_STARTED = "AUTO_MITIGATION_APPLY_STARTED"
AUDIT_APPLIED = "AUTO_MITIGATION_APPLIED"
AUDIT_BLOCKED = "AUTO_MITIGATION_BLOCKED"
AUDIT_FAILED = "AUTO_MITIGATION_FAILED"
AUDIT_WITHDRAW_STARTED = "AUTO_MITIGATION_WITHDRAW_STARTED"
AUDIT_WITHDRAWN = "AUTO_MITIGATION_WITHDRAWN"
AUDIT_WITHDRAW_FAILED = "AUTO_MITIGATION_WITHDRAW_FAILED"
AUDIT_DEDUPLICATED = "AUTO_MITIGATION_DEDUPLICATED"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)


def json_load(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return clean_text(value).lower() in {"1", "true", "yes", "on", "enabled", "allowed"}


def int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalized_match_from_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
    source = clean_text(candidate.get("src_prefix") or candidate.get("src_cidr"))
    destination = clean_text(candidate.get("dst_prefix") or candidate.get("dst_cidr"))
    normalized: dict[str, Any] = {
        "source": source,
        "destination": destination,
        "protocol": clean_text(candidate.get("protocol")).lower(),
        "source_port": clean_text(candidate.get("src_port")),
        "destination_port": clean_text(candidate.get("dst_port")),
        "tcp_flags": clean_text(candidate.get("tcp_flags")).lower(),
    }
    prefix = destination or source
    if prefix:
        try:
            normalized["address_family"] = f"ipv{ip_network(prefix, strict=False).version}"
        except ValueError:
            normalized["address_family"] = clean_text(candidate.get("address_family")).lower()
    else:
        normalized["address_family"] = clean_text(candidate.get("address_family")).lower()
    return normalized


def deterministic_idempotency_key(
    connector_id: Any,
    normalized_match: Mapping[str, Any],
    action: Any,
) -> str:
    logical_rule = {
        "connector_id": int_value(connector_id),
        "address_family": clean_text(normalized_match.get("address_family")).lower(),
        "source": clean_text(normalized_match.get("source")).lower(),
        "destination": clean_text(normalized_match.get("destination")).lower(),
        "protocol": clean_text(normalized_match.get("protocol")).lower(),
        "source_port": clean_text(normalized_match.get("source_port")).lower(),
        "destination_port": clean_text(normalized_match.get("destination_port")).lower(),
        "tcp_flags": clean_text(normalized_match.get("tcp_flags")).lower(),
        "action": clean_text(action).lower(),
    }
    digest = hashlib.sha256(json_dump(logical_rule).encode("utf-8")).hexdigest()
    return f"mit:{digest}"


@dataclass
class MitigationCandidate:
    anomaly_id: int
    vector: str
    profile_id: int | None
    profile_name: str
    candidate_kind: str
    automatic_eligible: bool
    auto_allowed: bool
    priority: int
    connector_id: int | None
    connector_type: str
    connector_mode: str
    profile_mode: str
    command: str
    withdraw_command: str
    normalized_match: dict[str, Any]
    action: str
    ttl_seconds: int
    idempotency_key: str
    gates: dict[str, Any] = field(default_factory=dict)
    policy_reason: str = ""
    policy_authorized: bool = False
    anomaly_status: str = "active"
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, item: Mapping[str, Any]) -> "MitigationCandidate":
        normalized = item.get("normalized_match")
        if not isinstance(normalized, Mapping):
            normalized = normalized_match_from_candidate(item)
        normalized_dict = dict(normalized)
        connector_id = item.get("connector_id")
        action = clean_text(item.get("action") or item.get("then_action") or "discard").lower()
        candidate_kind = clean_text(item.get("candidate_kind") or AUTOMATIC_PRIMARY).lower()
        if candidate_kind not in CANDIDATE_KINDS:
            candidate_kind = INFORMATIONAL
        idempotency_key = clean_text(item.get("idempotency_key") or item.get("mitigation_key"))
        if not idempotency_key:
            idempotency_key = deterministic_idempotency_key(connector_id, normalized_dict, action)
        gates = item.get("gates")
        if not isinstance(gates, Mapping):
            gates = {}
        metadata = item.get("metadata")
        if not isinstance(metadata, Mapping):
            metadata = {}
        return cls(
            anomaly_id=int_value(item.get("anomaly_id")),
            vector=clean_text(item.get("vector") or item.get("attack_vector_name") or item.get("vector_name")),
            profile_id=int_value(item.get("profile_id") or item.get("response_profile_id")) or None,
            profile_name=clean_text(item.get("profile_name") or item.get("profile") or item.get("response_profile_name")),
            candidate_kind=candidate_kind,
            automatic_eligible=bool_value(
                item.get("automatic_eligible")
                if "automatic_eligible" in item
                else item.get("eligible_for_automatic", item.get("eligible"))
            ),
            auto_allowed=bool_value(item.get("auto_allowed", item.get("allow_auto"))),
            priority=int_value(item.get("priority")),
            connector_id=int_value(connector_id) or None,
            connector_type=clean_text(item.get("connector_type") or item.get("backend_type") or "exabgp").lower(),
            connector_mode=clean_text(item.get("connector_mode") or item.get("mode")).lower(),
            profile_mode=clean_text(item.get("profile_mode") or item.get("mitigation_mode") or item.get("approval_mode")).lower(),
            command=clean_text(item.get("command") or item.get("announce_command") or item.get("rendered_command")),
            withdraw_command=clean_text(item.get("withdraw_command")),
            normalized_match=normalized_dict,
            action=action,
            ttl_seconds=int_value(item.get("ttl_seconds") or item.get("duration_seconds")),
            idempotency_key=idempotency_key,
            gates=dict(gates),
            policy_reason=clean_text(item.get("policy_reason") or item.get("reason")),
            policy_authorized=bool_value(
                item.get("policy_authorized")
                if "policy_authorized" in item
                else item.get("auto_allowed", item.get("allow_auto"))
            ),
            anomaly_status=clean_text(item.get("anomaly_status") or "active").lower(),
            metadata=dict(metadata),
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutorResult:
    success: bool
    result: dict[str, Any] = field(default_factory=dict)
    error_code: str = ""
    error_message: str = ""
    transient: bool = False


class MitigationExecutor(Protocol):
    connector_type: str

    def validate(self, candidate: MitigationCandidate) -> ExecutorResult:
        ...

    def readiness(self, candidate: MitigationCandidate) -> ExecutorResult:
        ...

    def apply(self, candidate: MitigationCandidate, execution: Mapping[str, Any]) -> ExecutorResult:
        ...

    def withdraw(self, candidate: MitigationCandidate, execution: Mapping[str, Any]) -> ExecutorResult:
        ...

    def status(self, candidate: MitigationCandidate, execution: Mapping[str, Any]) -> ExecutorResult:
        ...


class CallbackMitigationExecutor:
    """Generic connector adapter used by ExaBGP now and future backends later."""

    def __init__(
        self,
        connector_type: str,
        *,
        validator: Callable[[MitigationCandidate], ExecutorResult | Mapping[str, Any] | bool],
        readiness_probe: Callable[[MitigationCandidate], ExecutorResult | Mapping[str, Any] | bool],
        apply_callback: Callable[[MitigationCandidate, Mapping[str, Any]], ExecutorResult | Mapping[str, Any] | bool],
        withdraw_callback: Callable[[MitigationCandidate, Mapping[str, Any]], ExecutorResult | Mapping[str, Any] | bool],
        status_callback: Callable[[MitigationCandidate, Mapping[str, Any]], ExecutorResult | Mapping[str, Any] | bool] | None = None,
    ) -> None:
        self.connector_type = clean_text(connector_type).lower()
        self._validator = validator
        self._readiness_probe = readiness_probe
        self._apply_callback = apply_callback
        self._withdraw_callback = withdraw_callback
        self._status_callback = status_callback

    @staticmethod
    def _normalize(value: ExecutorResult | Mapping[str, Any] | bool, default_error: str) -> ExecutorResult:
        if isinstance(value, ExecutorResult):
            return value
        if isinstance(value, bool):
            return ExecutorResult(value, {}, "" if value else default_error, "" if value else default_error)
        payload = dict(value)
        success = bool_value(payload.get("success", payload.get("ready", payload.get("valid", False))))
        return ExecutorResult(
            success=success,
            result=dict(payload.get("result") or payload),
            error_code=clean_text(payload.get("error_code") or ("" if success else default_error)),
            error_message=clean_text(payload.get("error_message") or payload.get("reason") or ("" if success else default_error)),
            transient=bool_value(payload.get("transient")),
        )

    def validate(self, candidate: MitigationCandidate) -> ExecutorResult:
        return self._normalize(self._validator(candidate), "validation_failed")

    def readiness(self, candidate: MitigationCandidate) -> ExecutorResult:
        return self._normalize(self._readiness_probe(candidate), "connector_not_ready")

    def apply(self, candidate: MitigationCandidate, execution: Mapping[str, Any]) -> ExecutorResult:
        return self._normalize(self._apply_callback(candidate, execution), "apply_failed")

    def withdraw(self, candidate: MitigationCandidate, execution: Mapping[str, Any]) -> ExecutorResult:
        return self._normalize(self._withdraw_callback(candidate, execution), "withdraw_failed")

    def status(self, candidate: MitigationCandidate, execution: Mapping[str, Any]) -> ExecutorResult:
        if self._status_callback is None:
            return ExecutorResult(False, {}, "status_unknown", "status_unknown", transient=True)
        return self._normalize(self._status_callback(candidate, execution), "status_unknown")


def ensure_automatic_mitigation_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mitigation_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_id INTEGER NOT NULL,
            vector TEXT NOT NULL DEFAULT '',
            profile_id INTEGER,
            profile TEXT NOT NULL DEFAULT '',
            candidate_kind TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            connector_id INTEGER,
            connector_type TEXT NOT NULL DEFAULT '',
            command TEXT NOT NULL DEFAULT '',
            withdraw_command TEXT NOT NULL DEFAULT '',
            normalized_match TEXT NOT NULL DEFAULT '{}',
            action TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'generated',
            automatic INTEGER NOT NULL DEFAULT 1,
            policy_reason TEXT NOT NULL DEFAULT '',
            ttl_seconds INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            queued_at TEXT,
            apply_started_at TEXT,
            applied_at TEXT,
            expires_at TEXT,
            withdraw_started_at TEXT,
            withdrawn_at TEXT,
            error_code TEXT NOT NULL DEFAULT '',
            error_message TEXT NOT NULL DEFAULT '',
            apply_result TEXT NOT NULL DEFAULT '{}',
            withdraw_result TEXT NOT NULL DEFAULT '{}',
            retry_count INTEGER NOT NULL DEFAULT 0,
            max_retries INTEGER NOT NULL DEFAULT 0,
            next_retry_at TEXT,
            candidate_json TEXT NOT NULL DEFAULT '{}',
            gates_json TEXT NOT NULL DEFAULT '{}',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mitigation_execution_anomalies (
            execution_id INTEGER NOT NULL,
            anomaly_id INTEGER NOT NULL,
            associated_at TEXT NOT NULL,
            PRIMARY KEY(execution_id, anomaly_id),
            FOREIGN KEY(execution_id) REFERENCES mitigation_executions(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS automatic_mitigation_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            context_json TEXT NOT NULL DEFAULT '{}',
            requested_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            error_message TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_mitigation_execution_reservation
        ON mitigation_executions(idempotency_key)
        WHERE status IN ('generated', 'queued', 'applying', 'active', 'withdraw_pending')
        """
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_automatic_mitigation_job_pending
        ON automatic_mitigation_jobs(anomaly_id)
        WHERE status IN ('queued', 'processing')
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_mitigation_executions_status_expiry "
        "ON mitigation_executions(status, expires_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_mitigation_executions_anomaly "
        "ON mitigation_executions(anomaly_id, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_automatic_mitigation_jobs_status "
        "ON automatic_mitigation_jobs(status, requested_at)"
    )


def execution_row_to_dict(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["automatic"] = bool_value(item.get("automatic"))
    item["normalized_match"] = json_load(item.get("normalized_match"), {})
    item["apply_result"] = json_load(item.get("apply_result"), {})
    item["withdraw_result"] = json_load(item.get("withdraw_result"), {})
    item["candidate"] = json_load(item.pop("candidate_json", "{}"), {})
    item["gates"] = json_load(item.pop("gates_json", "{}"), {})
    item["metadata"] = json_load(item.pop("metadata_json", "{}"), {})
    return item


class AutomaticMitigationOrchestrator:
    def __init__(
        self,
        connection_factory: Callable[[], sqlite3.Connection],
        evaluator: Callable[[int, Mapping[str, Any]], list[Mapping[str, Any]]],
        executors: Mapping[str, MitigationExecutor],
        *,
        anomaly_loader: Callable[[int], Mapping[str, Any]] | None = None,
        logger: logging.Logger | None = None,
        max_apply_retries: int = 0,
        max_withdraw_retries: int = 2,
    ) -> None:
        self.connection_factory = connection_factory
        self.evaluator = evaluator
        self.executors = {clean_text(key).lower(): value for key, value in executors.items()}
        self.anomaly_loader = anomaly_loader
        self.logger = logger or logging.getLogger("gmj-flow.automatic-mitigation")
        self.max_apply_retries = max(0, int(max_apply_retries))
        self.max_withdraw_retries = max(0, int(max_withdraw_retries))

    def ensure_schema(self) -> None:
        conn = self.connection_factory()
        try:
            ensure_automatic_mitigation_schema(conn)
            conn.commit()
        finally:
            conn.close()

    def _audit(self, event: str, **fields: Any) -> None:
        self.logger.info("%s %s", event, json_dump(fields))

    @staticmethod
    def _blocking_reason(candidate: MitigationCandidate) -> str:
        if candidate.candidate_kind != AUTOMATIC_PRIMARY:
            return "candidate_not_automatic_primary"
        if not candidate.automatic_eligible:
            return "candidate_not_automatic_eligible"
        if not candidate.auto_allowed or not candidate.policy_authorized:
            return "blocked_by_policy"
        if candidate.profile_mode not in {"auto", "automatic"}:
            return "profile_not_automatic"
        if candidate.connector_mode not in {"auto", "automatic"}:
            return "connector_not_automatic"
        if candidate.anomaly_status != "active":
            return "anomaly_not_active"
        if candidate.connector_id is None:
            return "connector_not_resolved"
        if not candidate.connector_type:
            return "connector_type_missing"
        if not candidate.command:
            return "validation_failed"
        if candidate.ttl_seconds <= 0:
            return "invalid_ttl"
        blocking = candidate.gates.get("blocking")
        if bool_value(blocking):
            return clean_text(candidate.gates.get("reason") or "blocked_by_gate")
        blockers = candidate.gates.get("blocking_reasons")
        if isinstance(blockers, list) and blockers:
            return clean_text(blockers[0]) or "blocked_by_gate"
        return ""

    def _insert_blocked(self, candidate: MitigationCandidate, reason: str) -> dict[str, Any]:
        now = utc_now_iso()
        conn = self.connection_factory()
        try:
            ensure_automatic_mitigation_schema(conn)
            cursor = conn.execute(
                """
                INSERT INTO mitigation_executions (
                    anomaly_id, vector, profile_id, profile, candidate_kind, idempotency_key,
                    connector_id, connector_type, command, withdraw_command, normalized_match,
                    action, status, automatic, policy_reason, ttl_seconds, created_at,
                    error_code, error_message, candidate_json, gates_json, metadata_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'blocked', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate.anomaly_id,
                    candidate.vector,
                    candidate.profile_id,
                    candidate.profile_name,
                    candidate.candidate_kind,
                    candidate.idempotency_key,
                    candidate.connector_id,
                    candidate.connector_type,
                    candidate.command,
                    candidate.withdraw_command,
                    json_dump(candidate.normalized_match),
                    candidate.action,
                    candidate.policy_reason,
                    candidate.ttl_seconds,
                    now,
                    reason,
                    reason,
                    json_dump(candidate.as_dict()),
                    json_dump(candidate.gates),
                    json_dump(candidate.metadata),
                    now,
                ),
            )
            execution_id = int(cursor.lastrowid)
            conn.execute(
                "INSERT OR IGNORE INTO mitigation_execution_anomalies (execution_id, anomaly_id, associated_at) "
                "VALUES (?, ?, ?)",
                (execution_id, candidate.anomaly_id, now),
            )
            conn.commit()
            item = self.get_execution(execution_id)
        finally:
            conn.close()
        self._audit(
            AUDIT_BLOCKED,
            anomaly_id=candidate.anomaly_id,
            mitigation_id=execution_id,
            vector=candidate.vector,
            candidate_kind=candidate.candidate_kind,
            connector_id=candidate.connector_id,
            idempotency_key=candidate.idempotency_key,
            command=candidate.command,
            ttl=candidate.ttl_seconds,
            status="blocked",
            reason=reason,
        )
        return item

    def _reserve(self, candidate: MitigationCandidate) -> tuple[dict[str, Any], bool]:
        now = utc_now_iso()
        conn = self.connection_factory()
        try:
            ensure_automatic_mitigation_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT *
                FROM mitigation_executions
                WHERE idempotency_key = ?
                  AND status IN ('generated', 'queued', 'applying', 'active', 'withdraw_pending')
                ORDER BY id DESC
                LIMIT 1
                """,
                (candidate.idempotency_key,),
            ).fetchone()
            created = False
            if row is None:
                try:
                    cursor = conn.execute(
                        """
                        INSERT INTO mitigation_executions (
                            anomaly_id, vector, profile_id, profile, candidate_kind, idempotency_key,
                            connector_id, connector_type, command, withdraw_command, normalized_match,
                            action, status, automatic, policy_reason, ttl_seconds, created_at, queued_at,
                            max_retries, candidate_json, gates_json, metadata_json, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            candidate.anomaly_id,
                            candidate.vector,
                            candidate.profile_id,
                            candidate.profile_name,
                            candidate.candidate_kind,
                            candidate.idempotency_key,
                            candidate.connector_id,
                            candidate.connector_type,
                            candidate.command,
                            candidate.withdraw_command,
                            json_dump(candidate.normalized_match),
                            candidate.action,
                            candidate.policy_reason,
                            candidate.ttl_seconds,
                            now,
                            now,
                            self.max_apply_retries,
                            json_dump(candidate.as_dict()),
                            json_dump(candidate.gates),
                            json_dump(candidate.metadata),
                            now,
                        ),
                    )
                    execution_id = int(cursor.lastrowid)
                    row = conn.execute("SELECT * FROM mitigation_executions WHERE id = ?", (execution_id,)).fetchone()
                    created = True
                except sqlite3.IntegrityError:
                    row = conn.execute(
                        """
                        SELECT *
                        FROM mitigation_executions
                        WHERE idempotency_key = ?
                          AND status IN ('generated', 'queued', 'applying', 'active', 'withdraw_pending')
                        ORDER BY id DESC
                        LIMIT 1
                        """,
                        (candidate.idempotency_key,),
                    ).fetchone()
            if row is None:
                raise RuntimeError("persistence_failed: reservation disappeared")
            execution_id = int(row["id"])
            conn.execute(
                "INSERT OR IGNORE INTO mitigation_execution_anomalies (execution_id, anomaly_id, associated_at) "
                "VALUES (?, ?, ?)",
                (execution_id, candidate.anomaly_id, now),
            )
            conn.commit()
            item = execution_row_to_dict(row)
        finally:
            conn.close()
        if created:
            self._audit(
                AUDIT_QUEUED,
                anomaly_id=candidate.anomaly_id,
                mitigation_id=execution_id,
                vector=candidate.vector,
                candidate_kind=candidate.candidate_kind,
                connector_id=candidate.connector_id,
                idempotency_key=candidate.idempotency_key,
                command=candidate.command,
                ttl=candidate.ttl_seconds,
                status="queued",
            )
        else:
            self._audit(
                AUDIT_DEDUPLICATED,
                anomaly_id=candidate.anomaly_id,
                mitigation_id=execution_id,
                vector=candidate.vector,
                candidate_kind=candidate.candidate_kind,
                connector_id=candidate.connector_id,
                idempotency_key=candidate.idempotency_key,
                command=candidate.command,
                ttl=candidate.ttl_seconds,
                status=item.get("status"),
                reason="equivalent_active_rule",
            )
        return item, created

    def process_anomaly(
        self,
        anomaly_id: int,
        context: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        payload = dict(context or (self.anomaly_loader(anomaly_id) if self.anomaly_loader else {}))
        self._audit(AUDIT_EVALUATION_STARTED, anomaly_id=anomaly_id)
        raw_candidates = self.evaluator(int(anomaly_id), payload)
        candidates = [MitigationCandidate.from_mapping(item) for item in raw_candidates]
        candidates.sort(key=lambda item: item.priority, reverse=True)
        self._audit(
            AUDIT_EVALUATED,
            anomaly_id=anomaly_id,
            candidate_count=len(candidates),
            automatic_primary_count=sum(item.candidate_kind == AUTOMATIC_PRIMARY for item in candidates),
        )
        results: list[dict[str, Any]] = []
        for candidate in candidates:
            if candidate.candidate_kind != AUTOMATIC_PRIMARY:
                continue
            candidate.anomaly_id = int(anomaly_id)
            reason = self._blocking_reason(candidate)
            if reason:
                results.append(self._insert_blocked(candidate, reason))
                continue
            executor = self.executors.get(candidate.connector_type)
            if executor is None:
                results.append(self._insert_blocked(candidate, "connector_executor_not_registered"))
                continue
            validation = executor.validate(candidate)
            if not validation.success:
                results.append(self._insert_blocked(candidate, validation.error_code or "validation_failed"))
                continue
            readiness = executor.readiness(candidate)
            if not readiness.success:
                results.append(self._insert_blocked(candidate, readiness.error_code or "connector_not_ready"))
                continue
            execution, created = self._reserve(candidate)
            if not created:
                results.append(execution)
                continue
            results.append(self._apply(int(execution["id"]), candidate, executor))
        return results

    def _apply(
        self,
        execution_id: int,
        candidate: MitigationCandidate,
        executor: MitigationExecutor,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        conn = self.connection_factory()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE mitigation_executions
                SET status = 'applying', apply_started_at = COALESCE(apply_started_at, ?),
                    updated_at = ?, error_code = '', error_message = ''
                WHERE id = ? AND status = 'queued'
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                """,
                (now, now, execution_id, now),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                return self.get_execution(execution_id)
            conn.commit()
        finally:
            conn.close()
        self._audit(
            AUDIT_APPLY_STARTED,
            anomaly_id=candidate.anomaly_id,
            mitigation_id=execution_id,
            vector=candidate.vector,
            candidate_kind=candidate.candidate_kind,
            connector_id=candidate.connector_id,
            idempotency_key=candidate.idempotency_key,
            command=candidate.command,
            ttl=candidate.ttl_seconds,
            status="applying",
        )
        execution = self.get_execution(execution_id)
        try:
            result = executor.apply(candidate, execution)
        except Exception as exc:  # Connector adapters normalize known failures; keep the record safe on surprises.
            result = ExecutorResult(False, {}, "apply_failed", clean_text(exc) or exc.__class__.__name__, False)
        completed = utc_now()
        conn = self.connection_factory()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if result.success:
                result_expires_at = parse_datetime(result.result.get("expires_at"))
                expires_at = (
                    result_expires_at
                    if result_expires_at is not None and result_expires_at > completed
                    else completed + timedelta(seconds=candidate.ttl_seconds)
                ).isoformat().replace("+00:00", "Z")
                applied_at = clean_text(result.result.get("applied_at")) or completed.isoformat().replace("+00:00", "Z")
                conn.execute(
                    """
                    UPDATE mitigation_executions
                    SET status = 'active', applied_at = ?, expires_at = ?, apply_result = ?,
                        error_code = '', error_message = '', next_retry_at = NULL, updated_at = ?
                    WHERE id = ? AND status = 'applying'
                    """,
                    (applied_at, expires_at, json_dump(result.result), utc_now_iso(), execution_id),
                )
            else:
                row = conn.execute(
                    "SELECT retry_count, max_retries FROM mitigation_executions WHERE id = ?",
                    (execution_id,),
                ).fetchone()
                retry_count = int(row["retry_count"] or 0) + 1
                max_retries = int(row["max_retries"] or 0)
                retry = result.transient and retry_count <= max_retries
                next_retry_at = (
                    (completed + timedelta(seconds=min(60, 2 ** retry_count))).isoformat().replace("+00:00", "Z")
                    if retry
                    else None
                )
                conn.execute(
                    """
                    UPDATE mitigation_executions
                    SET status = ?, retry_count = ?, next_retry_at = ?, apply_result = ?,
                        error_code = ?, error_message = ?, updated_at = ?
                    WHERE id = ? AND status = 'applying'
                    """,
                    (
                        "queued" if retry else "failed",
                        retry_count,
                        next_retry_at,
                        json_dump(result.result),
                        result.error_code or "apply_failed",
                        result.error_message or result.error_code or "apply_failed",
                        utc_now_iso(),
                        execution_id,
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        item = self.get_execution(execution_id)
        self._audit(
            AUDIT_APPLIED if result.success else AUDIT_FAILED,
            anomaly_id=candidate.anomaly_id,
            mitigation_id=execution_id,
            vector=candidate.vector,
            candidate_kind=candidate.candidate_kind,
            connector_id=candidate.connector_id,
            idempotency_key=candidate.idempotency_key,
            command=candidate.command,
            ttl=candidate.ttl_seconds,
            status=item.get("status"),
            reason=result.error_code,
            error=result.error_message,
        )
        return item

    def enqueue(self, anomaly_id: int, context: Mapping[str, Any] | None = None) -> int:
        now = utc_now_iso()
        conn = self.connection_factory()
        try:
            ensure_automatic_mitigation_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT id
                FROM automatic_mitigation_jobs
                WHERE anomaly_id = ? AND status IN ('queued', 'processing')
                ORDER BY id DESC LIMIT 1
                """,
                (int(anomaly_id),),
            ).fetchone()
            if row is None:
                cursor = conn.execute(
                    """
                    INSERT INTO automatic_mitigation_jobs (
                        anomaly_id, status, context_json, requested_at, updated_at
                    )
                    VALUES (?, 'queued', ?, ?, ?)
                    """,
                    (int(anomaly_id), json_dump(dict(context or {})), now, now),
                )
                job_id = int(cursor.lastrowid)
            else:
                job_id = int(row["id"])
                conn.execute(
                    """
                    UPDATE automatic_mitigation_jobs
                    SET context_json = ?, requested_at = ?, updated_at = ?
                    WHERE id = ? AND status IN ('queued', 'processing')
                    """,
                    (json_dump(dict(context or {})), now, now, job_id),
                )
            conn.commit()
            return job_id
        finally:
            conn.close()

    def recover_jobs(self) -> int:
        conn = self.connection_factory()
        try:
            ensure_automatic_mitigation_schema(conn)
            now = utc_now_iso()
            cursor = conn.execute(
                """
                UPDATE automatic_mitigation_jobs
                SET status = 'queued', started_at = NULL, error_message = 'recovered_after_restart',
                    updated_at = ?
                WHERE status = 'processing'
                """,
                (now,),
            )
            conn.commit()
            return int(cursor.rowcount or 0)
        finally:
            conn.close()

    def process_jobs(self, limit: int = 50) -> dict[str, int]:
        stats = {"claimed": 0, "completed": 0, "failed": 0}
        conn = self.connection_factory()
        try:
            ensure_automatic_mitigation_schema(conn)
            ids = [
                int(row["id"])
                for row in conn.execute(
                    "SELECT id FROM automatic_mitigation_jobs WHERE status = 'queued' ORDER BY requested_at, id LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
            ]
        finally:
            conn.close()
        for job_id in ids:
            conn = self.connection_factory()
            try:
                conn.execute("BEGIN IMMEDIATE")
                now = utc_now_iso()
                cursor = conn.execute(
                    """
                    UPDATE automatic_mitigation_jobs
                    SET status = 'processing', started_at = ?, attempts = attempts + 1, updated_at = ?
                    WHERE id = ? AND status = 'queued'
                    """,
                    (now, now, job_id),
                )
                if cursor.rowcount != 1:
                    conn.rollback()
                    continue
                row = conn.execute("SELECT * FROM automatic_mitigation_jobs WHERE id = ?", (job_id,)).fetchone()
                conn.commit()
            finally:
                conn.close()
            stats["claimed"] += 1
            error = ""
            try:
                self.process_anomaly(int(row["anomaly_id"]), json_load(row["context_json"], {}))
            except Exception as exc:
                error = clean_text(exc) or exc.__class__.__name__
            conn = self.connection_factory()
            try:
                finished = utc_now_iso()
                conn.execute(
                    """
                    UPDATE automatic_mitigation_jobs
                    SET status = ?, finished_at = ?, error_message = ?, updated_at = ?
                    WHERE id = ? AND status = 'processing'
                    """,
                    ("failed" if error else "completed", finished, error, finished, job_id),
                )
                conn.commit()
            finally:
                conn.close()
            stats["failed" if error else "completed"] += 1
        return stats

    def _candidate_for_execution(self, execution: Mapping[str, Any]) -> MitigationCandidate:
        payload = execution.get("candidate")
        if not isinstance(payload, Mapping):
            payload = {}
        return MitigationCandidate.from_mapping({**payload, "anomaly_id": execution.get("anomaly_id")})

    def reconcile(self, limit: int = 200) -> dict[str, int]:
        stats = {"checked": 0, "active": 0, "withdrawn": 0, "failed": 0}
        now = utc_now()
        now_iso = now.isoformat().replace("+00:00", "Z")
        conn = self.connection_factory()
        try:
            ensure_automatic_mitigation_schema(conn)
            rows = conn.execute(
                """
                SELECT *
                FROM mitigation_executions
                WHERE (status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?)
                   OR (status = 'queued' AND next_retry_at IS NOT NULL AND next_retry_at <= ?)
                   OR status IN ('applying', 'withdraw_pending')
                ORDER BY updated_at, id
                LIMIT ?
                """,
                (now_iso, now_iso, max(1, int(limit))),
            ).fetchall()
        finally:
            conn.close()
        for raw_row in rows:
            execution = execution_row_to_dict(raw_row)
            stats["checked"] += 1
            candidate = self._candidate_for_execution(execution)
            executor = self.executors.get(clean_text(execution.get("connector_type")).lower())
            if executor is None:
                self._mark_failed(int(execution["id"]), "connector_executor_not_registered", "connector_executor_not_registered")
                stats["failed"] += 1
                continue
            status = clean_text(execution.get("status"))
            if status == "queued":
                retried = self._apply(int(execution["id"]), candidate, executor)
                if retried.get("status") == "active":
                    stats["active"] += 1
                elif retried.get("status") == "failed":
                    stats["failed"] += 1
                continue
            if status == "applying":
                probe = executor.status(candidate, execution)
                remote_status = clean_text(probe.result.get("status")).lower()
                if probe.success and remote_status in {"active", "applied", "advertised", "announced"}:
                    applied_at = clean_text(execution.get("apply_started_at")) or now_iso
                    expires = parse_datetime(execution.get("expires_at"))
                    if expires is None:
                        expires = (parse_datetime(applied_at) or now) + timedelta(seconds=candidate.ttl_seconds)
                    conn = self.connection_factory()
                    try:
                        conn.execute(
                            """
                            UPDATE mitigation_executions
                            SET status = 'active', applied_at = COALESCE(applied_at, ?), expires_at = ?,
                                apply_result = ?, error_code = '', error_message = '', updated_at = ?
                            WHERE id = ? AND status = 'applying'
                            """,
                            (applied_at, expires.isoformat().replace("+00:00", "Z"), json_dump(probe.result), now_iso, execution["id"]),
                        )
                        conn.commit()
                    finally:
                        conn.close()
                    stats["active"] += 1
                    continue
                if remote_status in {"withdrawn", "expired", "absent"}:
                    self._mark_withdrawn(int(execution["id"]), probe.result, expired=remote_status == "expired")
                    stats["withdrawn"] += 1
                    continue
                # Unknown delivery is deliberately not re-applied. Once its safety TTL
                # elapses it is withdrawn, which avoids a duplicate announce on restart.
                safety_start = parse_datetime(execution.get("apply_started_at")) or now
                if now < safety_start + timedelta(seconds=max(candidate.ttl_seconds, 1)):
                    continue
                self._claim_withdraw(int(execution["id"]), {"applying"})
                execution = self.get_execution(int(execution["id"]))
            elif status == "active":
                if not self._claim_withdraw(int(execution["id"]), {"active"}):
                    continue
                execution = self.get_execution(int(execution["id"]))
            self._withdraw(candidate, execution, executor, stats)
        return stats

    def _claim_withdraw(self, execution_id: int, expected: set[str]) -> bool:
        conn = self.connection_factory()
        try:
            conn.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in expected)
            now = utc_now_iso()
            cursor = conn.execute(
                f"""
                UPDATE mitigation_executions
                SET status = 'withdraw_pending', withdraw_started_at = COALESCE(withdraw_started_at, ?),
                    updated_at = ?
                WHERE id = ? AND status IN ({placeholders})
                """,
                (now, now, execution_id, *sorted(expected)),
            )
            if cursor.rowcount == 1:
                conn.commit()
                return True
            conn.rollback()
            return False
        finally:
            conn.close()

    def _withdraw(
        self,
        candidate: MitigationCandidate,
        execution: Mapping[str, Any],
        executor: MitigationExecutor,
        stats: dict[str, int],
    ) -> None:
        execution_id = int(execution["id"])
        self._audit(
            AUDIT_WITHDRAW_STARTED,
            anomaly_id=execution.get("anomaly_id"),
            mitigation_id=execution_id,
            vector=execution.get("vector"),
            candidate_kind=execution.get("candidate_kind"),
            connector_id=execution.get("connector_id"),
            idempotency_key=execution.get("idempotency_key"),
            command=candidate.withdraw_command,
            ttl=execution.get("ttl_seconds"),
            status="withdraw_pending",
        )
        try:
            result = executor.withdraw(candidate, execution)
        except Exception as exc:
            result = ExecutorResult(False, {}, "withdraw_failed", clean_text(exc) or exc.__class__.__name__, False)
        if result.success:
            self._mark_withdrawn(execution_id, result.result, expired=True)
            stats["withdrawn"] += 1
            self._audit(
                AUDIT_WITHDRAWN,
                anomaly_id=execution.get("anomaly_id"),
                mitigation_id=execution_id,
                vector=execution.get("vector"),
                candidate_kind=execution.get("candidate_kind"),
                connector_id=execution.get("connector_id"),
                idempotency_key=execution.get("idempotency_key"),
                command=candidate.withdraw_command,
                ttl=execution.get("ttl_seconds"),
                status="withdrawn",
            )
            return
        if result.error_code == "withdraw_in_progress":
            self._audit(
                AUDIT_WITHDRAW_FAILED,
                anomaly_id=execution.get("anomaly_id"),
                mitigation_id=execution_id,
                vector=execution.get("vector"),
                candidate_kind=execution.get("candidate_kind"),
                connector_id=execution.get("connector_id"),
                idempotency_key=execution.get("idempotency_key"),
                command=candidate.withdraw_command,
                ttl=execution.get("ttl_seconds"),
                status="withdraw_pending",
                reason=result.error_code,
                error=result.error_message,
            )
            return
        retry_count = int_value(execution.get("retry_count")) + 1
        retry = result.transient and retry_count <= self.max_withdraw_retries
        conn = self.connection_factory()
        try:
            conn.execute(
                """
                UPDATE mitigation_executions
                SET status = ?, retry_count = ?, withdraw_result = ?, error_code = ?,
                    error_message = ?, updated_at = ?
                WHERE id = ? AND status = 'withdraw_pending'
                """,
                (
                    "withdraw_pending" if retry else "failed",
                    retry_count,
                    json_dump(result.result),
                    result.error_code or "withdraw_failed",
                    result.error_message or result.error_code or "withdraw_failed",
                    utc_now_iso(),
                    execution_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        stats["failed"] += 0 if retry else 1
        self._audit(
            AUDIT_WITHDRAW_FAILED,
            anomaly_id=execution.get("anomaly_id"),
            mitigation_id=execution_id,
            vector=execution.get("vector"),
            candidate_kind=execution.get("candidate_kind"),
            connector_id=execution.get("connector_id"),
            idempotency_key=execution.get("idempotency_key"),
            command=candidate.withdraw_command,
            ttl=execution.get("ttl_seconds"),
            status="withdraw_pending" if retry else "failed",
            reason=result.error_code,
            error=result.error_message,
        )

    def _mark_withdrawn(self, execution_id: int, result: Mapping[str, Any], *, expired: bool) -> None:
        now = utc_now_iso()
        conn = self.connection_factory()
        try:
            row = conn.execute(
                "SELECT metadata_json FROM mitigation_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
            metadata = json_load(row["metadata_json"], {}) if row is not None else {}
            if not isinstance(metadata, dict):
                metadata = {}
            metadata["expired"] = bool(expired)
            conn.execute(
                """
                UPDATE mitigation_executions
                SET status = 'withdrawn', withdrawn_at = ?, withdraw_result = ?,
                    error_code = '', error_message = '', updated_at = ?,
                    metadata_json = ?
                WHERE id = ? AND status IN ('active', 'applying', 'withdraw_pending')
                """,
                (now, json_dump(dict(result)), now, json_dump(metadata), execution_id),
            )
            conn.commit()
        finally:
            conn.close()

    def _mark_failed(self, execution_id: int, error_code: str, error_message: str) -> None:
        conn = self.connection_factory()
        try:
            conn.execute(
                """
                UPDATE mitigation_executions
                SET status = 'failed', error_code = ?, error_message = ?, updated_at = ?
                WHERE id = ? AND status NOT IN ('withdrawn', 'expired', 'cancelled')
                """,
                (clean_text(error_code), clean_text(error_message), utc_now_iso(), execution_id),
            )
            conn.commit()
        finally:
            conn.close()

    def get_execution(self, execution_id: int) -> dict[str, Any]:
        conn = self.connection_factory()
        try:
            row = conn.execute("SELECT * FROM mitigation_executions WHERE id = ?", (int(execution_id),)).fetchone()
            if row is None:
                raise KeyError(f"mitigation execution {execution_id} not found")
            item = execution_row_to_dict(row)
            item["anomaly_ids"] = [
                int(link["anomaly_id"])
                for link in conn.execute(
                    "SELECT anomaly_id FROM mitigation_execution_anomalies WHERE execution_id = ? ORDER BY anomaly_id",
                    (int(execution_id),),
                ).fetchall()
            ]
            return item
        finally:
            conn.close()

    def list_executions(
        self,
        *,
        anomaly_id: int | None = None,
        status: str = "",
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        conn = self.connection_factory()
        try:
            ensure_automatic_mitigation_schema(conn)
            filters: list[str] = []
            values: list[Any] = []
            if anomaly_id is not None:
                filters.append(
                    "EXISTS (SELECT 1 FROM mitigation_execution_anomalies l "
                    "WHERE l.execution_id = e.id AND l.anomaly_id = ?)"
                )
                values.append(int(anomaly_id))
            if clean_text(status):
                if clean_text(status) not in EXECUTION_STATUSES:
                    return []
                filters.append("e.status = ?")
                values.append(clean_text(status))
            where = f"WHERE {' AND '.join(filters)}" if filters else ""
            rows = conn.execute(
                f"SELECT e.* FROM mitigation_executions e {where} ORDER BY e.updated_at DESC, e.id DESC LIMIT ?",
                (*values, max(1, min(int(limit), 1000))),
            ).fetchall()
            return [execution_row_to_dict(row) for row in rows]
        finally:
            conn.close()
