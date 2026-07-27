import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.automatic_mitigation import (  # noqa: E402
    AUTOMATIC_PRIMARY,
    MANUAL_ALTERNATIVE,
    AutomaticMitigationOrchestrator,
    ExecutorResult,
    ensure_automatic_mitigation_schema,
)


class FakeExecutor:
    connector_type = "fake"

    def __init__(self):
        self.valid = True
        self.ready = True
        self.apply_success = True
        self.apply_transient = False
        self.withdraw_success = True
        self.status_value = "active"
        self.apply_calls = []
        self.withdraw_calls = []

    def validate(self, candidate):
        return ExecutorResult(
            self.valid,
            error_code="" if self.valid else "validation_failed",
            error_message="" if self.valid else "invalid command",
        )

    def readiness(self, candidate):
        return ExecutorResult(
            self.ready,
            error_code="" if self.ready else "connector_not_ready",
            error_message="" if self.ready else "connector not ready",
            transient=not self.ready,
        )

    def apply(self, candidate, execution):
        self.apply_calls.append((candidate, execution["id"]))
        return ExecutorResult(
            self.apply_success,
            result={"remote_id": f"rule-{execution['id']}", "status": "active"},
            error_code="" if self.apply_success else "apply_failed",
            error_message="" if self.apply_success else "apply failed",
            transient=self.apply_transient,
        )

    def withdraw(self, candidate, execution):
        self.withdraw_calls.append((candidate, execution["id"]))
        return ExecutorResult(
            self.withdraw_success,
            result={"remote_id": f"rule-{execution['id']}", "status": "withdrawn"},
            error_code="" if self.withdraw_success else "withdraw_failed",
            error_message="" if self.withdraw_success else "withdraw failed",
            transient=not self.withdraw_success,
        )

    def status(self, candidate, execution):
        return ExecutorResult(
            self.status_value in {"active", "withdrawn", "expired"},
            result={"status": self.status_value},
            error_code="" if self.status_value != "unknown" else "status_unknown",
            transient=self.status_value == "unknown",
        )


class AutomaticMitigationOrchestratorTest(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.close()
        self.db_path = handle.name
        self.executor = FakeExecutor()
        self.candidates = [self.candidate()]

        def connection_factory():
            conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            return conn

        self.connection_factory = connection_factory
        with self.connection_factory() as conn:
            ensure_automatic_mitigation_schema(conn)
            conn.commit()
        self.orchestrator = AutomaticMitigationOrchestrator(
            self.connection_factory,
            lambda _anomaly_id, _context: [dict(item) for item in self.candidates],
            {"fake": self.executor},
        )

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    @staticmethod
    def candidate(**overrides):
        item = {
            "anomaly_id": 101,
            "vector": "GENERIC_VECTOR",
            "profile_id": 7,
            "profile_name": "AUTO_PROFILE",
            "candidate_kind": AUTOMATIC_PRIMARY,
            "automatic_eligible": True,
            "auto_allowed": True,
            "priority": 100,
            "connector_id": 9,
            "connector_type": "fake",
            "connector_mode": "auto",
            "profile_mode": "automatic",
            "command": "announce logical rule",
            "withdraw_command": "withdraw logical rule",
            "normalized_match": {
                "address_family": "ipv4",
                "source": "",
                "destination": "198.51.100.8/32",
                "protocol": "udp",
                "source_port": "",
                "destination_port": "53",
            },
            "action": "discard",
            "ttl_seconds": 900,
            "gates": {"blocking": False},
            "policy_authorized": True,
            "policy_reason": "AUTO_ALLOWED",
            "anomaly_status": "active",
        }
        item.update(overrides)
        return item

    def rows(self):
        return self.orchestrator.list_executions(limit=100)

    def test_authorized_profile_executes_without_frontend_and_persists_active(self):
        result = self.orchestrator.process_anomaly(101, {"source": "detector"})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["status"], "active")
        self.assertEqual(len(self.executor.apply_calls), 1)
        self.assertTrue(result[0]["applied_at"])
        self.assertTrue(result[0]["expires_at"])
        self.assertEqual(len(self.rows()), 1)

    def test_manual_profile_and_manual_alternative_never_call_executor(self):
        self.candidates = [
            self.candidate(profile_mode="manual_approval"),
            self.candidate(candidate_kind=MANUAL_ALTERNATIVE, command="manual alternative"),
        ]
        result = self.orchestrator.process_anomaly(101)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["status"], "blocked")
        self.assertEqual(result[0]["error_code"], "profile_not_automatic")
        self.assertEqual(self.executor.apply_calls, [])

    def test_manual_connector_is_blocked(self):
        self.candidates = [self.candidate(connector_mode="manual_approval")]
        result = self.orchestrator.process_anomaly(101)
        self.assertEqual(result[0]["error_code"], "connector_not_automatic")
        self.assertEqual(self.executor.apply_calls, [])

    def test_not_ready_connector_is_blocked(self):
        self.executor.ready = False
        result = self.orchestrator.process_anomaly(101)
        self.assertEqual(result[0]["status"], "blocked")
        self.assertEqual(result[0]["error_code"], "connector_not_ready")
        self.assertEqual(self.executor.apply_calls, [])

    def test_blocking_gate_and_validation_failure_never_apply(self):
        self.candidates = [self.candidate(gates={"blocking": True, "reason": "whitelist"})]
        result = self.orchestrator.process_anomaly(101)
        self.assertEqual(result[0]["error_code"], "whitelist")
        self.assertEqual(self.executor.apply_calls, [])

        self.candidates = [self.candidate(command="different logical rule")]
        self.executor.valid = False
        second = self.orchestrator.process_anomaly(102)
        self.assertEqual(second[0]["error_code"], "validation_failed")
        self.assertEqual(self.executor.apply_calls, [])

    def test_repeated_and_concurrent_evaluations_are_deduplicated(self):
        first = self.orchestrator.process_anomaly(101)
        second = self.orchestrator.process_anomaly(101)
        self.assertEqual(first[0]["id"], second[0]["id"])
        self.assertEqual(len(self.executor.apply_calls), 1)
        self.assertEqual(len(self.rows()), 1)

        self.candidates = [self.candidate(command="announce second rule", idempotency_key="logical-second")]
        barrier = threading.Barrier(2)
        original_validate = self.executor.validate

        def synchronized_validate(candidate):
            barrier.wait(timeout=5)
            return original_validate(candidate)

        self.executor.validate = synchronized_validate
        errors = []

        def run():
            try:
                self.orchestrator.process_anomaly(202)
            except Exception as exc:  # pragma: no cover - assertion reports any thread error.
                errors.append(exc)

        threads = [threading.Thread(target=run), threading.Thread(target=run)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(errors, [])
        second_rule_calls = [call for call in self.executor.apply_calls if call[0].command == "announce second rule"]
        self.assertEqual(len(second_rule_calls), 1)
        self.assertEqual(len([row for row in self.rows() if row["idempotency_key"] == "logical-second"]), 1)

    def test_apply_failure_is_persisted_as_failed(self):
        self.executor.apply_success = False
        result = self.orchestrator.process_anomaly(101)
        self.assertEqual(result[0]["status"], "failed")
        self.assertEqual(result[0]["error_code"], "apply_failed")
        self.assertEqual(result[0]["retry_count"], 1)

    def test_transient_apply_failure_retries_only_up_to_configured_limit(self):
        retrying = AutomaticMitigationOrchestrator(
            self.connection_factory,
            lambda _anomaly_id, _context: [self.candidate(command="retry rule", idempotency_key="retry-rule")],
            {"fake": self.executor},
            max_apply_retries=1,
        )
        self.executor.apply_success = False
        self.executor.apply_transient = True
        queued = retrying.process_anomaly(404)[0]
        self.assertEqual(queued["status"], "queued")
        self.assertEqual(queued["retry_count"], 1)
        with self.connection_factory() as conn:
            conn.execute(
                "UPDATE mitigation_executions SET next_retry_at = ? WHERE id = ?",
                ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), queued["id"]),
            )
            conn.commit()
        self.executor.apply_success = True
        retrying.reconcile()
        self.assertEqual(retrying.get_execution(queued["id"])["status"], "active")
        self.assertEqual(len(self.executor.apply_calls), 2)

    def test_ttl_withdraw_is_idempotent_and_allows_recurrence(self):
        active = self.orchestrator.process_anomaly(101)[0]
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        with self.connection_factory() as conn:
            conn.execute("UPDATE mitigation_executions SET expires_at = ? WHERE id = ?", (past, active["id"]))
            conn.commit()
        stats = self.orchestrator.reconcile()
        self.assertEqual(stats["withdrawn"], 1)
        self.assertEqual(self.orchestrator.get_execution(active["id"])["status"], "withdrawn")
        self.assertEqual(len(self.executor.withdraw_calls), 1)
        self.orchestrator.reconcile()
        self.assertEqual(len(self.executor.withdraw_calls), 1)

        recreated = self.orchestrator.process_anomaly(101)[0]
        self.assertNotEqual(recreated["id"], active["id"])
        self.assertEqual(recreated["status"], "active")

    def test_restart_recovers_pending_withdraw(self):
        active = self.orchestrator.process_anomaly(101)[0]
        with self.connection_factory() as conn:
            conn.execute(
                "UPDATE mitigation_executions SET status = 'withdraw_pending', withdraw_started_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), active["id"]),
            )
            conn.commit()
        restarted = AutomaticMitigationOrchestrator(
            self.connection_factory,
            lambda _anomaly_id, _context: [],
            {"fake": self.executor},
        )
        restarted.reconcile()
        self.assertEqual(restarted.get_execution(active["id"])["status"], "withdrawn")

    def test_equivalent_rule_is_shared_by_different_anomalies(self):
        first = self.orchestrator.process_anomaly(101)[0]
        second = self.orchestrator.process_anomaly(202)[0]
        self.assertEqual(first["id"], second["id"])
        linked = self.orchestrator.get_execution(first["id"])["anomaly_ids"]
        self.assertEqual(linked, [101, 202])
        self.assertEqual(len(self.executor.apply_calls), 1)

    def test_persistent_job_runs_pipeline_without_http_or_ui(self):
        job_id = self.orchestrator.enqueue(303, {"status": "active"})
        self.assertGreater(job_id, 0)
        stats = self.orchestrator.process_jobs()
        self.assertEqual(stats["completed"], 1)
        self.assertEqual(len(self.executor.apply_calls), 1)
        with self.connection_factory() as conn:
            job = conn.execute("SELECT status FROM automatic_mitigation_jobs WHERE id = ?", (job_id,)).fetchone()
        self.assertEqual(job["status"], "completed")

    def test_frontend_uses_execution_records_and_marks_automatic_application(self):
        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("/api/mitigation/executions?limit=200", html)
        self.assertIn("automaticMitigationExecutionsTable", html)
        self.assertIn("Aplicado automaticamente", html)
        self.assertIn("candidate.automatic_execution", html)

    def test_structured_audit_covers_evaluation_apply_dedup_and_withdraw(self):
        with self.assertLogs("gmj-flow.automatic-mitigation", level="INFO") as captured:
            active = self.orchestrator.process_anomaly(101)[0]
            self.orchestrator.process_anomaly(102)
            with self.connection_factory() as conn:
                conn.execute(
                    "UPDATE mitigation_executions SET expires_at = ? WHERE id = ?",
                    ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), active["id"]),
                )
                conn.commit()
            self.orchestrator.reconcile()
        audit = "\n".join(captured.output)
        for event in (
            "AUTO_MITIGATION_EVALUATION_STARTED",
            "AUTO_MITIGATION_EVALUATED",
            "AUTO_MITIGATION_QUEUED",
            "AUTO_MITIGATION_APPLY_STARTED",
            "AUTO_MITIGATION_APPLIED",
            "AUTO_MITIGATION_DEDUPLICATED",
            "AUTO_MITIGATION_WITHDRAW_STARTED",
            "AUTO_MITIGATION_WITHDRAWN",
        ):
            self.assertIn(event, audit)

    def test_dns_single_flow_executes_only_destination_udp53_with_default_ttl(self):
        dns_command = (
            "announce flow route { match { destination 83.29.96.194/32; "
            "protocol =udp; destination-port =53; } then { discard; } }"
        )
        self.candidates = [
            self.candidate(
                vector="DNS_SINGLE_FLOW_OUTBOUND",
                command=dns_command,
                withdraw_command=dns_command.replace("announce ", "withdraw ", 1),
                ttl_seconds=900,
                normalized_match={
                    "address_family": "ipv4",
                    "source": "",
                    "destination": "83.29.96.194/32",
                    "protocol": "udp",
                    "source_port": "",
                    "destination_port": "53",
                },
            ),
            self.candidate(
                vector="DNS_SINGLE_FLOW_OUTBOUND",
                candidate_kind=MANUAL_ALTERNATIVE,
                command=(
                    "announce flow route { match { source 45.5.248.196/32; "
                    "source-port =2258; destination 83.29.96.194/32; "
                    "protocol =udp; destination-port =53; } then { discard; } }"
                ),
            ),
        ]
        result = self.orchestrator.process_anomaly(2446)
        self.assertEqual(result[0]["status"], "active")
        self.assertEqual(result[0]["ttl_seconds"], 900)
        self.assertEqual(len(self.executor.apply_calls), 1)
        applied = self.executor.apply_calls[0][0]
        self.assertIn("destination 83.29.96.194/32", applied.command)
        self.assertIn("protocol =udp", applied.command)
        self.assertIn("destination-port =53", applied.command)
        self.assertNotIn("source ", applied.command)
        self.assertNotIn("source-port", applied.command)


if __name__ == "__main__":
    unittest.main()
