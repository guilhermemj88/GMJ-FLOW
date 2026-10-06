"""Testes do core de correlacao de anomalias (ocorrencias + sujeito canonico).

Fase "reincidencia por sujeito real": valida o registro de ocorrencias
(continuacao x reincidencia), a identidade canonica do sujeito (incluindo
resolucao CGNAT) e o backfill idempotente do historico.
"""

import gc
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_anomaly_threshold_policy_static import main
from app.services import anomaly_correlation as corr
from app.services.cgnat_mapping import ensure_cgnat_schema


def _iso(hour: int, minute: int = 0, *, day: int = 6, month: int = 10, year: int = 2026) -> str:
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:00Z"


def _receive_anomaly(**overrides):
    anomaly = {
        "vector": "DNS_REFLECTION_INBOUND",
        "direction": "receives",
        "protocol": "udp",
        "dst_ip": "45.163.144.18",
        "target_ip": "45.163.144.18",
        "target_role": "dst_ip",
        "scope_type": "internal_ip_32",
        "severity": "warning",
    }
    anomaly.update(overrides)
    return anomaly


class AnomalyCorrelationTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "gmjflow.db")
        self.environment = mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": self.db_path}, clear=False)
        self.ready = mock.patch.object(main, "SENSOR_DB_READY", False)
        self.password = mock.patch.object(main, "hash_password", return_value="test-hash")
        self.environment.start()
        self.ready.start()
        self.password.start()
        corr.reset_schema_cache()
        main.ensure_sensor_db()

    def tearDown(self):
        self.password.stop()
        self.ready.stop()
        self.environment.stop()
        corr.reset_schema_cache()
        gc.collect()
        self.tmpdir.cleanup()

    def occurrences(self, table: str, anomaly_id: int):
        with main.sqlite_connection() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT * FROM anomaly_occurrences
                    WHERE anomaly_table = ? AND anomaly_id = ?
                    ORDER BY first_seen, id
                    """,
                    (table, anomaly_id),
                )
            ]

    def setup_cgnat(self, mappings):
        with main.sqlite_connection() as conn:
            ensure_cgnat_schema(conn)
            conn.execute(
                "INSERT INTO cgnat_pools (name, prefix, mode, active, created_at, updated_at) VALUES (?, ?, 'non_deterministic', 1, ?, ?)",
                ("POOL-TESTE", "45.168.203.0/25", corr._now_iso(), corr._now_iso()),
            )
            cursor = conn.execute(
                """
                INSERT INTO cgnat_import_batches (filename, original_filename, file_hash, status, created_at, activated_at)
                VALUES ('t.txt', 't.txt', 'hash-t', 'active', ?, ?)
                """,
                (corr._now_iso(), corr._now_iso()),
            )
            batch_id = int(cursor.lastrowid or 0)
            for mapping in mappings:
                conn.execute(
                    """
                    INSERT INTO cgnat_port_mappings (
                        batch_id, source_type, source_filename, public_ip, private_ip, protocol,
                        port_start, port_end, subscriber_id, active, confidence, created_at, updated_at
                    ) VALUES (?, 'expanded_mapping_table', 't.txt', ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                    """,
                    (
                        batch_id,
                        mapping["public_ip"],
                        mapping["private_ip"],
                        mapping.get("protocol", "any"),
                        mapping["port_start"],
                        mapping["port_end"],
                        mapping.get("subscriber_id"),
                        mapping.get("confidence", 1.0),
                        corr._now_iso(),
                        corr._now_iso(),
                    ),
                )
            conn.commit()


class OccurrenceRecordingTest(AnomalyCorrelationTestBase):
    def test_record_creates_first_occurrence(self):
        anomaly = _receive_anomaly()
        with main.sqlite_connection() as conn:
            action = corr.record_anomaly_occurrence(
                conn,
                anomaly_table="security_anomalies",
                anomaly_id=1,
                anomaly=anomaly,
                first_seen=_iso(12, 0),
                last_seen=_iso(12, 0),
                severity="warning",
                metric="bits_s",
                metric_value=15_000_000.0,
            )
        self.assertEqual(action, "started")
        rows = self.occurrences("security_anomalies", 1)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["subject_type"], "ip")
        self.assertEqual(row["subject_key"], "45.163.144.18")
        self.assertEqual(row["operational_day"], "2026-10-06")
        self.assertEqual(row["vector_key"], "DNS_REFLECTION_INBOUND")
        self.assertIsNone(row["ended_at"])

    def test_record_continuation_keeps_single_occurrence(self):
        anomaly = _receive_anomaly()
        with main.sqlite_connection() as conn:
            corr.record_anomaly_occurrence(
                conn,
                anomaly_table="security_anomalies",
                anomaly_id=2,
                anomaly=anomaly,
                first_seen=_iso(12, 0),
                last_seen=_iso(12, 0),
                severity="warning",
            )
            action = corr.record_anomaly_occurrence(
                conn,
                anomaly_table="security_anomalies",
                anomaly_id=2,
                anomaly=anomaly,
                first_seen=_iso(12, 0),
                last_seen=_iso(12, 4),
                severity="critical",
            )
        self.assertEqual(action, "continued")
        rows = self.occurrences("security_anomalies", 2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["last_seen"], _iso(12, 4))
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertEqual(rows[0]["first_seen"], _iso(12, 0))

    def test_record_gap_without_end_starts_new_occurrence(self):
        anomaly = _receive_anomaly()
        with main.sqlite_connection() as conn:
            corr.record_anomaly_occurrence(
                conn,
                anomaly_table="security_anomalies",
                anomaly_id=3,
                anomaly=anomaly,
                first_seen=_iso(10, 0),
                last_seen=_iso(10, 5),
            )
            action = corr.record_anomaly_occurrence(
                conn,
                anomaly_table="security_anomalies",
                anomaly_id=3,
                anomaly=anomaly,
                first_seen=_iso(15, 0),
                last_seen=_iso(15, 0),
            )
        self.assertEqual(action, "started")
        rows = self.occurrences("security_anomalies", 3)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["last_seen"], _iso(10, 5))
        self.assertEqual(rows[1]["first_seen"], _iso(15, 0))

    def test_mark_ended_then_record_starts_new_occurrence(self):
        anomaly = _receive_anomaly()
        with main.sqlite_connection() as conn:
            corr.record_anomaly_occurrence(
                conn,
                anomaly_table="security_anomalies",
                anomaly_id=4,
                anomaly=anomaly,
                first_seen=_iso(9, 0),
                last_seen=_iso(9, 30),
            )
            ended = corr.mark_occurrences_ended(conn, "security_anomalies", [4], _iso(9, 40))
            action = corr.record_anomaly_occurrence(
                conn,
                anomaly_table="security_anomalies",
                anomaly_id=4,
                anomaly=anomaly,
                first_seen=_iso(9, 45),
                last_seen=_iso(9, 45),
            )
        self.assertEqual(ended, 1)
        self.assertEqual(action, "started")
        rows = self.occurrences("security_anomalies", 4)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ended_at"], _iso(9, 40))
        self.assertIsNone(rows[1]["ended_at"])

    def test_mark_ended_is_noop_without_open_occurrence(self):
        with main.sqlite_connection() as conn:
            ended = corr.mark_occurrences_ended(conn, "security_anomalies", [999], _iso(9, 40))
        self.assertEqual(ended, 0)

    def test_operational_day_uses_sao_paulo_timezone(self):
        anomaly = _receive_anomaly()
        with main.sqlite_connection() as conn:
            corr.record_anomaly_occurrence(
                conn,
                anomaly_table="security_anomalies",
                anomaly_id=5,
                anomaly=anomaly,
                first_seen=_iso(2, 30),
                last_seen=_iso(2, 30),
            )
        rows = self.occurrences("security_anomalies", 5)
        self.assertEqual(rows[0]["operational_day"], "2026-10-05")


class SubjectIdentityTest(AnomalyCorrelationTestBase):
    def test_subject_outside_pool_is_plain_ip(self):
        anomaly = _receive_anomaly(dst_ip="200.10.20.30", target_ip="200.10.20.30")
        with main.sqlite_connection() as conn:
            subject = corr.resolve_subject_for_anomaly(conn, anomaly, table="security_anomalies")
        self.assertEqual(subject["subject_type"], "ip")
        self.assertEqual(subject["subject_key"], "200.10.20.30")
        self.assertEqual(subject["subject_confidence"], "high")

    def test_subject_in_pool_without_mapping_falls_back_to_public(self):
        self.setup_cgnat([])
        anomaly = _receive_anomaly(dst_ip="45.168.203.83", target_ip="45.168.203.83", top_dst_port=53, direction="receives")
        anomaly["top_dst_port"] = 53
        with main.sqlite_connection() as conn:
            subject = corr.resolve_subject_for_anomaly(conn, anomaly, table="security_anomalies")
        self.assertEqual(subject["subject_type"], "cgnat_public_ip")
        self.assertEqual(subject["subject_key"], "45.168.203.83")
        self.assertEqual(subject["subject_confidence"], "low")
        self.assertTrue(subject["subject_context"]["fallback"])
        self.assertEqual(subject["subject_context"]["cgnat"]["reason"], "no_mapping")

    def test_subject_in_pool_without_port_falls_back(self):
        self.setup_cgnat([{"public_ip": "45.168.203.83", "private_ip": "100.97.0.17", "port_start": 1, "port_end": 65535}])
        anomaly = _receive_anomaly(dst_ip="45.168.203.83", target_ip="45.168.203.83", direction="receives")
        anomaly.pop("top_dst_port", None)
        with main.sqlite_connection() as conn:
            subject = corr.resolve_subject_for_anomaly(conn, anomaly, table="security_anomalies")
        self.assertEqual(subject["subject_type"], "cgnat_public_ip")
        self.assertEqual(subject["subject_context"]["cgnat"]["reason"], "no_public_port")

    def test_subject_cgnat_resolved_uses_subscriber_id(self):
        self.setup_cgnat(
            [
                {
                    "public_ip": "45.168.203.83",
                    "private_ip": "100.97.0.17",
                    "port_start": 18400,
                    "port_end": 18499,
                    "subscriber_id": "SUB-777",
                }
            ]
        )
        anomaly = _receive_anomaly(dst_ip="45.168.203.83", target_ip="45.168.203.83", direction="receives")
        anomaly["top_dst_port"] = 18432
        with main.sqlite_connection() as conn:
            subject = corr.resolve_subject_for_anomaly(conn, anomaly, table="security_anomalies")
        self.assertEqual(subject["subject_type"], "cgnat_subscriber")
        self.assertEqual(subject["subject_key"], "SUB-777")
        self.assertEqual(subject["subject_confidence"], "high")
        cgnat = subject["subject_context"]["cgnat"]
        self.assertTrue(cgnat["resolved"])
        self.assertEqual(cgnat["private_ip"], "100.97.0.17")

    def test_subject_cgnat_resolved_uses_private_ip_without_subscriber(self):
        self.setup_cgnat(
            [
                {
                    "public_ip": "45.168.203.90",
                    "private_ip": "100.97.0.44",
                    "port_start": 1000,
                    "port_end": 2000,
                }
            ]
        )
        anomaly = _receive_anomaly(dst_ip="45.168.203.90", target_ip="45.168.203.90", direction="receives")
        anomaly["top_dst_port"] = 1500
        with main.sqlite_connection() as conn:
            subject = corr.resolve_subject_for_anomaly(conn, anomaly, table="security_anomalies")
        self.assertEqual(subject["subject_type"], "cgnat_private_ip")
        self.assertEqual(subject["subject_key"], "100.97.0.44")

    def test_same_public_different_private_do_not_correlate(self):
        self.setup_cgnat(
            [
                {"public_ip": "45.168.203.83", "private_ip": "100.97.0.17", "port_start": 1000, "port_end": 1999},
                {"public_ip": "45.168.203.83", "private_ip": "100.97.0.99", "port_start": 2000, "port_end": 2999},
            ]
        )
        with main.sqlite_connection() as conn:
            first = _receive_anomaly(direction="receives", top_dst_port=1500)
            first["dst_ip"] = first["target_ip"] = "45.168.203.83"
            first["top_dst_port"] = 1500
            second = dict(first, top_dst_port=2500)
            subject_a = corr.resolve_subject_for_anomaly(conn, first, table="security_anomalies")
            subject_b = corr.resolve_subject_for_anomaly(conn, second, table="security_anomalies")
        self.assertEqual(subject_a["subject_type"], "cgnat_private_ip")
        self.assertEqual(subject_b["subject_type"], "cgnat_private_ip")
        self.assertNotEqual(subject_a["subject_key"], subject_b["subject_key"])

    def test_same_subscriber_across_publics_correlates(self):
        self.setup_cgnat(
            [
                {
                    "public_ip": "45.168.203.10",
                    "private_ip": "100.97.0.10",
                    "port_start": 1000,
                    "port_end": 1999,
                    "subscriber_id": "SUB-SHARED",
                },
                {
                    "public_ip": "45.168.203.11",
                    "private_ip": "100.97.0.10",
                    "port_start": 3000,
                    "port_end": 3999,
                    "subscriber_id": "SUB-SHARED",
                },
            ]
        )
        with main.sqlite_connection() as conn:
            first = _receive_anomaly(direction="receives")
            first["dst_ip"] = first["target_ip"] = "45.168.203.10"
            first["top_dst_port"] = 1500
            second = _receive_anomaly(direction="receives")
            second["dst_ip"] = second["target_ip"] = "45.168.203.11"
            second["top_dst_port"] = 3500
            subject_a = corr.resolve_subject_for_anomaly(conn, first, table="security_anomalies")
            subject_b = corr.resolve_subject_for_anomaly(conn, second, table="security_anomalies")
        self.assertEqual(subject_a["subject_key"], "SUB-SHARED")
        self.assertEqual(subject_b["subject_key"], "SUB-SHARED")

    def test_subnet_domain_uses_prefix_subject(self):
        anomaly = {
            "vector": "DNS_REFLECTION_INBOUND_MULTI",
            "domain": "subnet",
            "direction": "receives",
            "prefix_cidr": "45.163.144.0/24",
            "protocol": "udp",
            "severity": "warning",
        }
        with main.sqlite_connection() as conn:
            subject = corr.resolve_subject_for_anomaly(conn, anomaly, table="security_anomalies")
        self.assertEqual(subject["subject_type"], "prefix")
        self.assertEqual(subject["subject_key"], "45.163.144.0/24")


class BackfillTest(AnomalyCorrelationTestBase):
    def _insert_security_anomaly(self, conn, vector: str, dst_ip: str, first_seen: str, last_seen: str, status="active"):
        cursor = conn.execute(
            """
            INSERT INTO security_anomalies (vector, severity, status, domain, direction, src_ip, dst_ip, target_ip,
                target_role, protocol, first_seen, last_seen, created_at, updated_at, dedupe_key)
            VALUES (?, 'warning', ?, 'internal_ip', 'receives', '', ?, ?, 'dst_ip', 'UDP', ?, ?, ?, ?, ?)
            """,
            (vector, status, dst_ip, dst_ip, first_seen, last_seen, first_seen, last_seen, f"{vector}|{dst_ip}"),
        )
        return int(cursor.lastrowid or 0)

    def test_backfill_inserts_one_occurrence_per_row_and_is_idempotent(self):
        with main.sqlite_connection() as conn:
            sec_id = self._insert_security_anomaly(conn, "DNS_AMP_INBOUND_HIGH_BITS", "45.163.144.18", _iso(8, 0), _iso(8, 10))
            conn.commit()
        with main.sqlite_connection() as conn:
            self.assertTrue(conn.execute("SELECT 1 FROM anomaly_occurrences").fetchone() is None)
            conn.execute("DELETE FROM system_settings WHERE key = ?", (corr.BACKFILL_FLAG_KEY,))
            conn.commit()
            corr.reset_schema_cache()
            corr.ensure_anomaly_correlation_schema(conn)
            rows = conn.execute(
                "SELECT * FROM anomaly_occurrences WHERE anomaly_table = 'security_anomalies' AND anomaly_id = ?",
                (sec_id,),
            ).fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["first_seen"], _iso(8, 0))
            self.assertEqual(rows[0]["subject_key"], "45.163.144.18")
            corr.reset_schema_cache()
            corr.ensure_anomaly_correlation_schema(conn)
            again = conn.execute("SELECT COUNT(*) FROM anomaly_occurrences").fetchone()[0]
            self.assertEqual(again, 1)


class UpsertIntegrationTest(AnomalyCorrelationTestBase):
    def test_upsert_security_anomaly_records_occurrence(self):
        candidate = {
            "vector": "DNS_REFLECTION_INBOUND",
            "severity": "warning",
            "zone_id": 6,
            "zone_name": "Zona 6",
            "template_id": 1,
            "template_name": "default",
            "rule_id": 29,
            "prefix_id": None,
            "prefix_cidr": "",
            "domain": "internal_ip",
            "direction": "receives",
            "src_ip": "",
            "dst_ip": "45.163.144.18",
            "target_ip": "45.163.144.18",
            "target_role": "dst_ip",
            "scope_type": "internal_ip_32",
            "protocol": "udp",
            "packets_s": 3000.0,
            "bits_s": 15_000_000.0,
            "first_seen": _iso(12, 0),
            "last_seen": _iso(12, 1),
        }
        with main.sqlite_connection() as conn:
            action = main.upsert_security_anomaly(conn, candidate)
            conn.commit()
        self.assertEqual(action, "created")
        with main.sqlite_connection() as conn:
            row = conn.execute("SELECT id FROM security_anomalies ORDER BY id DESC LIMIT 1").fetchone()
            anomaly_id = int(row["id"])
            occurrences = conn.execute(
                "SELECT * FROM anomaly_occurrences WHERE anomaly_table = 'security_anomalies' AND anomaly_id = ?",
                (anomaly_id,),
            ).fetchall()
        self.assertEqual(len(occurrences), 1)
        self.assertEqual(occurrences[0]["subject_key"], "45.163.144.18")
        self.assertEqual(occurrences[0]["vector_key"], "DNS_REFLECTION_INBOUND")
        # segundo match dentro do gap = continuacao, mesmo em outra chamada do upsert
        candidate_2 = dict(candidate, last_seen=_iso(12, 3))
        with main.sqlite_connection() as conn:
            action_2 = main.upsert_security_anomaly(conn, candidate_2)
            conn.commit()
        self.assertEqual(action_2, "updated")
        with main.sqlite_connection() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM anomaly_occurrences WHERE anomaly_table = 'security_anomalies' AND anomaly_id = ?",
                (anomaly_id,),
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_upsert_does_not_change_dedupe_or_status_fields(self):
        candidate = {
            "vector": "DNS_REFLECTION_INBOUND",
            "severity": "warning",
            "zone_id": 6,
            "zone_name": "Zona 6",
            "template_id": 1,
            "template_name": "default",
            "rule_id": 29,
            "prefix_id": None,
            "prefix_cidr": "",
            "domain": "internal_ip",
            "direction": "receives",
            "src_ip": "",
            "dst_ip": "45.163.144.19",
            "target_ip": "45.163.144.19",
            "target_role": "dst_ip",
            "scope_type": "internal_ip_32",
            "protocol": "udp",
            "packets_s": 3000.0,
            "bits_s": 15_000_000.0,
            "first_seen": _iso(12, 0),
            "last_seen": _iso(12, 1),
        }
        with main.sqlite_connection() as conn:
            main.upsert_security_anomaly(conn, candidate)
            conn.commit()
        with main.sqlite_connection() as conn:
            row = dict(conn.execute("SELECT * FROM security_anomalies ORDER BY id DESC LIMIT 1").fetchone())
            occurrence_count = conn.execute("SELECT COUNT(*) FROM anomaly_occurrences").fetchone()[0]
        self.assertEqual(row["dedupe_key"], "DNS_REFLECTION_INBOUND|6|45.163.144.19/32|udp")
        self.assertEqual(row["status"], "active")
        self.assertEqual(occurrence_count, 1)


class CorrelationSummaryTest(AnomalyCorrelationTestBase):
    def _record(
        self,
        conn,
        anomaly_id,
        first,
        last,
        *,
        vector="DNS_REFLECTION_INBOUND",
        dst="45.163.144.18",
        severity="warning",
        table="security_anomalies",
    ):
        anomaly = _receive_anomaly(dst_ip=dst, target_ip=dst, vector=vector, severity=severity)
        return corr.record_anomaly_occurrence(
            conn,
            anomaly_table=table,
            anomaly_id=anomaly_id,
            anomaly=anomaly,
            first_seen=first,
            last_seen=last,
            severity=severity,
        )

    def test_first_occurrence_summary(self):
        with main.sqlite_connection() as conn:
            self._record(conn, 10, _iso(10, 0), _iso(10, 1))
            summary = corr.resolve_anomaly_correlation(conn, "security_anomalies", 10)
        self.assertIsNotNone(summary)
        self.assertFalse(summary["is_recurrence"])
        self.assertEqual(summary["occurrences_today"], 1)
        self.assertEqual(summary["occurrence_number_today"], 1)
        self.assertEqual(summary["previous_occurrences_today"], 0)
        self.assertEqual(summary["previous_occurrences"], [])
        self.assertEqual(summary["subject_type"], "ip")
        self.assertEqual(summary["subject_key"], "45.163.144.18")
        self.assertEqual(summary["timezone"], "America/Sao_Paulo")
        self.assertEqual(summary["operational_day"], "2026-10-06")

    def test_continuation_keeps_single_count(self):
        with main.sqlite_connection() as conn:
            self._record(conn, 11, _iso(10, 0), _iso(10, 1))
            self._record(conn, 11, _iso(10, 0), _iso(10, 3))
            summary = corr.resolve_anomaly_correlation(conn, "security_anomalies", 11)
        self.assertFalse(summary["is_recurrence"])
        self.assertEqual(summary["occurrences_today"], 1)

    def test_ended_and_return_counts_two(self):
        with main.sqlite_connection() as conn:
            self._record(conn, 12, _iso(10, 0), _iso(10, 1))
            corr.mark_occurrences_ended(conn, "security_anomalies", [12], _iso(10, 2))
            self._record(conn, 12, _iso(11, 0), _iso(11, 1))
            summary = corr.resolve_anomaly_correlation(conn, "security_anomalies", 12)
        self.assertTrue(summary["is_recurrence"])
        self.assertEqual(summary["occurrences_today"], 2)
        self.assertEqual(summary["occurrence_number_today"], 2)
        self.assertEqual(summary["previous_occurrences_today"], 1)
        self.assertEqual(len(summary["previous_occurrences"]), 1)
        self.assertEqual(summary["previous_occurrences"][0]["first_seen"], _iso(10, 0))
        self.assertEqual(summary["previous_occurrences"][0]["ended_at"], _iso(10, 2))
        self.assertEqual(summary["last_previous_occurrence_at"], _iso(10, 0))

    def test_three_recurrences_numbering(self):
        with main.sqlite_connection() as conn:
            self._record(conn, 13, _iso(8, 0), _iso(8, 5))
            self._record(conn, 13, _iso(10, 0), _iso(10, 5))
            self._record(conn, 13, _iso(12, 0), _iso(12, 5))
            self._record(conn, 13, _iso(14, 0), _iso(14, 5))
            summary = corr.resolve_anomaly_correlation(conn, "security_anomalies", 13)
        self.assertTrue(summary["is_recurrence"])
        self.assertEqual(summary["occurrence_number_today"], 4)
        self.assertEqual(summary["occurrences_today"], 4)
        self.assertEqual(summary["previous_occurrences_today"], 3)
        self.assertFalse(summary["previous_occurrences_truncated"])

    def test_same_ip_different_vector_not_correlated(self):
        with main.sqlite_connection() as conn:
            self._record(conn, 14, _iso(10, 0), _iso(10, 1), vector="DNS_REFLECTION_INBOUND")
            self._record(conn, 15, _iso(10, 30), _iso(10, 31), vector="NTP_REFLECTION_INBOUND")
            first = corr.resolve_anomaly_correlation(conn, "security_anomalies", 14)
            second = corr.resolve_anomaly_correlation(conn, "security_anomalies", 15)
        self.assertFalse(first["is_recurrence"])
        self.assertFalse(second["is_recurrence"])
        self.assertEqual(second["occurrences_today"], 1)

    def test_different_ip_same_vector_not_correlated(self):
        with main.sqlite_connection() as conn:
            self._record(conn, 16, _iso(10, 0), _iso(10, 1), dst="45.163.144.18")
            self._record(conn, 17, _iso(10, 30), _iso(10, 31), dst="45.163.144.19")
            second = corr.resolve_anomaly_correlation(conn, "security_anomalies", 17)
        self.assertFalse(second["is_recurrence"])
        self.assertEqual(second["occurrences_today"], 1)

    def test_previous_day_not_counted(self):
        with main.sqlite_connection() as conn:
            # 2026-10-05 23:00 BRT (02:00Z do dia 06) ainda e dia 5
            self._record(conn, 18, _iso(2, 0, day=6), _iso(2, 0, day=6))
            # 2026-10-06 09:00 BRT
            self._record(conn, 19, _iso(12, 0), _iso(12, 0), dst="45.163.144.18")
            second = corr.resolve_anomaly_correlation(conn, "security_anomalies", 19)
        self.assertEqual(second["operational_day"], "2026-10-06")
        # a ocorrencia do dia anterior tem o mesmo sujeito/regra? dst igual e dia diferente:
        # primeira ocorrencia usou dst padrao tambem; dia operacional 2026-10-05 => nao conta
        self.assertFalse(second["is_recurrence"])
        self.assertEqual(second["occurrences_today"], 1)

    def test_timezone_boundary_same_operational_day(self):
        with main.sqlite_connection() as conn:
            # 2026-10-06 09:00 BRT (12:00Z dia 6)
            self._record(conn, 20, _iso(12, 0), _iso(12, 0))
            # 2026-10-07 02:30Z = 2026-10-06 23:30 BRT -> mesmo dia operacional
            self._record(conn, 21, _iso(2, 30, day=7), _iso(2, 30, day=7))
            summary = corr.resolve_anomaly_correlation(conn, "security_anomalies", 21)
        self.assertEqual(summary["operational_day"], "2026-10-06")
        self.assertTrue(summary["is_recurrence"])
        self.assertEqual(summary["occurrences_today"], 2)

    def test_mark_ended_alone_does_not_recount(self):
        with main.sqlite_connection() as conn:
            self._record(conn, 22, _iso(10, 0), _iso(10, 1))
            corr.mark_occurrences_ended(conn, "security_anomalies", [22], _iso(10, 2))
            summary = corr.resolve_anomaly_correlation(conn, "security_anomalies", 22)
        self.assertFalse(summary["is_recurrence"])
        self.assertEqual(summary["occurrences_today"], 1)

    def test_current_occurrence_excluded_and_details_limited(self):
        with main.sqlite_connection() as conn:
            for hour in (8, 10, 12, 14, 16):
                self._record(conn, 23, _iso(hour, 0), _iso(hour, 5))
            summary = corr.resolve_anomaly_correlation(conn, "security_anomalies", 23)
            current_ids = {
                row["id"]
                for row in conn.execute(
                    "SELECT id FROM anomaly_occurrences WHERE anomaly_id = 23 ORDER BY first_seen DESC LIMIT 1"
                )
            }
        self.assertEqual(summary["occurrences_today"], 5)
        self.assertEqual(summary["occurrence_number_today"], 5)
        self.assertEqual(summary["previous_occurrences_today"], 4)
        self.assertEqual(len(summary["previous_occurrences"]), 3)
        self.assertTrue(summary["previous_occurrences_truncated"])
        listed = {item["occurrence_id"] for item in summary["previous_occurrences"]}
        self.assertTrue(listed.isdisjoint(current_ids))

    def test_details_limit_parameter(self):
        with main.sqlite_connection() as conn:
            for hour in (8, 10, 12, 14, 16):
                self._record(conn, 24, _iso(hour, 0), _iso(hour, 5))
            summary = corr.resolve_anomaly_correlation(conn, "security_anomalies", 24, details_limit=10)
        self.assertEqual(len(summary["previous_occurrences"]), 4)
        self.assertFalse(summary["previous_occurrences_truncated"])

    def test_attach_to_consolidated_security_items(self):
        with main.sqlite_connection() as conn:
            self._record(conn, 25, _iso(10, 0), _iso(10, 1))
            self._record(conn, 25, _iso(11, 0), _iso(11, 1))
            security_item = {"id": 25, "source": "security_anomalies", "security_anomaly_ids": [25]}
            corr.attach_correlation_to_anomaly_items(conn, [security_item])
        self.assertIn("correlation", security_item)
        self.assertTrue(security_item["correlation"]["is_recurrence"])
        self.assertEqual(security_item["correlation"]["occurrences_today"], 2)

    def test_list_security_anomalies_returns_correlation(self):
        candidate = {
            "vector": "DNS_REFLECTION_INBOUND",
            "severity": "warning",
            "zone_id": 6,
            "zone_name": "Zona 6",
            "template_id": 1,
            "template_name": "default",
            "rule_id": 29,
            "prefix_id": None,
            "prefix_cidr": "",
            "domain": "internal_ip",
            "direction": "receives",
            "src_ip": "",
            "dst_ip": "45.163.144.30",
            "target_ip": "45.163.144.30",
            "target_role": "dst_ip",
            "scope_type": "internal_ip_32",
            "protocol": "udp",
            "packets_s": 3000.0,
            "bits_s": 15_000_000.0,
            "first_seen": _iso(12, 0),
            "last_seen": _iso(12, 1),
        }
        with main.sqlite_connection() as conn:
            main.upsert_security_anomaly(conn, candidate)
            conn.commit()
        payload = main.list_security_anomalies("active", None, None, None, None, None, None, None, 50)
        self.assertTrue(payload["items"])
        item = payload["items"][0]
        self.assertIn("correlation", item)
        self.assertEqual(item["correlation"]["subject_key"], "45.163.144.30")
        self.assertEqual(item["correlation"]["occurrences_today"], 1)
        self.assertFalse(item["correlation"]["is_recurrence"])


    def test_upsert_detection_template_dns_anomaly_event_records_occurrence(self):
        candidate = {
            "vector": "DNS_SINGLE_FLOW_OUTBOUND",
            "rule_name": "DNS_SINGLE_FLOW_OUTBOUND",
            "severity": "critical",
            "zone_id": 7,
            "zone_name": "Zona 7",
            "template_id": 2,
            "rule_id": 18,
            "first_seen": _iso(12, 0),
            "last_seen": _iso(12, 1),
            "top_src_ip": "45.168.203.126",
            "top_src_port": 53075,
            "top_dst_ip": "45.163.144.18",
            "top_dst_port": 53,
            "metric": "packets_s",
            "metric_value": 6000.0,
            "packets_s": 6000.0,
            "flows": 1,
            "rule_config": {},
        }
        with main.sqlite_connection() as conn:
            action = main.upsert_detection_template_dns_anomaly_event(conn, candidate)
            conn.commit()
        self.assertEqual(action, "created")
        with main.sqlite_connection() as conn:
            row = conn.execute("SELECT id FROM anomaly_events ORDER BY id DESC LIMIT 1").fetchone()
            occurrences = conn.execute(
                "SELECT * FROM anomaly_occurrences WHERE anomaly_table = 'anomaly_events' AND anomaly_id = ?",
                (int(row["id"]),),
            ).fetchall()
        self.assertEqual(len(occurrences), 1)
        self.assertEqual(occurrences[0]["vector_key"], "DNS_SINGLE_FLOW_OUTBOUND")
        self.assertEqual(occurrences[0]["subject_key"], "45.168.203.126")
        # segundo match dentro do gap => continuacao
        candidate_2 = dict(candidate, last_seen=_iso(12, 3))
        with main.sqlite_connection() as conn:
            action_2 = main.upsert_detection_template_dns_anomaly_event(conn, candidate_2)
            conn.commit()
        self.assertEqual(action_2, "updated")
        with main.sqlite_connection() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM anomaly_occurrences WHERE anomaly_table = 'anomaly_events' AND anomaly_id = ?",
                (int(row["id"]),),
            ).fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
