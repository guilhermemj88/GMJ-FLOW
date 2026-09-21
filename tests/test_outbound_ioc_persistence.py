"""P4 outbound IOC security-event persistence tests."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.security_events import ensure_security_event_schema  # noqa: E402
from app.services.outbound_ioc_aggregation import (  # noqa: E402
    AMBIGUOUS,
    ERROR,
    IDENTITY_CGNAT_SUBSCRIBER,
    IDENTITY_CUSTOMER_IP,
    RESOLVED,
    UNRESOLVED,
    CgnatResolution,
    OutboundIocAggregationCycle,
    OutboundIocRelationship,
)
from app.services.outbound_ioc_persistence import (  # noqa: E402
    DETECTOR,
    OutboundIocPersistence,
    build_vector,
)

BASE = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def rel(
    identity="10.0.0.10",
    ioc="203.0.113.10",
    identity_kind=IDENTITY_CUSTOMER_IP,
    first_seen=None,
    last_seen=None,
    hit_count=1,
    flows=1,
    packets=10,
    bytes_count=1000,
    providers=("CEREAL2",),
    indicator_types=("C2",),
    classifications=("c2",),
    categories=("c2",),
    signal_class="HIGH_VALUE",
    semantic_tier=1,
    botnet_family="",
    protocols=(6,),
    src_ports=(40000,),
    dst_ports=(443,),
    sensors=("edge",),
    cgnat=None,
):
    first = first_seen or iso(BASE)
    last = last_seen or iso(BASE + timedelta(minutes=1))
    return OutboundIocRelationship(
        internal_identity=identity,
        external_ioc=ioc,
        identity_kind=identity_kind,
        first_seen=first,
        last_seen=last,
        first_seen_epoch=BASE.timestamp(),
        last_seen_epoch=(BASE + timedelta(minutes=1)).timestamp(),
        hit_count=hit_count,
        flows=flows,
        packets=packets,
        bytes=bytes_count,
        protocols=set(protocols),
        src_ports=set(src_ports),
        dst_ports=set(dst_ports),
        sensors=set(sensors),
        providers=set(providers),
        indicator_types=set(indicator_types),
        classifications=set(classifications),
        categories=set(categories),
        botnet_families={botnet_family} if botnet_family else set(),
        tags=set(),
        signal_class=signal_class,
        semantic_tier=semantic_tier,
        cgnat=cgnat or CgnatResolution(status="NOT_APPLICABLE"),
        set_truncated=False,
    )


def cycle(*relationships):
    return OutboundIocAggregationCycle(tuple(relationships), (), {})


class PersistenceTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "events.db")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        ensure_security_event_schema(conn)
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def factory(self):
        def f():
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        return f

    def persistence(self, enabled=True):
        return OutboundIocPersistence(connection_factory=self.factory(), enabled=enabled)

    def event_rows(self, detector=DETECTOR):
        conn = self.factory()()
        try:
            rows = conn.execute(
                "SELECT * FROM security_events WHERE detector=?", (detector,)
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def event_count(self):
        return len(self.event_rows())


class PersistenceTest(PersistenceTestBase):
    def test_first_relationship_creates_one_event(self):
        p = self.persistence()
        p.persist(cycle(rel()))
        self.assertEqual(1, self.event_count())

    def test_same_relationship_updates_no_duplicate(self):
        p = self.persistence()
        p.persist(cycle(rel()))
        p.persist(cycle(rel(hit_count=2, flows=2)))
        self.assertEqual(1, self.event_count())

    def test_identical_replay_is_idempotent(self):
        p = self.persistence()
        c = cycle(rel())
        p.persist(c)
        p.persist(c)
        self.assertEqual(1, self.event_count())

    def test_counters_and_ioc_metadata_persisted(self):
        p = self.persistence()
        p.persist(cycle(rel(hit_count=7, flows=3, packets=50, bytes_count=5000)))
        rows = self.event_rows()
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual(50, row["packets"])  # canonical MAX semantics
        self.assertEqual(3, row["flows"])
        from app.services.threat_intelligence import safe_json
        ti = safe_json(row["threat_intel_json"], {})
        self.assertEqual(7, ti["hit_count"])
        self.assertEqual(3, ti["flows"])
        self.assertEqual(50, ti["packets"])
        self.assertEqual(["CEREAL2"], ti["providers"])
        self.assertEqual(["c2"], ti["categories"])
        self.assertEqual("HIGH_VALUE", ti["signal_class"])

    def test_first_seen_preserved_last_seen_advances(self):
        p = self.persistence()
        p.persist(cycle(rel(first_seen=iso(BASE), last_seen=iso(BASE + timedelta(minutes=1)))))
        p.persist(cycle(rel(first_seen=iso(BASE + timedelta(minutes=5)), last_seen=iso(BASE + timedelta(minutes=6)))))
        rows = self.event_rows()
        self.assertEqual(1, len(rows))
        self.assertEqual(iso(BASE), rows[0]["first_seen"])  # MIN preserved
        self.assertEqual(iso(BASE + timedelta(minutes=6)), rows[0]["last_seen"])  # MAX advances

    def test_relationship_expires_reports_closed_event_preserved(self):
        p = self.persistence()
        p.persist(cycle(rel(identity="10.0.0.10", ioc="203.0.113.10")))
        m = p.persist(cycle(rel(identity="10.0.0.11", ioc="203.0.113.11")))
        self.assertEqual(1, m["events_closed"])
        # Closed event is preserved in the table (history retained).
        self.assertEqual(2, self.event_count())

    def test_reappearance_reopens_same_event(self):
        p = self.persistence()
        p.persist(cycle(rel(identity="10.0.0.10", ioc="203.0.113.10")))
        p.persist(cycle(rel(identity="10.0.0.11", ioc="203.0.113.11")))
        p.persist(cycle(rel(identity="10.0.0.10", ioc="203.0.113.10")))
        self.assertEqual(2, self.event_count())  # A/X and B/Y, A/X reopened not duplicated
        rows = self.event_rows()
        keys = {row["event_key"] for row in rows}
        self.assertEqual(2, len(keys))

    def test_two_clients_same_ioc_two_events(self):
        p = self.persistence()
        p.persist(cycle(rel(identity="10.0.0.10"), rel(identity="10.0.0.11")))
        self.assertEqual(2, self.event_count())

    def test_one_client_two_iocs_two_events(self):
        p = self.persistence()
        p.persist(cycle(rel(ioc="203.0.113.10"), rel(ioc="203.0.113.11")))
        self.assertEqual(2, self.event_count())

    def test_10k_flows_same_relationship_one_event(self):
        p = self.persistence()
        p.persist(cycle(rel(flows=10000, packets=100000, bytes_count=1000000)))
        self.assertEqual(1, self.event_count())

    def test_multi_provider_union_preserved(self):
        p = self.persistence()
        p.persist(cycle(rel(providers=("CEREAL2", "FEODO", "GREYNOISE"),
                            classifications=("c2", "botnet", "malicious"))))
        rows = self.event_rows()
        from app.services.threat_intelligence import safe_json
        ti = safe_json(rows[0]["threat_intel_json"], {})
        self.assertEqual({"CEREAL2", "FEODO", "GREYNOISE"}, set(ti["providers"]))
        self.assertEqual({"c2", "botnet", "malicious"}, set(ti["classifications"]))

    def test_c2_tcp443_and_udp443_persist(self):
        p = self.persistence()
        p.persist(cycle(rel(protocols=(6,), dst_ports=(443,))))
        p.persist(cycle(rel(protocols=(17,), dst_ports=(443,))))
        self.assertEqual(1, self.event_count())  # same key (client+IOC)

    def test_cdn_ggc_context_does_not_suppress(self):
        p = self.persistence()
        p.persist(cycle(rel(categories=("cdn",), signal_class="LOWER_SIGNAL", semantic_tier=4)))
        self.assertEqual(1, self.event_count())

    def test_cgnat_resolved_identity_persisted(self):
        cgnat = CgnatResolution(status=RESOLVED, public_ip="100.64.0.5", private_ip="10.99.0.1",
                                subscriber_id="SUB-1", subscriber_name="Alice", confidence=0.9)
        p = self.persistence()
        p.persist(cycle(rel(identity="SUB-1", identity_kind=IDENTITY_CGNAT_SUBSCRIBER, cgnat=cgnat)))
        rows = self.event_rows()
        self.assertEqual("SUB-1", rows[0]["src_ip"])
        from app.services.threat_intelligence import safe_json
        nc = safe_json(rows[0]["network_context_json"], {})
        self.assertEqual("SUB-1", nc["subscriber_id"])
        self.assertEqual("10.99.0.1", nc["private_ip"])
        self.assertEqual("100.64.0.5", nc["public_ip"])

    def test_cgnat_unresolved_event_preserved(self):
        cgnat = CgnatResolution(status=UNRESOLVED, public_ip="100.64.0.5", error="no_mapping")
        p = self.persistence()
        p.persist(cycle(rel(identity="100.64.0.5", identity_kind="CGNAT_PUBLIC_UNRESOLVED", cgnat=cgnat)))
        self.assertEqual(1, self.event_count())
        self.assertEqual("100.64.0.5", self.event_rows()[0]["src_ip"])

    def test_cgnat_ambiguous_does_not_invent_subscriber(self):
        cgnat = CgnatResolution(status=AMBIGUOUS, public_ip="100.64.0.8")
        p = self.persistence()
        p.persist(cycle(rel(identity="100.64.0.8", identity_kind="CGNAT_PUBLIC_AMBIGUOUS", cgnat=cgnat)))
        rows = self.event_rows()
        from app.services.threat_intelligence import safe_json
        nc = safe_json(rows[0]["network_context_json"], {})
        self.assertEqual("", nc.get("subscriber_id", ""))
        self.assertEqual("", nc.get("private_ip", ""))

    def test_ipv6_works(self):
        p = self.persistence()
        p.persist(cycle(rel(identity="2001:db8:100::10", ioc="2001:db8:bad::1")))
        self.assertEqual(1, self.event_count())
        self.assertEqual("2001:db8:100::10", self.event_rows()[0]["src_ip"])

    def test_feature_disabled_zero_write(self):
        p = self.persistence(enabled=False)
        p.persist(cycle(rel()))
        self.assertEqual(0, self.event_count())

    def test_empty_cycle_zero_write(self):
        p = self.persistence()
        p.persist(cycle())
        self.assertEqual(0, self.event_count())

    def test_db_exception_survives(self):
        p = self.persistence()
        def broken_factory():
            raise RuntimeError("db unavailable")
        p.connection_factory = broken_factory
        m = p.persist(cycle(rel()))
        self.assertEqual(0, m["events_written"])
        self.assertGreaterEqual(m["cycle_errors"], 1)

    def test_restart_reconciliation_no_duplicate(self):
        p1 = self.persistence()
        p1.persist(cycle(rel()))
        # Simulate restart: a new instance over the same DB.
        p2 = self.persistence()
        p2.persist(cycle(rel()))
        self.assertEqual(1, self.event_count())


if __name__ == "__main__":
    unittest.main()
