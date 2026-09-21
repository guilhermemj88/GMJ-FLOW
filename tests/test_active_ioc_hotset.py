"""Tests for the P1 Active IOC Hot Set (backend/app/services/active_ioc_hotset.py).

Covers the 20 mandatory cases from the P1 runbook plus network/prefix lookup,
IPv4-mapped normalization and metrics. Uses a temporary SQLite database with
the real threat intelligence schema (control plane semantics preserved).
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import app.services.active_ioc_hotset as hotset_module  # noqa: E402
from app.services.active_ioc_hotset import (  # noqa: E402
    ActiveIocHotSet,
    IocEntry,
    build_snapshot,
    normalize_ip,
)
from app.services.threat_intelligence import ensure_threat_intel_schema


def _factory(path: str):
    def factory() -> sqlite3.Connection:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn
    return factory


def _insert_indicator(
    conn: sqlite3.Connection,
    provider: str,
    indicator_type: str,
    ip: str = "",
    network: str = "",
    classification: str = "c2",
    botnet_family: str = "",
    active: int = 1,
    tags: str = "[]",
) -> None:
    conn.execute(
        """
        INSERT INTO threat_intel_indicators
            (provider, indicator_type, ip, network, classification,
             botnet_family, tags_json, active, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, '2026-09-16T00:00:00Z')
        """,
        (provider, indicator_type, ip, network, classification, botnet_family, tags, active),
    )
    conn.commit()


def _set_provider_enabled(conn: sqlite3.Connection, provider: str, enabled: int) -> None:
    conn.execute(
        "UPDATE threat_intel_providers SET enabled = ? WHERE provider = ?",
        (enabled, provider),
    )
    conn.commit()


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        threading.Event().wait(0.01)
    return bool(predicate())


class _ControlledBuilder:
    """Deterministic slow builder used to force overlapping refresh requests."""

    def __init__(self, delegate=build_snapshot, error: Exception | None = None) -> None:
        self._delegate = delegate
        self._error = error
        self._lock = threading.Lock()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0
        self.active = 0
        self.max_active = 0

    def __call__(self, conn, generation):
        with self._lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.entered.set()
        try:
            if not self.release.wait(5.0):
                raise RuntimeError("controlled builder release timed out")
            if self._error is not None:
                raise self._error
            return self._delegate(conn, generation)
        finally:
            with self._lock:
                self.active -= 1


class HotSetTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "ti.db")
        conn = sqlite3.connect(self.db_path)
        ensure_threat_intel_schema(conn)
        conn.commit()
        conn.close()
        self.hotset = ActiveIocHotSet(
            _factory(self.db_path),
            refresh_seconds=60,
            enabled=True,
            stale_after_seconds=600.0,
        )

    def tearDown(self) -> None:
        self.hotset.stop()
        self._tmp.cleanup()

    def _seed_single(self, provider="CEREAL2", indicator_type="C2", ip="1.2.3.4",
                     classification="c2", botnet_family="", active=1, tags="[]"):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, provider, 1)
        _insert_indicator(conn, provider, indicator_type, ip=ip,
                          classification=classification,
                          botnet_family=botnet_family, active=active, tags=tags)
        conn.close()


class HotSetLookupTests(HotSetTestCase):
    # 1. empty snapshot
    def test_empty_snapshot_default(self):
        self.assertEqual(0, self.hotset.generation)
        self.assertIsNone(self.hotset.lookup("1.2.3.4"))
        self.assertIsNone(self.hotset.lookup("2001:db8::1"))

    # 2/3. exact IPv4 hit/miss
    def test_exact_ipv4_hit(self):
        self._seed_single(ip="203.0.113.7")
        self.assertTrue(self.hotset.refresh())
        entry = self.hotset.lookup("203.0.113.7")
        self.assertIsNotNone(entry)
        self.assertEqual("203.0.113.7", entry.ip)
        self.assertIn("CEREAL2", entry.providers)
        self.assertEqual(1, entry.semantic_tier)

    def test_exact_ipv4_miss(self):
        self._seed_single(ip="203.0.113.7")
        self.assertTrue(self.hotset.refresh())
        self.assertIsNone(self.hotset.lookup("203.0.113.8"))
        self.assertIsNone(self.hotset.lookup("8.8.8.8"))

    # 4/5. exact IPv6 hit/miss
    def test_exact_ipv6_hit(self):
        self._seed_single(ip="2001:db8::42", classification="active_botnet")
        self.assertTrue(self.hotset.refresh())
        entry = self.hotset.lookup("2001:db8::42")
        self.assertIsNotNone(entry)
        self.assertEqual(2, entry.semantic_tier)
        self.assertIn("botnet", entry.categories)

    def test_exact_ipv6_miss(self):
        self._seed_single(ip="2001:db8::42")
        self.assertTrue(self.hotset.refresh())
        self.assertIsNone(self.hotset.lookup("2001:db8::43"))

    # 6. multiple providers, same IOC
    def test_multiple_providers_same_ioc(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _set_provider_enabled(conn, "FEODO", 1)
        _insert_indicator(conn, "CEREAL2", "C2", ip="1.2.3.4", classification="c2", botnet_family="Mirai")
        _insert_indicator(conn, "FEODO", "BOTNET", ip="1.2.3.4", classification="active_botnet", botnet_family="Mirai")
        conn.close()
        self.assertTrue(self.hotset.refresh())
        entry = self.hotset.lookup("1.2.3.4")
        self.assertIsNotNone(entry)
        self.assertEqual(("CEREAL2", "FEODO"), entry.providers)
        self.assertEqual(2, len(entry.matches))

    # 7. semantic categories preserved
    def test_semantic_categories_preserved(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _set_provider_enabled(conn, "BLOCKLIST_DE", 1)
        _insert_indicator(conn, "CEREAL2", "C2", ip="1.2.3.4", classification="c2")
        _insert_indicator(conn, "BLOCKLIST_DE", "ABUSE", ip="1.2.3.4", classification="scanner")
        conn.close()
        self.assertTrue(self.hotset.refresh())
        entry = self.hotset.lookup("1.2.3.4")
        self.assertIn("c2", entry.categories)
        self.assertIn("scanner", entry.categories)
        self.assertEqual(1, entry.semantic_tier)  # best tier wins

    # 8. botnet family preserved
    def test_botnet_family_preserved(self):
        self._seed_single(ip="5.6.7.8", classification="botnet_cc", botnet_family="Mirai")
        self.assertTrue(self.hotset.refresh())
        entry = self.hotset.lookup("5.6.7.8")
        self.assertEqual("Mirai", entry.botnet_family)

    # 9. inactive IOC excluded
    def test_inactive_ioc_excluded(self):
        self._seed_single(ip="9.9.9.9", active=0)
        self.assertTrue(self.hotset.refresh())
        self.assertIsNone(self.hotset.lookup("9.9.9.9"))

    # 10. malformed IOC skipped safely
    def test_malformed_ioc_skipped(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _insert_indicator(conn, "CEREAL2", "C2", ip="not-an-ip")
        _insert_indicator(conn, "CEREAL2", "C2", network="999.1.2.0/24")
        _insert_indicator(conn, "CEREAL2", "C2", ip="", network="")
        conn.close()
        self.assertTrue(self.hotset.refresh())
        self.assertEqual(0, self.hotset.status()["indicator_count_exact"])
        self.assertEqual(0, self.hotset.status()["indicator_count_network"])

    # 11. successful refresh
    def test_successful_refresh(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        status = self.hotset.status()
        self.assertEqual(1, status["snapshot_generation"])
        self.assertEqual(1, status["indicator_count_exact"])
        self.assertEqual("", status["last_error"])
        self.assertTrue(status["last_refresh_success"])
        self.assertFalse(status["stale"])
        self.assertTrue(self.hotset.refresh())
        self.assertEqual(2, self.hotset.status()["snapshot_generation"])

    # 12. failed refresh keeps last known good
    def test_failed_refresh_keeps_last_good(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        broken = ActiveIocHotSet(
            lambda: (_ for _ in ()).throw(sqlite3.OperationalError("database is locked")),
            enabled=True, stale_after_seconds=600.0,
        )
        self.assertFalse(broken.refresh())
        self.assertEqual(0, broken.generation)
        self.assertIsNone(broken.lookup("1.2.3.4"))
        status = broken.status()
        self.assertEqual(1, status["refresh_failures"])
        self.assertIn("OperationalError", status["last_error"])

    # 20. SQLite unavailable during refresh keeps last known good snapshot
    def test_sqlite_unavailable_during_refresh(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        entry_before = self.hotset.lookup("1.2.3.4")
        self.assertIsNotNone(entry_before)
        broken_factory = lambda: (_ for _ in ()).throw(sqlite3.OperationalError("unable to open database file"))
        self.hotset._connection_factory = broken_factory
        self.assertFalse(self.hotset.refresh())
        entry_after = self.hotset.lookup("1.2.3.4")
        self.assertIsNotNone(entry_after)
        self.assertEqual(entry_before.semantic_tier, entry_after.semantic_tier)
        self.assertEqual(1, self.hotset.status()["refresh_failures"])

    # 13. atomic swap: readers only ever see complete snapshots
    def test_atomic_swap(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        conn.close()
        errors: list[Exception] = []
        stop = threading.Event()
        results: list[set] = []

        def reader():
            seen = set()
            try:
                for _ in range(1200):
                    for i in range(200):
                        ip = f"10.{(i // 256) % 256}.{(i // 1) % 256}.{i % 256}"
                        entry = self.hotset.lookup(ip)
                        if entry is not None:
                            seen.add(entry.ip)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            results.append(seen)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        try:
            for generation in range(1, 6):
                conn = sqlite3.connect(self.db_path)
                conn.execute("DELETE FROM threat_intel_indicators")
                for i in range(0, 500, 2 if generation % 2 else 1):
                    _insert_indicator(conn, "CEREAL2", "C2", ip=f"10.{(i // 256) % 256}.{(i // 1) % 256}.{i % 256}")
                conn.close()
                self.assertTrue(self.hotset.refresh())
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=10)
        self.assertEqual([], errors)
        self.assertEqual(5, self.hotset.generation)

    # 14. concurrent reads during refresh
    def test_concurrent_reads_during_refresh(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        errors: list[Exception] = []
        stop = threading.Event()

        def reader():
            try:
                for _ in range(4000):
                    self.assertIsNotNone(self.hotset.lookup("1.2.3.4"))
                    self.assertIsNone(self.hotset.lookup("8.8.4.4"))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        try:
            for _ in range(15):
                self.assertTrue(self.hotset.refresh())
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=10)
        self.assertEqual([], errors)
        status = self.hotset.status()
        self.assertGreaterEqual(status["lookup_hits"] + 4, status["lookup_misses"])

    # 15. repeated refresh no leak / no growth
    def test_repeated_refresh_no_growth(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _set_provider_enabled(conn, "FEODO", 1)
        _insert_indicator(conn, "CEREAL2", "C2", ip="1.2.3.4", classification="c2")
        _insert_indicator(conn, "FEODO", "BOTNET", ip="1.2.3.4", classification="active_botnet")
        conn.close()
        for generation in range(1, 26):
            self.assertTrue(self.hotset.refresh())
            self.assertEqual(generation, self.hotset.generation)
        entry = self.hotset.lookup("1.2.3.4")
        self.assertIsNotNone(entry)
        self.assertEqual(2, len(entry.matches))  # no duplicated providers
        status = self.hotset.status()
        self.assertEqual(1, status["indicator_count_exact"])

    # 16. stale state
    def test_stale_state(self):
        hotset = ActiveIocHotSet(_factory(self.db_path), enabled=True, stale_after_seconds=0.2)
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(hotset.refresh())
        self.assertFalse(hotset.status()["stale"])
        time.sleep(0.35)
        self.assertTrue(hotset.status()["stale"])
        self.assertEqual("", hotset.status()["last_error"])

    def test_disabled_never_stale(self):
        hotset = ActiveIocHotSet(_factory(self.db_path), enabled=False, stale_after_seconds=0.2)
        self.assertFalse(hotset.status()["stale"])
        self.assertFalse(hotset.start() or hotset._thread)

    # 17. duplicate normalization (textual + IPv4-mapped)
    def test_duplicate_normalization(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _set_provider_enabled(conn, "FEODO", 1)
        _insert_indicator(conn, "CEREAL2", "C2", ip="1.2.3.4")
        _insert_indicator(conn, "FEODO", "BOTNET", ip="::ffff:1.2.3.4", classification="active_botnet")
        conn.close()
        self.assertTrue(self.hotset.refresh())
        self.assertEqual(1, self.hotset.status()["indicator_count_exact"])
        entry = self.hotset.lookup("1.2.3.4")
        self.assertEqual(2, len(entry.matches))
        entry6 = self.hotset.lookup("::ffff:1.2.3.4")
        self.assertEqual(entry, entry6)
        self.assertEqual(normalize_ip("1.2.3.4"), normalize_ip("::ffff:1.2.3.4"))

    # 18. provider disappearing on next valid snapshot
    def test_provider_disappearing_next_snapshot(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _set_provider_enabled(conn, "FEODO", 1)
        _insert_indicator(conn, "CEREAL2", "C2", ip="1.2.3.4")
        _insert_indicator(conn, "FEODO", "BOTNET", ip="5.6.7.8", classification="active_botnet")
        conn.close()
        self.assertTrue(self.hotset.refresh())
        self.assertIsNotNone(self.hotset.lookup("5.6.7.8"))
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "FEODO", 0)
        conn.close()
        self.assertTrue(self.hotset.refresh())
        self.assertIsNone(self.hotset.lookup("5.6.7.8"))
        self.assertIsNotNone(self.hotset.lookup("1.2.3.4"))

    # 19. empty VALID dataset semantics
    def test_empty_valid_dataset(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        conn.close()
        self.assertTrue(self.hotset.refresh())
        status = self.hotset.status()
        self.assertEqual(1, status["snapshot_generation"])
        self.assertEqual(0, status["indicator_count_exact"])
        self.assertEqual("", status["last_error"])
        self.assertTrue(status["last_refresh_success"])


class RefreshSerializationTests(HotSetTestCase):
    def _run_concurrent_refreshes(self, count, builder):
        results = [None] * count
        threads = []

        def caller(index, barrier=None):
            if barrier is not None:
                barrier.wait()
            results[index] = self.hotset.refresh()

        with mock.patch.object(hotset_module, "build_snapshot", builder):
            owner = threading.Thread(target=caller, args=(0,))
            threads.append(owner)
            owner.start()
            self.assertTrue(builder.entered.wait(2.0))

            followers_ready = threading.Barrier(count)
            for index in range(1, count):
                thread = threading.Thread(
                    target=caller, args=(index, followers_ready)
                )
                threads.append(thread)
                thread.start()
            followers_ready.wait()

            try:
                self.assertTrue(
                    _wait_for(
                        lambda: self.hotset.status()["refresh_coalesced_total"]
                        == count - 1
                    )
                )
            finally:
                builder.release.set()
                for thread in threads:
                    thread.join(5.0)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        return results

    # P1.2-1: two simultaneous requests share one actual build.
    def test_two_simultaneous_refresh_requests_single_flight(self):
        builder = _ControlledBuilder()
        results = self._run_concurrent_refreshes(2, builder)
        self.assertEqual([True, True], results)
        self.assertEqual(1, builder.calls)
        self.assertEqual(1, builder.max_active)
        self.assertEqual(1, self.hotset.generation)

    # P1.2-2: a burst of ten requests does not create ten builds.
    def test_ten_simultaneous_refresh_requests_single_flight(self):
        builder = _ControlledBuilder()
        results = self._run_concurrent_refreshes(10, builder)
        self.assertEqual([True] * 10, results)
        self.assertEqual(1, builder.calls)
        self.assertEqual(1, builder.max_active)
        self.assertEqual(9, self.hotset.status()["refresh_coalesced_total"])

    # P1.2-3: readers keep using snapshot A while B is under construction.
    def test_lookups_continue_during_refresh(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        builder = _ControlledBuilder()
        refresh_result = []
        lookup_result = []
        lookup_done = threading.Event()

        def refresh():
            refresh_result.append(self.hotset.refresh())

        def lookup():
            lookup_result.append(self.hotset.lookup("1.2.3.4"))
            lookup_done.set()

        with mock.patch.object(hotset_module, "build_snapshot", builder):
            refresh_thread = threading.Thread(target=refresh)
            refresh_thread.start()
            self.assertTrue(builder.entered.wait(2.0))
            lookup_thread = threading.Thread(target=lookup)
            lookup_thread.start()
            try:
                self.assertTrue(lookup_done.wait(1.0))
                self.assertIsNotNone(lookup_result[0])
            finally:
                builder.release.set()
                refresh_thread.join(5.0)
                lookup_thread.join(5.0)

        self.assertEqual([True], refresh_result)
        self.assertFalse(refresh_thread.is_alive())

    # P1.2-4: B appears only after the complete immutable snapshot is built.
    def test_successful_refresh_publishes_b_atomically(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM threat_intel_indicators")
        _insert_indicator(conn, "CEREAL2", "C2", ip="5.6.7.8")
        conn.close()
        builder = _ControlledBuilder()
        results = []

        with mock.patch.object(hotset_module, "build_snapshot", builder):
            thread = threading.Thread(
                target=lambda: results.append(self.hotset.refresh())
            )
            thread.start()
            self.assertTrue(builder.entered.wait(2.0))
            self.assertIsNotNone(self.hotset.lookup("1.2.3.4"))
            self.assertIsNone(self.hotset.lookup("5.6.7.8"))
            builder.release.set()
            thread.join(5.0)

        self.assertEqual([True], results)
        self.assertIsNone(self.hotset.lookup("1.2.3.4"))
        self.assertIsNotNone(self.hotset.lookup("5.6.7.8"))
        self.assertEqual(2, self.hotset.generation)

    # P1.2-5: a failed leader and its follower preserve snapshot A.
    def test_failed_refresh_preserves_a(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        builder = _ControlledBuilder(error=RuntimeError("controlled failure"))
        results = self._run_concurrent_refreshes(2, builder)
        self.assertEqual([False, False], results)
        self.assertEqual(1, builder.calls)
        self.assertEqual(1, self.hotset.generation)
        self.assertIsNotNone(self.hotset.lookup("1.2.3.4"))

    # P1.2-6: exception cleanup always clears the in-progress state.
    def test_refresh_state_released_after_exception(self):
        with mock.patch.object(
            hotset_module, "build_snapshot", side_effect=RuntimeError("boom")
        ):
            self.assertFalse(self.hotset.refresh())
        status = self.hotset.status()
        self.assertFalse(status["refresh_in_progress"])
        self.assertEqual(1, status["refresh_failures"])
        self.assertIn("RuntimeError", status["last_error"])

    # P1.2-7: a normal refresh can lead after a failed flight.
    def test_second_refresh_works_after_first_failure(self):
        with mock.patch.object(
            hotset_module, "build_snapshot", side_effect=RuntimeError("boom")
        ):
            self.assertFalse(self.hotset.refresh())
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        self.assertEqual(1, self.hotset.generation)
        self.assertIsNotNone(self.hotset.lookup("1.2.3.4"))
        self.assertFalse(self.hotset.status()["refresh_in_progress"])

    # P1.2-8: successful zero-row reads still publish a valid empty snapshot.
    def test_valid_empty_refresh_remains_valid(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM threat_intel_indicators")
        conn.commit()
        conn.close()
        self.assertTrue(self.hotset.refresh())
        status = self.hotset.status()
        self.assertEqual(2, status["snapshot_generation"])
        self.assertEqual(0, status["indicator_count_exact"])
        self.assertEqual("", status["last_error"])

    # P1.2-9: all followers are released even when the leader fails.
    def test_no_deadlock_when_single_flight_fails(self):
        builder = _ControlledBuilder(error=RuntimeError("controlled failure"))
        results = self._run_concurrent_refreshes(10, builder)
        self.assertEqual([False] * 10, results)
        self.assertEqual(1, builder.calls)
        self.assertFalse(self.hotset.status()["refresh_in_progress"])

    # P1.2-10: lookup does not acquire the refresh/state lock.
    def test_lookup_is_not_serialized_by_refresh_lock(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        result = []
        done = threading.Event()

        def lookup():
            result.append(self.hotset.lookup("1.2.3.4"))
            done.set()

        self.hotset._state_lock.acquire()
        try:
            thread = threading.Thread(target=lookup)
            thread.start()
            self.assertTrue(done.wait(1.0))
        finally:
            self.hotset._state_lock.release()
        thread.join(2.0)
        self.assertFalse(thread.is_alive())
        self.assertIsNotNone(result[0])


class NetworkPrefixLookupTests(HotSetTestCase):
    def test_ipv4_network_hit(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _insert_indicator(conn, "CEREAL2", "C2", network="10.0.0.0/8", classification="c2")
        conn.close()
        self.assertTrue(self.hotset.refresh())
        entry = self.hotset.lookup("10.1.2.3")
        self.assertIsNotNone(entry)
        self.assertEqual("10.0.0.0/8", entry.ip)
        self.assertEqual(1, self.hotset.status()["indicator_count_network"])
        self.assertIsNone(self.hotset.lookup("11.1.2.3"))

    def test_ipv6_network_hit(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _insert_indicator(conn, "CEREAL2", "C2", network="2001:db8::/32", classification="c2")
        conn.close()
        self.assertTrue(self.hotset.refresh())
        self.assertIsNotNone(self.hotset.lookup("2001:db8:1:2::3"))
        self.assertIsNone(self.hotset.lookup("2001:db9::1"))

    def test_most_specific_prefix_wins(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _insert_indicator(conn, "CEREAL2", "C2", network="10.0.0.0/8", classification="c2")
        _insert_indicator(conn, "CEREAL2", "BOTNET", network="10.1.0.0/16", classification="active_botnet", botnet_family="Mirai")
        conn.close()
        self.assertTrue(self.hotset.refresh())
        entry = self.hotset.lookup("10.1.5.5")
        self.assertEqual("10.1.0.0/16", entry.ip)
        self.assertIn("botnet", entry.categories)
        entry_broad = self.hotset.lookup("10.99.5.5")
        self.assertEqual("10.0.0.0/8", entry_broad.ip)

    def test_exact_beats_prefix(self):
        conn = sqlite3.connect(self.db_path)
        _set_provider_enabled(conn, "CEREAL2", 1)
        _insert_indicator(conn, "CEREAL2", "C2", network="10.0.0.0/8", classification="c2")
        _insert_indicator(conn, "CEREAL2", "C2", ip="10.5.6.7", classification="malware_distribution")
        conn.close()
        self.assertTrue(self.hotset.refresh())
        entry = self.hotset.lookup("10.5.6.7")
        self.assertEqual("10.5.6.7", entry.ip)
        self.assertIn("malware", entry.categories)


class MetricsAndStatusTests(HotSetTestCase):
    def test_lookup_metrics(self):
        self._seed_single(ip="1.2.3.4")
        self.assertTrue(self.hotset.refresh())
        for _ in range(3):
            self.hotset.lookup("1.2.3.4")
        self.hotset.lookup("8.8.8.8")
        self.hotset.lookup("not-an-ip")
        status = self.hotset.status()
        self.assertEqual(5, status["lookup_count"])
        self.assertEqual(3, status["lookup_hits"])
        self.assertEqual(2, status["lookup_misses"])
        self.assertGreaterEqual(status["lookup_latency_ns_max"], 0)


if __name__ == "__main__":
    unittest.main()