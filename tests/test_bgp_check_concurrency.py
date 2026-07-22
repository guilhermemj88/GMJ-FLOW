from __future__ import annotations

import ast
import os
import threading
import time
import types
import unittest
import uuid
from concurrent.futures import CancelledError, Future, ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = ROOT / "backend" / "app" / "main.py"
FRONTEND_PATH = ROOT / "frontend" / "index.html"
MAIN_SOURCE = MAIN_PATH.read_text(encoding="utf-8")
FRONTEND_SOURCE = FRONTEND_PATH.read_text(encoding="utf-8")


def source_between(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    return source[start_index:source.index(end, start_index)]


def load_main_definitions(*names: str) -> dict[str, Any]:
    tree = ast.parse(MAIN_SOURCE)
    selected = [
        node
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names
    ]
    for node in selected:
        node.decorator_list = []
    module = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__",
                names=[ast.alias(name="annotations", asname=None)],
                level=0,
            ),
            *selected,
        ],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)
    namespace: dict[str, Any] = {
        "Any": Any,
        "Future": Future,
        "CancelledError": CancelledError,
        "ThreadPoolExecutor": ThreadPoolExecutor,
        "FutureTimeoutError": FutureTimeoutError,
        "os": os,
        "threading": threading,
        "time": time,
        "types": types,
        "uuid": uuid,
        "datetime": datetime,
        "timedelta": timedelta,
        "timezone": timezone,
        "clean_text": lambda value: str(value or "").strip(),
        "logger": types.SimpleNamespace(warning=lambda *_args, **_kwargs: None),
        "BGP_STATUS_CHECK_LOCKS_GUARD": threading.Lock(),
        "BGP_STATUS_CHECK_LOCKS": {},
        "BGP_STATUS_CHECK_EXECUTOR_GUARD": threading.Lock(),
        "BGP_STATUS_CHECK_EXECUTOR": None,
        "BGP_STATUS_CHECK_EXECUTOR_WORKERS": 0,
        "BGP_STATUS_CHECK_EXPIRED_TOTAL": 0,
    }
    exec(compile(module, str(MAIN_PATH), "exec"), namespace)
    return namespace


COORDINATOR_DEFINITIONS = (
    "BgpStatusCheckInProgress",
    "BgpStatusCheckTimedOut",
    "bgp_status_check_timeout_seconds",
    "cleanup_bgp_status_check_locks",
    "acquire_bgp_status_check_lock",
    "release_bgp_status_check_lock",
    "bgp_status_check_future_done",
    "start_bgp_status_check_executor",
    "shutdown_bgp_status_check_executor",
    "submit_bgp_connector_status_check",
    "expire_bgp_status_check",
    "await_bgp_connector_status_check",
    "bgp_active_status_check_count",
    "bgp_status_check_metadata",
    "bgp_status_check_workers",
)


class BgpGenerationCoordinatorTest(unittest.TestCase):
    def coordinator(self, workers: int = 2) -> dict[str, Any]:
        namespace = load_main_definitions(*COORDINATOR_DEFINITIONS)
        namespace["bgp_status_check_workers"] = lambda connector_count=None: workers
        return namespace

    def shutdown(self, namespace):
        namespace["shutdown_bgp_status_check_executor"](wait=True)

    def test_different_connectors_acquire_independent_tokens(self):
        namespace = self.coordinator()
        first = namespace["acquire_bgp_status_check_lock"](1, "GM")
        fourth = namespace["acquire_bgp_status_check_lock"](4, "FIBINET")
        try:
            self.assertNotEqual(first["token"], fourth["token"])
            self.assertEqual(namespace["bgp_active_status_check_count"](), 2)
        finally:
            namespace["release_bgp_status_check_lock"](1, first["token"])
            namespace["release_bgp_status_check_lock"](4, fourth["token"])

    def test_old_generation_cannot_release_new_generation(self):
        namespace = self.coordinator()
        acquire = namespace["acquire_bgp_status_check_lock"]
        release = namespace["release_bgp_status_check_lock"]
        generation_a = acquire(4, "generation-a")
        with namespace["BGP_STATUS_CHECK_LOCKS_GUARD"]:
            namespace["BGP_STATUS_CHECK_LOCKS"][4]["state"] = "timed_out"
        self.assertTrue(release(4, generation_a["token"]))
        generation_b = acquire(4, "generation-b")
        try:
            self.assertNotEqual(generation_a["token"], generation_b["token"])
            self.assertFalse(release(4, generation_a["token"]))
            completed_a = Future()
            completed_a.set_result({"bgp_state": "down"})
            namespace["bgp_status_check_future_done"](4, generation_a["token"], completed_a)
            metadata = namespace["bgp_status_check_metadata"](4)
            self.assertEqual(metadata["token"], generation_b["token"])
            self.assertEqual(metadata["owner"], "generation-b")
            self.assertEqual(namespace["bgp_active_status_check_count"](), 1)
        finally:
            self.assertTrue(release(4, generation_b["token"]))

    def test_late_task_does_not_accumulate_on_successive_cycles(self):
        namespace = self.coordinator(workers=1)
        namespace["bgp_status_check_timeout_seconds"] = lambda: 0.01
        started = threading.Event()
        finish = threading.Event()

        def slow_status(_connector):
            started.set()
            finish.wait(1)
            return {"bgp_state": "established"}

        namespace["bgp_connector_status"] = slow_status
        lease = namespace["acquire_bgp_status_check_lock"](1, "cycle-a")
        future = namespace["submit_bgp_connector_status_check"]({"id": 1}, lease)
        self.assertTrue(started.wait(1))
        with self.assertRaises(namespace["BgpStatusCheckTimedOut"]):
            namespace["await_bgp_connector_status_check"]({"id": 1}, lease, future)
        with self.assertRaises(namespace["BgpStatusCheckInProgress"]):
            namespace["acquire_bgp_status_check_lock"](1, "cycle-b-too-early")
        self.assertEqual(namespace["bgp_active_status_check_count"](), 1)

        finish.set()
        future.result(1)
        deadline = time.monotonic() + 1
        while namespace["bgp_status_check_metadata"](1) and time.monotonic() < deadline:
            time.sleep(0.01)
        generation_b = namespace["acquire_bgp_status_check_lock"](1, "cycle-b")
        namespace["release_bgp_status_check_lock"](1, generation_b["token"])
        self.shutdown(namespace)

    def test_shared_executor_respects_configured_worker_limit(self):
        namespace = load_main_definitions(*COORDINATOR_DEFINITIONS)
        with patch.dict(os.environ, {"GMJFLOW_BGP_STATUS_CHECK_WORKERS": "3"}):
            executor = namespace["start_bgp_status_check_executor"]()
            self.assertEqual(executor._max_workers, 3)
            self.assertIs(executor, namespace["start_bgp_status_check_executor"]())
            self.assertEqual(namespace["BGP_STATUS_CHECK_EXECUTOR_WORKERS"], 3)
        self.shutdown(namespace)


class BgpTimeoutIsolationTest(unittest.TestCase):
    def test_late_execution_has_no_persistent_or_operational_effect(self):
        namespace = load_main_definitions(
            *COORDINATOR_DEFINITIONS,
            "finish_bgp_connector_status_check",
        )
        namespace["bgp_status_check_workers"] = lambda connector_count=None: 1
        namespace["bgp_status_check_timeout_seconds"] = lambda: 0.01
        started = threading.Event()
        finish = threading.Event()
        persisted = []
        marked = []
        previous_snapshot = {
            "bgp_state": "established",
            "flowspec_state": "established",
            "pipe_state": "ok",
            "last_checked_at": "2026-07-22T11:00:00+00:00",
        }

        def slow_down_status(_connector):
            started.set()
            finish.wait(1)
            return {
                "bgp_state": "down",
                "flowspec_state": "down",
                "pipe_state": "down",
            }

        namespace.update(
            {
                "bgp_connector_status": slow_down_status,
                "persist_bgp_connector_status_snapshot": lambda *_args: persisted.append(True),
                "mark_connector_advertisements_peer_down": lambda *_args: marked.append(True),
                "sqlite_connection": lambda: (_ for _ in ()).throw(AssertionError("database must not open")),
            }
        )
        connector = {"id": 1, "name": "GM"}
        lease = namespace["acquire_bgp_status_check_lock"](1, "late-test")
        future = namespace["submit_bgp_connector_status_check"](connector, lease)
        execution = {"connector": connector, "lease": lease, "future": future}
        self.assertTrue(started.wait(1))
        with self.assertRaises(namespace["BgpStatusCheckTimedOut"]):
            namespace["finish_bgp_connector_status_check"](execution)
        finish.set()
        future.result(1)
        self.assertEqual(persisted, [])
        self.assertEqual(marked, [])
        self.assertEqual(
            previous_snapshot,
            {
                "bgp_state": "established",
                "flowspec_state": "established",
                "pipe_state": "ok",
                "last_checked_at": "2026-07-22T11:00:00+00:00",
            },
        )
        namespace["shutdown_bgp_status_check_executor"](wait=True)

    def test_timeout_does_not_persist_snapshot_or_mark_peer_down(self):
        namespace = load_main_definitions("BgpStatusCheckTimedOut", "finish_bgp_connector_status_check")
        persisted = []
        marked = []
        released = []
        timeout = namespace["BgpStatusCheckTimedOut"](1, "2026-07-22T12:00:00+00:00")
        namespace.update(
            {
                "await_bgp_connector_status_check": lambda *_args: (_ for _ in ()).throw(timeout),
                "persist_bgp_connector_status_snapshot": lambda *_args: persisted.append(True),
                "mark_connector_advertisements_peer_down": lambda *_args: marked.append(True),
                "sqlite_connection": lambda: (_ for _ in ()).throw(AssertionError("database must not open")),
                "release_bgp_status_check_lock": lambda connector_id, token: released.append((connector_id, token)),
                "clean_text": lambda value: str(value or "").strip(),
            }
        )
        execution = {
            "connector": {"id": 1, "name": "GM"},
            "lease": {"token": "generation-a"},
            "future": Future(),
        }
        with self.assertRaises(namespace["BgpStatusCheckTimedOut"]):
            namespace["finish_bgp_connector_status_check"](execution)
        self.assertEqual(persisted, [])
        self.assertEqual(marked, [])
        self.assertEqual(released, [(1, "generation-a")])

    def test_readiness_timeout_has_no_snapshot_or_operational_callback(self):
        namespace = load_main_definitions(
            "BgpStatusCheckTimedOut",
            "check_bgp_connector_readiness",
        )
        persisted = []
        timeout = namespace["BgpStatusCheckTimedOut"](4, "2026-07-22T12:00:00+00:00")
        namespace.update(
            {
                "acquire_bgp_status_check_lock": lambda *_args: {"token": "generation-a"},
                "submit_bgp_connector_status_check": lambda *_args: Future(),
                "await_bgp_connector_status_check": lambda *_args: (_ for _ in ()).throw(timeout),
                "persist_bgp_connector_status_snapshot": lambda *_args: persisted.append(True),
                "release_bgp_status_check_lock": lambda *_args: True,
                "clean_text": lambda value: str(value or "").strip(),
            }
        )
        with self.assertRaises(namespace["BgpStatusCheckTimedOut"]):
            namespace["check_bgp_connector_readiness"](object(), {"id": 4, "name": "FIBINET"})
        self.assertEqual(persisted, [])

    def test_late_callback_only_releases_matching_token(self):
        source = source_between(
            MAIN_SOURCE,
            "def bgp_status_check_future_done(",
            "def start_bgp_status_check_executor(",
        )
        self.assertIn('entry.get("token")', source)
        self.assertIn("release_bgp_status_check_lock(connector_id, token)", source)
        for forbidden in (
            "persist_bgp_connector_status_snapshot",
            "mark_connector_advertisements_peer_down",
            "exabgp_write_pipe",
            "transition_bgp_announcement",
        ):
            self.assertNotIn(forbidden, source)

    def test_readiness_happens_before_any_announcement_transition(self):
        source = source_between(MAIN_SOURCE, "def attempt_bgp_announcement(", "def bgp_expiration_loop(")
        readiness = source.index("check_bgp_connector_readiness(conn, connector)")
        self.assertLess(readiness, source.index("transition_bgp_announcement("))
        self.assertLess(readiness, source.index("persist_bgp_send_intent("))
        self.assertLess(readiness, source.index("exabgp_write_pipe(connector, command)"))


class BgpExecutorAndHealthStaticTest(unittest.TestCase):
    def test_application_has_only_one_shared_bgp_executor(self):
        self.assertEqual(MAIN_SOURCE.count("ThreadPoolExecutor("), 1)
        executor_source = source_between(
            MAIN_SOURCE,
            "def start_bgp_status_check_executor(",
            "def shutdown_bgp_status_check_executor(",
        )
        self.assertIn("BGP_STATUS_CHECK_EXECUTOR is None", executor_source)
        self.assertIn("max_workers=workers", executor_source)
        auto_source = source_between(
            MAIN_SOURCE,
            "def run_bgp_connector_status_checks_once(",
            "def bgp_status_check_loop(",
        )
        self.assertNotIn("ThreadPoolExecutor", auto_source)
        self.assertNotIn("threading.Thread", auto_source)
        self.assertIn("begin_bgp_connector_status_check", auto_source)
        self.assertIn('stats["expired"]', auto_source)
        self.assertIn('stats["active"]', auto_source)

    def test_shared_executor_lifecycle_is_bound_to_application(self):
        startup = source_between(MAIN_SOURCE, 'def startup()', '@app.on_event("shutdown")')
        shutdown = source_between(MAIN_SOURCE, 'def shutdown()', "def peak_hunter_runner_enabled")
        self.assertIn("start_bgp_status_check_executor()", startup)
        self.assertIn("stop_bgp_status_check_thread()", shutdown)
        self.assertIn("shutdown_bgp_status_check_executor()", shutdown)

    def test_health_check_never_writes_exabgp_fifo(self):
        pipe_source = source_between(
            MAIN_SOURCE,
            "def exabgp_peer_from_pipe(",
            "def exabgp_peer_from_log_heuristic(",
        )
        self.assertIn('"state": "not_verified"', pipe_source)
        for forbidden in ("exabgp_write_pipe", "os.open", "os.write", "show neighbor summary"):
            self.assertNotIn(forbidden, pipe_source)
        self.assertNotIn("show neighbor summary", MAIN_SOURCE)
        namespace = load_main_definitions("exabgp_peer_from_pipe")
        writes = []
        namespace["exabgp_write_pipe"] = lambda *_args: writes.append(True)
        result = namespace["exabgp_peer_from_pipe"]({"peer_ip": "192.0.2.1"})
        self.assertEqual(result["state"], "not_verified")
        self.assertEqual(writes, [])
        status_source = source_between(
            MAIN_SOURCE,
            "def bgp_connector_status(",
            "def normalize_bgp_connector_status_snapshot(",
        )
        self.assertNotIn("exabgp_write_pipe", status_source)

    def test_get_status_and_manual_timeout_are_transient(self):
        get_source = source_between(
            MAIN_SOURCE,
            "def get_bgp_connector_status(",
            "def check_bgp_connector_router(",
        )
        self.assertIn("status = persisted_bgp_connector_status(connector)", get_source)
        self.assertIn('"check_state": in_progress.get("state") if in_progress else "idle"', get_source)
        self.assertNotIn("persist_bgp_connector_status_snapshot", get_source)
        post_source = source_between(
            MAIN_SOURCE,
            "def check_bgp_connector_router(",
            "def test_bgp_connector_flowspec(",
        )
        self.assertIn("except BgpStatusCheckInProgress as exc", post_source)
        self.assertIn("status_code=409", post_source)
        self.assertIn("except BgpStatusCheckTimedOut as exc", post_source)
        self.assertIn("status_code=504", post_source)
        self.assertEqual(post_source.count('headers={"Retry-After": str(exc.retry_after_seconds)}'), 2)


class BgpFrontendConcurrencyStaticTest(unittest.TestCase):
    def check_source(self) -> str:
        return source_between(
            FRONTEND_SOURCE,
            "function updateBgpCheckButtonsState()",
            "async function loadBgpConnectorsView()",
        )

    def test_single_check_refreshes_status_in_finally_for_every_outcome(self):
        source = self.check_source()
        single = source[source.index("async function checkBgpConnectorStatusNow(connectorId)"):]
        self.assertIn("try {\n        result = await request;\n      } finally {", single)
        self.assertIn("if (options.refresh !== false) await refreshBgpConnectorStatuses({ afterCurrent: true });", single)
        bulk = source_between(
            source,
            "async function checkBgpConnectorStatusesNow()",
            "async function checkBgpConnectorStatusNow(connectorId)",
        )
        self.assertIn("await refreshBgpConnectorStatuses({ afterCurrent: true })", bulk)
        refresh_source = source_between(
            FRONTEND_SOURCE,
            "async function refreshBgpConnectorStatuses(options = {})",
            "function updateBgpCheckButtonsState()",
        )
        self.assertIn("await activeRefresh.catch(() => {})", refresh_source)
        self.assertIn("return refreshBgpConnectorStatuses(options)", refresh_source)
        self.assertNotIn("bgpConnectorStatuses =", single)
        self.assertEqual(single.count("/check-router`, { method: 'POST' }"), 1)

    def test_inflight_promise_is_generation_checked_and_always_removed(self):
        source = self.check_source()
        self.assertIn("const bgpConnectorChecksInFlight = new Map()", FRONTEND_SOURCE)
        self.assertIn("request.finally(() =>", source)
        self.assertIn("bgpConnectorChecksInFlight.get(connectorKey) === trackedRequest", source)
        self.assertIn("bgpConnectorChecksInFlight.delete(connectorKey)", source)
        self.assertIn("button.disabled = checking", source)

    def test_each_check_action_has_exactly_one_listener_and_no_bgp_timer(self):
        markers = (
            "getElementById('checkAllBgpConnectorsButton').addEventListener('click'",
            "getElementById('checkBgpStatusButton').addEventListener('click'",
            "getElementById('bgpPeerStatusRows').addEventListener('click'",
        )
        for marker in markers:
            self.assertEqual(FRONTEND_SOURCE.count(marker), 1, marker)
        source = self.check_source()
        self.assertNotIn("setInterval", source)
        self.assertNotIn("setTimeout", source)
        self.assertNotIn("/announcements", source)
        self.assertNotIn("runBgpDryRun", source)
        self.assertNotIn("updateBgpAnnouncement", source)


if __name__ == "__main__":
    unittest.main()
