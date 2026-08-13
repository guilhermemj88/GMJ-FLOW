from __future__ import annotations

import copy
import logging
import os
import pickle
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


MIB = 1024 * 1024
GIB = 1024 * MIB
DEFAULT_SCHEMA_VERSION = "dashboard-v3"
_UNLIMITED_CGROUP_THRESHOLD = 1 << 60


class CacheBackend:
    def get(self, key: str) -> Any | None: ...

    def set(self, key: str, value: Any, ttl_seconds: int) -> bool: ...

    def clear(self) -> int: ...

    def status(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class MemorySnapshot:
    host_total_bytes: int
    host_available_bytes: int
    container_limit_bytes: int | None = None
    container_usage_bytes: int | None = None

    @property
    def container_available_bytes(self) -> int | None:
        if self.container_limit_bytes is None:
            return None
        return max(0, self.container_limit_bytes - int(self.container_usage_bytes or 0))

    @property
    def available_bytes(self) -> int:
        available = max(0, int(self.host_available_bytes))
        container_available = self.container_available_bytes
        if container_available is not None:
            available = min(available, container_available)
        return available


@dataclass(frozen=True)
class DashboardCacheConfig:
    mode: str = "auto"
    custom_max_bytes: int | None = None
    max_entries: int = 1000
    min_available_bytes: int = 1536 * MIB
    max_available_percent: float = 5.0
    max_item_bytes: int = 8 * MIB
    workers: int = 1
    monitor_interval_seconds: int = 15
    singleflight_timeout_seconds: int = 35
    schema_version: str = DEFAULT_SCHEMA_VERSION
    prewarm: bool = False

    @classmethod
    def from_env(
        cls,
        environ: dict[str, str] | None = None,
        log: logging.Logger | None = None,
    ) -> "DashboardCacheConfig":
        env = environ if environ is not None else os.environ
        logger = log or logging.getLogger("gmj-flow.dashboard-cache")
        mode = str(env.get("GMJFLOW_DASHBOARD_CACHE_MODE", "auto")).strip().lower()
        if mode not in {"disabled", "auto", "custom"}:
            logger.warning("DASHBOARD_CACHE_CONFIG_INVALID mode=%s fallback=auto", mode)
            mode = "auto"

        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            raw = str(env.get(name, default)).strip()
            try:
                value = int(raw)
            except (TypeError, ValueError):
                logger.warning("DASHBOARD_CACHE_CONFIG_INVALID name=%s value=%s fallback=%s", name, raw, default)
                return default
            if value < minimum or value > maximum:
                safe = min(max(value, minimum), maximum)
                logger.warning("DASHBOARD_CACHE_CONFIG_CLAMPED name=%s value=%s safe=%s", name, value, safe)
                return safe
            return value

        def number(name: str, default: float, minimum: float, maximum: float) -> float:
            raw = str(env.get(name, default)).strip()
            try:
                value = float(raw)
            except (TypeError, ValueError):
                logger.warning("DASHBOARD_CACHE_CONFIG_INVALID name=%s value=%s fallback=%s", name, raw, default)
                return default
            if value < minimum or value > maximum:
                safe = min(max(value, minimum), maximum)
                logger.warning("DASHBOARD_CACHE_CONFIG_CLAMPED name=%s value=%s safe=%s", name, value, safe)
                return safe
            return value

        custom_raw = str(env.get("GMJFLOW_DASHBOARD_CACHE_MAX_MB", "")).strip()
        custom_max_bytes: int | None = None
        if custom_raw:
            try:
                custom_mb = int(custom_raw)
            except ValueError:
                custom_mb = 0
            if custom_mb <= 0:
                logger.warning("DASHBOARD_CACHE_CONFIG_INVALID name=GMJFLOW_DASHBOARD_CACHE_MAX_MB value=%s", custom_raw)
            else:
                custom_max_bytes = min(custom_mb, 4096) * MIB
                if custom_mb > 4096:
                    logger.warning(
                        "DASHBOARD_CACHE_CONFIG_CLAMPED name=GMJFLOW_DASHBOARD_CACHE_MAX_MB value=%s safe=4096",
                        custom_mb,
                    )
        if mode == "custom" and custom_max_bytes is None:
            logger.warning("DASHBOARD_CACHE_CUSTOM_MAX_REQUIRED fallback=disabled")
            mode = "disabled"

        workers = detected_worker_count(env)
        return cls(
            mode=mode,
            custom_max_bytes=custom_max_bytes,
            max_entries=integer("GMJFLOW_DASHBOARD_CACHE_MAX_ENTRIES", 1000, 1, 100_000),
            min_available_bytes=integer(
                "GMJFLOW_DASHBOARD_CACHE_MIN_AVAILABLE_MB",
                1536,
                128,
                1_048_576,
            )
            * MIB,
            max_available_percent=number(
                "GMJFLOW_DASHBOARD_CACHE_MAX_AVAILABLE_PERCENT",
                5.0,
                0.1,
                25.0,
            ),
            max_item_bytes=integer("GMJFLOW_DASHBOARD_CACHE_MAX_ITEM_MB", 8, 1, 256) * MIB,
            workers=workers,
            monitor_interval_seconds=integer(
                "GMJFLOW_DASHBOARD_CACHE_MEMORY_CHECK_SECONDS",
                15,
                5,
                300,
            ),
            singleflight_timeout_seconds=integer(
                "GMJFLOW_DASHBOARD_CACHE_SINGLEFLIGHT_TIMEOUT_SECONDS",
                35,
                1,
                600,
            ),
            schema_version=str(
                env.get("GMJFLOW_DASHBOARD_CACHE_SCHEMA_VERSION", DEFAULT_SCHEMA_VERSION)
            ).strip()
            or DEFAULT_SCHEMA_VERSION,
            prewarm=str(env.get("GMJFLOW_DASHBOARD_CACHE_PREWARM", "false")).strip().lower()
            in {"1", "true", "yes", "on"},
        )


@dataclass
class _CacheEntry:
    value: Any
    size_bytes: int
    created_at: float
    expires_at: float


@dataclass
class _Flight:
    event: threading.Event
    owner_thread_id: int
    started_at: float
    result: Any = None
    error: BaseException | None = None


def detected_worker_count(environ: dict[str, str] | None = None) -> int:
    env = environ if environ is not None else os.environ
    for name in ("GMJFLOW_DASHBOARD_CACHE_WORKERS", "WEB_CONCURRENCY", "UVICORN_WORKERS"):
        raw = str(env.get(name, "")).strip()
        if raw:
            try:
                return max(1, min(int(raw), 128))
            except ValueError:
                continue
    gunicorn_args = str(env.get("GUNICORN_CMD_ARGS", ""))
    match = re.search(r"(?:--workers(?:=|\s+)|-w\s+)(\d+)", gunicorn_args)
    if match:
        return max(1, min(int(match.group(1)), 128))
    return 1


def _read_positive_int(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None
    if not raw or raw.lower() == "max":
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    if value <= 0 or value >= _UNLIMITED_CGROUP_THRESHOLD:
        return None
    return value


def _cgroup_memory(cgroup_root: Path = Path("/sys/fs/cgroup")) -> tuple[int | None, int | None]:
    # cgroup v2
    limit = _read_positive_int(cgroup_root / "memory.max")
    usage = _read_positive_int(cgroup_root / "memory.current")
    if limit is not None:
        return limit, usage or 0

    # cgroup v1; the common direct path is checked first, followed by one
    # bounded search for runtimes that mount the memory controller deeper.
    candidates = [
        cgroup_root / "memory" / "memory.limit_in_bytes",
        cgroup_root / "memory.limit_in_bytes",
    ]
    for path in candidates:
        limit = _read_positive_int(path)
        if limit is not None:
            return limit, _read_positive_int(path.with_name("memory.usage_in_bytes")) or 0
    try:
        paths = list(cgroup_root.glob("**/memory.limit_in_bytes"))[:32]
    except OSError:
        paths = []
    for path in paths:
        limit = _read_positive_int(path)
        if limit is not None:
            return limit, _read_positive_int(path.with_name("memory.usage_in_bytes")) or 0
    return None, None


def detect_memory_snapshot(cgroup_root: Path = Path("/sys/fs/cgroup")) -> MemorySnapshot:
    total = 0
    available = 0
    try:
        import psutil  # type: ignore

        memory = psutil.virtual_memory()
        total = int(memory.total)
        available = int(memory.available)
    except Exception:
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            values: dict[str, int] = {}
            try:
                for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        values[parts[0].rstrip(":")] = int(parts[1]) * 1024
            except (OSError, ValueError):
                values = {}
            total = values.get("MemTotal", 0)
            available = values.get("MemAvailable", values.get("MemFree", 0))
        if not total:
            try:
                import ctypes

                class MemoryStatus(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                status = MemoryStatus()
                status.dwLength = ctypes.sizeof(MemoryStatus)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                    total = int(status.ullTotalPhys)
                    available = int(status.ullAvailPhys)
            except Exception:
                pass

    limit, usage = _cgroup_memory(cgroup_root)
    # Some cgroup v1 installations publish a sentinel larger than physical
    # memory. It is not an effective container limit.
    if limit is not None and total and limit > total * 4:
        limit, usage = None, None
    return MemorySnapshot(
        host_total_bytes=max(0, total),
        host_available_bytes=max(0, available),
        container_limit_bytes=limit,
        container_usage_bytes=usage,
    )


def automatic_total_budget(available_bytes: int) -> int:
    if available_bytes < 2 * GIB:
        return 0
    if available_bytes < 4 * GIB:
        return 64 * MIB
    if available_bytes < 8 * GIB:
        return 128 * MIB
    if available_bytes < 16 * GIB:
        return 256 * MIB
    return 512 * MIB


def effective_budget(config: DashboardCacheConfig, memory: MemorySnapshot) -> tuple[int, int]:
    if config.mode == "disabled":
        return 0, 0
    available = memory.available_bytes
    if config.mode == "custom":
        configured_total = int(config.custom_max_bytes or 0)
    else:
        configured_total = automatic_total_budget(available)
    workers = max(1, int(config.workers))
    if available < config.min_available_bytes:
        return configured_total // workers, 0
    percent_cap = int(available * config.max_available_percent / 100.0)
    container_cap = memory.container_available_bytes
    safe_total = min(configured_total, percent_cap)
    if container_cap is not None:
        safe_total = min(safe_total, container_cap)
    return configured_total // workers, max(0, safe_total // workers)


class MemoryDashboardCache(CacheBackend):
    """Bounded local-process cache.

    Every backend worker owns one instance. The safe host/container budget is
    divided by the configured worker count before this instance is enabled.
    """

    def __init__(
        self,
        config: DashboardCacheConfig | None = None,
        *,
        memory_provider: Callable[[], MemorySnapshot] = detect_memory_snapshot,
        clock: Callable[[], float] = time.monotonic,
        log: logging.Logger | None = None,
    ):
        self.config = config or DashboardCacheConfig.from_env()
        self._memory_provider = memory_provider
        self._clock = clock
        self._logger = log or logging.getLogger("gmj-flow.dashboard-cache")
        self._lock = threading.RLock()
        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._flights: dict[str, _Flight] = {}
        self._current_bytes = 0
        self._started_at = clock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._skipped_large_items = 0
        self._singleflight_shared_requests = 0
        self._memory_pressure = False
        self._insertions_suspended = False
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._memory = memory_provider()
        self._configured_max_bytes, self._effective_max_bytes = effective_budget(self.config, self._memory)
        if self.config.mode == "custom" and self.config.custom_max_bytes and (
            self._effective_max_bytes < self.config.custom_max_bytes // max(1, self.config.workers)
        ):
            self._logger.warning(
                "DASHBOARD_CACHE_CUSTOM_LIMIT_REDUCED configured=%s effective=%s workers=%s",
                self.config.custom_max_bytes,
                self._effective_max_bytes,
                self.config.workers,
            )

    @property
    def enabled(self) -> bool:
        return self.config.mode != "disabled" and self._effective_max_bytes > 0

    @property
    def effective_max_bytes(self) -> int:
        return self._effective_max_bytes

    @staticmethod
    def approximate_size(value: Any) -> int:
        try:
            return max(1, len(pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)))
        except Exception:
            try:
                return max(1, len(repr(value).encode("utf-8", errors="replace")))
            except Exception:
                return 1

    def _purge_expired_locked(self, now: float) -> None:
        expired = [key for key, entry in self._entries.items() if entry.expires_at <= now]
        for key in expired:
            self._remove_locked(key, eviction=False)

    def _remove_locked(self, key: str, *, eviction: bool) -> bool:
        entry = self._entries.pop(key, None)
        if entry is None:
            return False
        self._current_bytes = max(0, self._current_bytes - entry.size_bytes)
        if eviction:
            self._evictions += 1
        return True

    def _shrink_to_locked(self, target_bytes: int) -> int:
        removed = 0
        while self._entries and (
            self._current_bytes > max(0, target_bytes)
            or len(self._entries) > self.config.max_entries
        ):
            key = next(iter(self._entries))
            if self._remove_locked(key, eviction=True):
                removed += 1
        return removed

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            with self._lock:
                self._misses += 1
            return None
        now = self._clock()
        with self._lock:
            self._purge_expired_locked(now)
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None
            self._entries.move_to_end(key)
            self._hits += 1
            return copy.deepcopy(entry.value)

    def set(self, key: str, value: Any, ttl_seconds: int) -> bool:
        if not self.enabled or self._insertions_suspended or ttl_seconds <= 0:
            return False
        size = self.approximate_size(value)
        max_item = min(self.config.max_item_bytes, max(1, self._effective_max_bytes // 4))
        if size > max_item or size > self._effective_max_bytes:
            with self._lock:
                self._skipped_large_items += 1
            self._logger.warning(
                "cache_item_too_large key_hash=%s size_bytes=%s max_item_bytes=%s",
                hash(key),
                size,
                max_item,
            )
            return False
        now = self._clock()
        stored = copy.deepcopy(value)
        with self._lock:
            self._purge_expired_locked(now)
            self._remove_locked(key, eviction=False)
            self._entries[key] = _CacheEntry(
                value=stored,
                size_bytes=size,
                created_at=now,
                expires_at=now + max(1, int(ttl_seconds)),
            )
            self._current_bytes += size
            self._entries.move_to_end(key)
            self._shrink_to_locked(self._effective_max_bytes)
        return True

    def get_or_compute(self, key: str, ttl_seconds: int, compute: Callable[[], Any]) -> Any:
        cached = self.get(key)
        if cached is not None:
            return cached
        flight, owner = self._flight(key)
        if not owner:
            if not flight.event.wait(self.config.singleflight_timeout_seconds):
                self._logger.warning(
                    "dashboard_cache_singleflight_wait_exceeded key_hash=%s wait_seconds=%s",
                    hash(key),
                    self.config.singleflight_timeout_seconds,
                )
                # A slow owner must remain the only computation. Starting a
                # second ClickHouse query here used to amplify dashboard load.
                flight.event.wait()
            if flight.error is not None:
                raise flight.error
            return copy.deepcopy(flight.result)
        try:
            result = compute()
        except BaseException as exc:
            self.fail_flight(key, exc)
            raise
        self.publish(key, result, ttl_seconds)
        return result

    def lookup_or_reserve(self, key: str) -> tuple[Any | None, bool]:
        """Compatibility bridge for legacy get/compute/set call sites.

        The owner receives ``(None, True)`` and computes. Concurrent callers
        wait for the owner's publish even when storage mode is disabled.
        """
        if self.enabled:
            now = self._clock()
            with self._lock:
                self._purge_expired_locked(now)
                entry = self._entries.get(key)
                if entry is not None:
                    self._entries.move_to_end(key)
                    self._hits += 1
                    return copy.deepcopy(entry.value), False
        flight, owner = self._flight(key)
        if owner:
            with self._lock:
                self._misses += 1
            return None, True
        if not flight.event.wait(self.config.singleflight_timeout_seconds):
            self._logger.warning(
                "dashboard_cache_singleflight_wait_exceeded key_hash=%s wait_seconds=%s",
                hash(key),
                self.config.singleflight_timeout_seconds,
            )
            flight.event.wait()
        if flight.error is not None:
            raise flight.error
        return copy.deepcopy(flight.result), False

    def _flight(self, key: str) -> tuple[_Flight, bool]:
        now = self._clock()
        thread_id = threading.get_ident()
        with self._lock:
            flight = self._flights.get(key)
            if flight is None or flight.event.is_set():
                flight = _Flight(threading.Event(), thread_id, now)
                self._flights[key] = flight
                return flight, True
            if flight.owner_thread_id == thread_id:
                return flight, True
            self._singleflight_shared_requests += 1
            return flight, False

    def publish(self, key: str, value: Any, ttl_seconds: int) -> bool:
        stored = self.set(key, value, ttl_seconds)
        with self._lock:
            flight = self._flights.pop(key, None)
            if flight is not None:
                flight.result = copy.deepcopy(value)
                flight.event.set()
        return stored

    def fail_flight(self, key: str, error: BaseException) -> None:
        with self._lock:
            flight = self._flights.pop(key, None)
            if flight is not None:
                flight.error = error
                flight.event.set()

    def fail_thread_flights(self, error: BaseException) -> int:
        thread_id = threading.get_ident()
        with self._lock:
            keys = [
                key
                for key, flight in self._flights.items()
                if flight.owner_thread_id == thread_id
            ]
            for key in keys:
                flight = self._flights.pop(key)
                flight.error = error
                flight.event.set()
            return len(keys)

    def clear(self) -> int:
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._current_bytes = 0
            return count

    def invalidate(self, predicate: Callable[[str], bool]) -> int:
        with self._lock:
            keys = [key for key in self._entries if predicate(key)]
            for key in keys:
                self._remove_locked(key, eviction=False)
            return len(keys)

    def evaluate_memory_pressure(self, snapshot: MemorySnapshot | None = None) -> bool:
        memory = snapshot or self._memory_provider()
        configured, effective = effective_budget(self.config, memory)
        available = memory.available_bytes
        pressure = available < self.config.min_available_bytes or (
            self.config.mode != "disabled" and effective <= 0
        )
        with self._lock:
            was_pressure = self._memory_pressure
            previous_limit = self._effective_max_bytes
            self._memory = memory
            self._configured_max_bytes = configured
            self._effective_max_bytes = effective
            self._memory_pressure = pressure
            self._insertions_suspended = pressure
            removed = 0
            if pressure:
                target = min(effective, max(0, self._current_bytes // 2))
                removed = self._shrink_to_locked(target)
            elif effective < previous_limit:
                removed = self._shrink_to_locked(effective)
        if pressure and not was_pressure:
            self._logger.warning(
                "DASHBOARD_CACHE_MEMORY_PRESSURE available=%s minimum=%s",
                available,
                self.config.min_available_bytes,
            )
            if effective <= 0:
                self._logger.warning("DASHBOARD_CACHE_DISABLED_BY_MEMORY available=%s", available)
        if removed:
            self._logger.warning(
                "DASHBOARD_CACHE_SHRUNK removed=%s current_bytes=%s effective_max_bytes=%s",
                removed,
                self._current_bytes,
                effective,
            )
        if was_pressure and not pressure:
            self._logger.info(
                "DASHBOARD_CACHE_RECOVERED available=%s effective_max_bytes=%s",
                available,
                effective,
            )
        return pressure

    def start_monitor(self) -> None:
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()

        def loop() -> None:
            while not self._stop_event.wait(self.config.monitor_interval_seconds):
                try:
                    self.evaluate_memory_pressure()
                except Exception as exc:
                    self._logger.warning("DASHBOARD_CACHE_MEMORY_CHECK_FAILED error=%s", exc)

        self._monitor_thread = threading.Thread(
            target=loop,
            name="dashboard-cache-memory",
            daemon=True,
        )
        self._monitor_thread.start()

    def stop_monitor(self) -> None:
        self._stop_event.set()
        thread = self._monitor_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=1)
        self._monitor_thread = None

    def status(self) -> dict[str, Any]:
        with self._lock:
            requests = self._hits + self._misses
            memory = self._memory
            return {
                "mode": self.config.mode,
                "enabled": self.enabled,
                "schema_version": self.config.schema_version,
                "configured_max_bytes": self._configured_max_bytes,
                "effective_max_bytes": self._effective_max_bytes,
                "current_bytes": self._current_bytes,
                "entries": len(self._entries),
                "max_entries": self.config.max_entries,
                "max_item_bytes": min(
                    self.config.max_item_bytes,
                    max(0, self._effective_max_bytes // 4),
                ),
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "skipped_large_items": self._skipped_large_items,
                "singleflight_shared_requests": self._singleflight_shared_requests,
                "singleflight_inflight": len(self._flights),
                "memory_pressure": self._memory_pressure,
                "insertions_suspended": self._insertions_suspended,
                "available_memory": memory.available_bytes,
                "host_available_memory": memory.host_available_bytes,
                "detected_container_limit": memory.container_limit_bytes,
                "detected_container_usage": memory.container_usage_bytes,
                "workers": self.config.workers,
                "estimated_total_worker_budget": self._effective_max_bytes * self.config.workers,
                "uptime": round(max(0.0, self._clock() - self._started_at), 2),
                "hit_ratio": round(self._hits / requests, 4) if requests else 0.0,
                "prewarm": self.config.prewarm,
            }
