from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any


def _summary_number(summary: dict[str, Any], *names: str) -> int:
    for name in names:
        value = summary.get(name)
        if value is None:
            continue
        try:
            return int(float(value))
        except (TypeError, ValueError):
            continue
    return 0


@dataclass
class DashboardPerformanceTrace:
    dashboard_id: Any
    widget_id: Any
    widget_type: str
    metric: str
    request_id: str
    started_at: float = field(default_factory=time.monotonic)
    stages_ms: dict[str, float] = field(default_factory=dict)
    queries: list[dict[str, Any]] = field(default_factory=list)
    cache_hit: bool = False
    query_path: str = ""

    def add_stage(self, name: str, duration_seconds: float) -> None:
        self.stages_ms[name] = round(
            self.stages_ms.get(name, 0.0) + max(0.0, duration_seconds) * 1000,
            2,
        )

    def record_query(
        self,
        *,
        query_id: str,
        duration_seconds: float,
        result: Any = None,
        failed: bool = False,
    ) -> None:
        summary = getattr(result, "summary", None)
        if not isinstance(summary, dict):
            summary = {}
        rows = getattr(result, "result_rows", None)
        self.queries.append(
            {
                "query_id": query_id,
                "duration_ms": round(max(0.0, duration_seconds) * 1000, 2),
                "read_rows": _summary_number(summary, "read_rows", "rows_read"),
                "read_bytes": _summary_number(summary, "read_bytes", "bytes_read"),
                "result_rows": _summary_number(summary, "result_rows")
                or (len(rows) if isinstance(rows, list) else 0),
                "memory_bytes": _summary_number(
                    summary,
                    "memory_usage",
                    "memory_usage_bytes",
                    "peak_memory_usage",
                ),
                "cpu_time_us": _summary_number(
                    summary,
                    "cpu_time_us",
                    "os_cpu_virtual_time_microseconds",
                ),
                "failed": bool(failed),
            }
        )

    def log_payload(
        self,
        *,
        cache_hit: bool,
        query_path: str,
        result_rows: int = 0,
        response_bytes: int = 0,
        error: str = "",
    ) -> dict[str, Any]:
        total_ms = round((time.monotonic() - self.started_at) * 1000, 2)
        clickhouse_ms = round(
            sum(float(item.get("duration_ms") or 0) for item in self.queries),
            2,
        )
        attributed_ms = clickhouse_ms + sum(
            float(self.stages_ms.get(name, 0.0))
            for name in (
                "auth",
                "sqlite",
                "enrichment",
                "aggregation",
                "serialization",
                "fallback",
            )
        )
        return {
            "event": "dashboard_widget_performance",
            "request_id": self.request_id,
            "dashboard_id": self.dashboard_id,
            "widget_id": self.widget_id,
            "widget_type": self.widget_type,
            "metric": self.metric,
            "query_path": query_path,
            "cache_hit": bool(cache_hit),
            "total_ms": total_ms,
            "clickhouse_ms": clickhouse_ms,
            "auth_ms": round(self.stages_ms.get("auth", 0.0), 2),
            "sqlite_ms": round(self.stages_ms.get("sqlite", 0.0), 2),
            "enrichment_ms": round(self.stages_ms.get("enrichment", 0.0), 2),
            "aggregation_ms": round(self.stages_ms.get("aggregation", 0.0), 2),
            "serialization_ms": round(self.stages_ms.get("serialization", 0.0), 2),
            "fallback_ms": round(self.stages_ms.get("fallback", 0.0), 2),
            "unattributed_ms": round(max(0.0, total_ms - attributed_ms), 2),
            "query_count": len(self.queries),
            "query_ids": [item["query_id"] for item in self.queries],
            "query_stats": [dict(item) for item in self.queries],
            "read_rows": sum(int(item.get("read_rows") or 0) for item in self.queries),
            "read_bytes": sum(int(item.get("read_bytes") or 0) for item in self.queries),
            "query_result_rows": sum(
                int(item.get("result_rows") or 0) for item in self.queries
            ),
            "peak_query_memory_bytes": max(
                (int(item.get("memory_bytes") or 0) for item in self.queries),
                default=0,
            ),
            "cpu_time_us": sum(
                int(item.get("cpu_time_us") or 0) for item in self.queries
            ),
            "result_rows": int(result_rows or 0),
            "response_bytes": int(response_bytes or 0),
            "error": error,
        }
