from __future__ import annotations

"""Anomaly / Security Event handoff point for the Peak Hunter.

The Peak Hunter NEVER creates an anomaly or applies mitigation on its own.
When a peak is triaged as noteworthy/suspicious (``handoff_recommended``),
the runner calls :func:`handoff_peak_event`, which delegates to an
injectable ``create_event`` callback provided by the caller. The caller is
responsible for wiring that callback to the EXISTING security-event /
anomaly pipeline and for applying whatever criteria that pipeline requires.

A normal peak is simply persisted as a Peak Event; no handoff happens.
"""

from typing import Any, Callable

CreateEvent = Callable[..., Any]


def handoff_peak_event(
    conn: Any,
    event_id: int,
    entry: dict[str, Any],
    create_event: CreateEvent | None = None,
) -> dict[str, Any]:
    """Hand off a triaged peak to the existing pipeline (never mitigates)."""
    threat = entry.get("threat") or {}
    if not threat.get("handoff_recommended"):
        return {"status": "no_handoff", "event_id": event_id}
    payload = {
        "event_id": event_id,
        "verdict": threat.get("verdict"),
        "reasons": threat.get("reasons") or [],
        "ioc_hit_count": threat.get("ioc_hit_count") or 0,
        "peak": entry.get("peak") or {},
        "evidence": entry.get("evidence") or {},
    }
    if create_event is None:
        return {"status": "handoff_pending", "event_id": event_id, "payload": payload}
    created = create_event(conn, payload)
    return {"status": "handed_off", "event_id": event_id, "payload": payload, "created": created}
