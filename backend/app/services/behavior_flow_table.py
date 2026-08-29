"""Single owner of the behavior 10-second aggregate table name (Behavior V2 cutover).

All readers of the behavior flow aggregates MUST resolve the table through this
module so the V1 -> V2 switch stays a single-point, reversible decision.

- Default (env absent/empty): ``behavior_flow_10s_v2`` (time-safe).
- Allowlist: ``behavior_flow_10s``, ``behavior_flow_10s_v2``.
- Invalid env value: safe fallback to ``behavior_flow_10s`` (never interpolates
  an unvalidated string into SQL).

Rollback: set ``GMJFLOW_BEHAVIOR_FLOW_TABLE=behavior_flow_10s`` and rebuild/restart.
"""

from __future__ import annotations

import os

BEHAVIOR_FLOW_TABLE_DEFAULT = "behavior_flow_10s_v2"
BEHAVIOR_FLOW_TABLE_FALLBACK = "behavior_flow_10s"
_ALLOWED = {BEHAVIOR_FLOW_TABLE_DEFAULT, BEHAVIOR_FLOW_TABLE_FALLBACK}


def behavior_flow_table() -> str:
    raw = os.getenv("GMJFLOW_BEHAVIOR_FLOW_TABLE")
    if raw is None or not raw.strip():
        return BEHAVIOR_FLOW_TABLE_DEFAULT
    value = raw.strip()
    if value in _ALLOWED:
        return value
    return BEHAVIOR_FLOW_TABLE_FALLBACK


__all__ = [
    "BEHAVIOR_FLOW_TABLE_DEFAULT",
    "BEHAVIOR_FLOW_TABLE_FALLBACK",
    "behavior_flow_table",
]
