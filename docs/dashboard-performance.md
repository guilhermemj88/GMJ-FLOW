# Dashboard performance

The dashboard read path uses three complementary controls:

1. a bounded local-memory cache with TTL, LRU eviction and single-flight;
2. narrow one-minute ClickHouse aggregates for the high-cardinality panels;
3. lazy, independently rendered browser requests.

## Cache sizing

`GMJFLOW_DASHBOARD_CACHE_MODE` accepts `disabled`, `auto` or `custom` and
defaults to `auto`. Auto mode measures available memory, including the
remaining cgroup v1/v2 allowance when the backend is containerized. It does
not size from total host RAM alone.

The automatic total budget is 0 below 2 GiB available, then 64, 128, 256 or
512 MiB for the configured memory bands. The effective budget is also capped
by `GMJFLOW_DASHBOARD_CACHE_MAX_AVAILABLE_PERCENT`, the remaining container
allowance and `GMJFLOW_DASHBOARD_CACHE_MIN_AVAILABLE_MB`.

The cache is process-local. Each Uvicorn/Gunicorn worker has its own entries
and statistics. The detected/configured worker count divides the safe total
budget, so:

```text
estimated maximum cache RAM =
    effective limit per worker × worker count
```

Set `GMJFLOW_DASHBOARD_CACHE_WORKERS` when worker discovery through
`WEB_CONCURRENCY`, `UVICORN_WORKERS` or `GUNICORN_CMD_ARGS` is not sufficient.
Redis is not required; the backend is exposed through a small cache interface
so a shared backend can be added later.

In `disabled` mode no result is retained and prewarm is ignored. Single-flight
remains active, so concurrent equal requests still share one computation.

## Memory pressure

A daemon checks available memory periodically. Under the configured floor it
suspends insertion and evicts least-recently-used derived entries. Requests
continue without relying on the cache. Once memory recovers, insertion is
enabled again without an automatic prewarm burst.

The read-only `GET /api/system/dashboard-cache` endpoint exposes counters and
sizing only, never cache keys or values. `DELETE /api/system/dashboard-cache`
clears derived entries only.

## ClickHouse aggregates and rollout

The backend creates one-minute tables and materialized views for:

- series;
- source and destination IP;
- destination port/protocol;
- protocol;
- source and destination ASN;
- TCP flags;
- SYN source/destination;
- conversations.

No existing table or TTL is changed. There is no `DROP`, `TRUNCATE`,
`OPTIMIZE FINAL` or automatic historical backfill.

During an upgrade, a panel uses its aggregate only after the requested
interior minutes are covered. The first and last partial minute still come
from the raw table and are unioned with the aggregate, preserving exact
window boundaries. Until coverage exists, the endpoint safely uses the
original query. This makes rollout non-destructive and avoids showing partial
historical totals.

Sample-rate configuration is copied to a small derived ClickHouse
configuration table. Aggregate queries join it after minute aggregation,
instead of evaluating the generated `multiIf` for every raw row. Raw
`sample_rate` remains the fallback, preserving exporters without an explicit
configuration.

Zone queries use an aggregate only when that aggregate contains every
dimension needed by the filter. Otherwise they retain the raw semantic path.

## Prewarm

Prewarm defaults to off. When explicitly enabled it applies a per-process
jitter and loads only configured sensors and the SQLite operations summary.
It never invokes a raw-flow query and is skipped during memory pressure.

## Operational verification

HTTP logs contain method, path, status, duration, response size and request
ID, without request or response payloads. Each ClickHouse call receives a
query ID derived from that request ID and a `log_comment` containing the
request ID, allowing the slow HTTP request and `system.query_log` entry to be
correlated.

