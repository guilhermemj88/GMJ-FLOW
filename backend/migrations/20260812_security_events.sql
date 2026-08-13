-- GMJ-FLOW additive SQLite migration.
-- Runtime startup applies the equivalent idempotent migration through
-- ensure_security_event_schema; this file is provided for controlled/manual rollout.
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL DEFAULT '',
    event_key TEXT NOT NULL UNIQUE,
    detector TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    attack_family TEXT NOT NULL DEFAULT 'OTHER_FAMILY',
    severity TEXT NOT NULL DEFAULT 'INFO',
    detector_score INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0,
    verdict TEXT NOT NULL DEFAULT 'INFO',
    src_ip TEXT NOT NULL DEFAULT '',
    src_prefix TEXT NOT NULL DEFAULT '',
    target_ip TEXT NOT NULL DEFAULT '',
    target_prefix TEXT NOT NULL DEFAULT '',
    src_role TEXT NOT NULL DEFAULT 'UNKNOWN',
    dst_role TEXT NOT NULL DEFAULT 'UNKNOWN',
    direction TEXT NOT NULL DEFAULT 'UNKNOWN',
    protocol TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    recurrence_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active',
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    packets_per_second REAL NOT NULL DEFAULT 0,
    bits_per_second REAL NOT NULL DEFAULT 0,
    flows INTEGER NOT NULL DEFAULT 0,
    flows_per_second REAL NOT NULL DEFAULT 0,
    unique_sources INTEGER NOT NULL DEFAULT 0,
    unique_destinations INTEGER NOT NULL DEFAULT 0,
    unique_src_ports INTEGER NOT NULL DEFAULT 0,
    unique_dst_ports INTEGER NOT NULL DEFAULT 0,
    unique_source_asns INTEGER NOT NULL DEFAULT 0,
    baseline_deviation REAL NOT NULL DEFAULT 0,
    input_if INTEGER NOT NULL DEFAULT 0,
    output_if INTEGER NOT NULL DEFAULT 0,
    sensor TEXT NOT NULL DEFAULT '',
    exporter TEXT NOT NULL DEFAULT '',
    cgnat_context TEXT NOT NULL DEFAULT '',
    network_context_json TEXT NOT NULL DEFAULT '{}',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    score_components_json TEXT NOT NULL DEFAULT '{}',
    threat_intel_json TEXT NOT NULL DEFAULT '{}',
    investigation_json TEXT NOT NULL DEFAULT '{}',
    ai_analysis_json TEXT NOT NULL DEFAULT '{}',
    ai_analysis_status TEXT NOT NULL DEFAULT 'not_analyzed',
    ai_analysis_stale_at TEXT,
    analyzed_at TEXT,
    ai_provider TEXT NOT NULL DEFAULT '',
    ai_model TEXT NOT NULL DEFAULT '',
    analysis_version TEXT NOT NULL DEFAULT '',
    ai_event_fingerprint TEXT NOT NULL DEFAULT '',
    ai_evidence_fingerprint TEXT NOT NULL DEFAULT '',
    ai_analysis_error TEXT NOT NULL DEFAULT '',
    campaign_id TEXT NOT NULL DEFAULT '',
    mitigation_status TEXT NOT NULL DEFAULT 'not_executed',
    decision_source TEXT NOT NULL DEFAULT 'GMJ_FLOW'
);

CREATE TABLE IF NOT EXISTS security_event_migrations (
    migration_key TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_event_ai_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    generated_at TEXT,
    event_version INTEGER NOT NULL DEFAULT 1,
    event_fingerprint TEXT NOT NULL DEFAULT '',
    evidence_fingerprint TEXT NOT NULL DEFAULT '',
    result_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    error_type TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(event_id) REFERENCES security_events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_security_events_status_time
    ON security_events(status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_type_time
    ON security_events(attack_type, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_campaign
    ON security_events(campaign_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_src
    ON security_events(src_ip, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_target
    ON security_events(target_ip, target_prefix, last_seen DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_security_events_public_id
    ON security_events(public_id) WHERE public_id<>'';
CREATE INDEX IF NOT EXISTS idx_security_event_ai_history
    ON security_event_ai_analyses(event_id, id DESC);
