-- 20260829_transit_rtbh.sql
-- Transit Providers + RTBH policies + Threat Intelligence mitigation candidates.
--
-- RECOMMEND_ONLY / DRY RUN version: this migration creates storage and
-- relationships only. No BGP announcement, router change or FlowSpec/RTBH
-- action is performed. Candidate statuses reach at most
-- PROPOSED / REVIEW_REQUIRED / DRY_RUN.
--
-- The backend also applies this DDL idempotently at startup
-- (ensure_transit_rtbh_schema) so this file is the canonical reference.

CREATE TABLE IF NOT EXISTS transit_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    sensor_id INTEGER,
    input_if INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Per-transit RTBH policy. Communities are NEVER hardcoded; the operator
-- registers them. Threat Intelligence never receives or creates communities.
CREATE TABLE IF NOT EXISTS transit_rtbh_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id INTEGER NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    standard_communities_json TEXT NOT NULL DEFAULT '[]',
    large_communities_json TEXT NOT NULL DEFAULT '[]',
    communities_sensitive INTEGER NOT NULL DEFAULT 1,
    address_family TEXT NOT NULL DEFAULT 'ipv4',
    mode TEXT NOT NULL DEFAULT 'RECOMMEND_ONLY',  -- OFF | RECOMMEND_ONLY | MANUAL_APPROVAL | AUTO
    min_prefix_length INTEGER NOT NULL DEFAULT 32,
    max_prefix_length INTEGER NOT NULL DEFAULT 32,
    min_confidence REAL NOT NULL DEFAULT 0.90,
    min_attack_bps REAL NOT NULL DEFAULT 1000000000.0,
    min_duration_seconds INTEGER NOT NULL DEFAULT 60,
    cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
    allow_auto INTEGER NOT NULL DEFAULT 0,
    require_manual_approval INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES transit_providers(id) ON DELETE CASCADE
);

-- Persistent mitigation candidates generated from Threat Intelligence.
-- Lifecycle in this version: PROPOSED -> REVIEW_REQUIRED -> DRY_RUN.
-- EXECUTING / ACTIVE are defined for schema completeness but unreachable.
CREATE TABLE IF NOT EXISTS rtbh_mitigation_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL DEFAULT '',
    threat_assessment_id TEXT NOT NULL DEFAULT '',
    classification TEXT NOT NULL DEFAULT '',
    action_type TEXT NOT NULL DEFAULT 'RTBH',  -- RTBH | MANUAL_LARGE_PREFIX_RTBH
    target_prefix TEXT NOT NULL DEFAULT '',
    provider_id INTEGER,
    input_if INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0,
    attack_bps_observed REAL NOT NULL DEFAULT 0,
    attack_bps_estimated REAL NOT NULL DEFAULT 0,
    attack_pps_observed REAL NOT NULL DEFAULT 0,
    attack_pps_estimated REAL NOT NULL DEFAULT 0,
    baseline_bps REAL NOT NULL DEFAULT 0,
    attack_baseline_ratio REAL NOT NULL DEFAULT 0,
    attack_share_provider REAL NOT NULL DEFAULT 0,
    suitability_json TEXT NOT NULL DEFAULT '{}',
    collateral_risk TEXT NOT NULL DEFAULT 'NONE',  -- NONE | LOW | MEDIUM | HIGH | CRITICAL
    reason TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'PROPOSED',
    no_safe_selective_rtbh_candidate INTEGER NOT NULL DEFAULT 0,
    large_prefix_manual_only INTEGER NOT NULL DEFAULT 0,
    dry_run_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT 'GMJ_FLOW',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES transit_providers(id) ON DELETE SET NULL
);

-- Audit trail. Community values are never duplicated here; the policy id is
-- the secure reference when communities are sensitive.
CREATE TABLE IF NOT EXISTS rtbh_candidate_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    incident_id TEXT NOT NULL DEFAULT '',
    candidate_id INTEGER,
    provider_id INTEGER,
    target_prefix TEXT NOT NULL DEFAULT '',
    policy_id INTEGER,
    communities_ref TEXT NOT NULL DEFAULT '',
    old_state TEXT NOT NULL DEFAULT '',
    new_state TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_rtbh_candidate_incident_provider_target
    ON rtbh_mitigation_candidates(incident_id, COALESCE(provider_id, 0), target_prefix);
CREATE INDEX IF NOT EXISTS idx_rtbh_candidates_status
    ON rtbh_mitigation_candidates(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rtbh_candidates_incident
    ON rtbh_mitigation_candidates(incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rtbh_candidate_audit_candidate
    ON rtbh_candidate_audit(candidate_id, created_at DESC);

-- Incremental protected-prefix migration (compatibility preserved):
-- legacy block_rtbh boolean remains; three-level RTBH controls are added.
-- Applied by ensure_bgp_db(); listed here for reference.
-- ALTER TABLE bgp_protected_prefixes ADD COLUMN block_auto_rtbh INTEGER NOT NULL DEFAULT 0;
-- ALTER TABLE bgp_protected_prefixes ADD COLUMN require_manual_rtbh INTEGER NOT NULL DEFAULT 1;
-- ALTER TABLE bgp_protected_prefixes ADD COLUMN block_all_rtbh INTEGER NOT NULL DEFAULT 0;
