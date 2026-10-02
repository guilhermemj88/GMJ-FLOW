-- GMJ-FLOW additive SQLite migration: Destinos / Alertas por Webhook.
--
-- O startup do backend aplica exatamente o mesmo DDL de forma idempotente via
-- ensure_media_db(); este arquivo existe para rollout manual controlado.
--
-- Cria tres tabelas novas. O filtro por sensor e aditivo: destinos existentes
-- recebem all_sensors = 1 (todos os sensores) e continuam funcionando igual.
-- Rollback: DROP TABLE media_destination_sensors; DROP TABLE media_delivery_logs;
--           DROP TABLE media_integrations;

CREATE TABLE IF NOT EXISTS media_integrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'webhook',
    url TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    all_sensors INTEGER NOT NULL DEFAULT 1,
    payload_template TEXT,
    event_types TEXT NOT NULL DEFAULT '["anomaly_detected"]',
    minimum_severity TEXT NOT NULL DEFAULT 'info',
    timeout_seconds REAL NOT NULL DEFAULT 5,
    secret_encrypted TEXT NOT NULL DEFAULT '',
    secret_header TEXT NOT NULL DEFAULT 'X-GMJ-Flow-Token',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_test_at TEXT,
    last_test_status TEXT NOT NULL DEFAULT '',
    last_test_http_status INTEGER,
    last_test_duration_ms INTEGER,
    last_test_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_media_integrations_active
    ON media_integrations (active, type);

CREATE TABLE IF NOT EXISTS media_delivery_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    media_id INTEGER NOT NULL,
    event_id INTEGER,
    event_type TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    http_status INTEGER,
    duration_ms INTEGER,
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_media_delivery_logs_media
    ON media_delivery_logs (media_id, id DESC);

-- Associacao N:N destino <-> sensor. UNIQUE(media_id, sensor_id) pela PK.
-- AUSENCIA de linha = "nenhum sensor especifico"; quem decide e all_sensors.
CREATE TABLE IF NOT EXISTS media_destination_sensors (
    media_id INTEGER NOT NULL,
    sensor_id INTEGER NOT NULL,
    PRIMARY KEY (media_id, sensor_id)
);

CREATE INDEX IF NOT EXISTS idx_media_destination_sensors_sensor
    ON media_destination_sensors (sensor_id);
