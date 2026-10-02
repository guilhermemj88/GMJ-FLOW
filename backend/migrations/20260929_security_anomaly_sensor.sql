-- GMJ-FLOW additive SQLite migration: sensor_id nas anomalias consolidadas.
--
-- O startup aplica exatamente o mesmo DDL de forma idempotente via
-- ensure_sqlite_column("security_anomalies", "sensor_id", ...). Este arquivo
-- existe para rollout manual controlado.
--
-- Semantica: sensor_id = sensor REAL que originou o trafego (detected_sensor_id),
-- resolvido na deteccao. Nunca o sensor de escopo da regra.
--
-- Rollback: ALTER TABLE security_anomalies DROP COLUMN sensor_id;  (SQLite 3.35+)

-- Instalacoes existentes (ALTER nao cria a FK no SQLite):
ALTER TABLE security_anomalies ADD COLUMN sensor_id INTEGER;

CREATE INDEX IF NOT EXISTS idx_security_anomalies_sensor
    ON security_anomalies (sensor_id);

-- Instalacoes novas recebem a coluna ja no CREATE TABLE, com FK:
--   sensor_id INTEGER REFERENCES sensors(id) ON DELETE SET NULL,
