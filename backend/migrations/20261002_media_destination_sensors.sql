-- GMJ-FLOW additive SQLite migration: filtro de sensores nos destinos existentes.
--
-- Para instalacoes que JA aplicaram 20260928_media_webhooks.sql.
-- O startup do backend aplica o mesmo efeito de forma idempotente via
-- ensure_media_db() + ensure_sqlite_column(); este arquivo serve para rollout
-- manual controlado.
--
-- Compatibilidade: nada de UPDATE. O DEFAULT 1 faz TODO destino existente
-- continuar recebendo eventos de todos os sensores (allSensors = true).
-- O usuario pode depois desmarcar "Todos os sensores" e escolher sensores.
--
-- SQLite nao suporta ADD COLUMN IF NOT EXISTS. Rode este ALTER apenas se a
-- coluna ainda nao existir:
--   PRAGMA table_info(media_integrations);

ALTER TABLE media_integrations ADD COLUMN all_sensors INTEGER NOT NULL DEFAULT 1;

-- Associacao N:N destino <-> sensor. UNIQUE(media_id, sensor_id) pela PK.
-- AUSENCIA de linha = "nenhum sensor especifico"; quem decide e all_sensors.
CREATE TABLE IF NOT EXISTS media_destination_sensors (
    media_id INTEGER NOT NULL,
    sensor_id INTEGER NOT NULL,
    PRIMARY KEY (media_id, sensor_id)
);

CREATE INDEX IF NOT EXISTS idx_media_destination_sensors_sensor
    ON media_destination_sensors (sensor_id);
