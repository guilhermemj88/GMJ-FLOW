-- GMJ-FLOW additive SQLite migration: template JSON editavel por destino.
--
-- Para instalacoes que JA aplicaram 20260928_media_webhooks.sql.
-- O startup do backend aplica o mesmo efeito de forma idempotente via
-- ensure_media_db() + ensure_sqlite_column(); este arquivo serve para rollout
-- manual controlado.
--
-- Compatibilidade: a coluna nasce NULL. Destino sem template customizado usa
-- automaticamente o DEFAULT_PAYLOAD_TEMPLATE (payload legado identico).
-- Nada de UPDATE: nenhum destino existente e alterado.
--
-- SQLite nao suporta ADD COLUMN IF NOT EXISTS. Rode este ALTER apenas se a
-- coluna ainda nao existir:
--   PRAGMA table_info(media_integrations);

ALTER TABLE media_integrations ADD COLUMN payload_template TEXT;
