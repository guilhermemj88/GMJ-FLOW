-- ============================================================================
-- Cobertura / benchmark / cardinalidade do ASN dictionary (read-only)
-- Roda em flowdb.flow_raw, somente time_classification='VALID_TIME'.
-- Lookup IPv6 direto (prefixos IPv4 ja chegam como ::ffff:x/120 no dicionario).
-- ============================================================================

-- ----------------------------------------------------------------------------
-- FASE D — testes funcionais de lookup (endianess e LPM)
-- ----------------------------------------------------------------------------
-- 8.8.8.8 (IPv4-mapped, ASN 15169 Google); usar IP NAO-simetrico para pegar
-- endianess (8.8.8.8 e palindromo e NAO detecta inversao).
SELECT
  dictGetOrDefault('flowdb.asn_prefix_dict', 'asn', toIPv6('::ffff:8.8.8.8'), 0)    AS v4_mapped_8888,
  dictGetOrDefault('flowdb.asn_prefix_dict', 'asn', toIPv6('::ffff:8.8.4.4'), 0)    AS v4_mapped_8844,   -- nao-simetrico
  dictGetOrDefault('flowdb.asn_prefix_dict', 'asn', toIPv6('::ffff:1.1.1.1'), 0)    AS v4_mapped_1111,   -- Cloudflare 13335
  dictGetOrDefault('flowdb.asn_prefix_dict', 'asn', toIPv6('2001:4860:4860::8888'), 0) AS v6_google,      -- Google DNS
  dictGetOrDefault('flowdb.asn_prefix_dict', 'asn', toIPv6('::ffff:192.168.0.1'), 0) AS v4_private,      -- privado => 0
  dictGetOrDefault('flowdb.asn_prefix_dict', 'asn', toIPv6('::'), 0)                AS v6_zero;          -- sem anuncio => 0

-- ----------------------------------------------------------------------------
-- FASE E — cobertura (SRC e DST). Comece com janela pequena e expanda.
-- ----------------------------------------------------------------------------
-- SRC — cobertura por bytes e IPs distintos
WITH unresolved AS (
    SELECT src_ip, bytes
    FROM flowdb.flow_raw
    WHERE time_classification = 'VALID_TIME'
      AND flow_time >= now() - INTERVAL 1 HOUR   -- <-- expandir de forma controlada
      AND src_asn = 0
),
resolved AS (
    SELECT
        src_ip, bytes,
        dictGetOrDefault('flowdb.asn_prefix_dict', 'asn', src_ip, 0) AS eff_asn
    FROM unresolved
)
SELECT
    sum(bytes)                                          AS bytes_0,
    sumIf(bytes, eff_asn > 0)                           AS bytes_resolvable,
    round(sumIf(bytes, eff_asn > 0) / sum(bytes), 4)    AS coverage_bytes,
    uniqExact(src_ip)                                   AS distinct_ips_0,
    uniqExactIf(src_ip, eff_asn > 0)                    AS distinct_ips_resolvable,
    round(uniqExactIf(src_ip, eff_asn > 0) / uniqExact(src_ip), 4) AS coverage_distinct_ips,
    sumIf(bytes, eff_asn = 0)                           AS residual_bytes_0,
    round(sumIf(bytes, eff_asn = 0) / sum(bytes), 4)    AS residual_unresolved_bytes
FROM resolved;

-- DST — idem (trocando src_* por dst_*)
WITH unresolved AS (
    SELECT dst_ip, bytes
    FROM flowdb.flow_raw
    WHERE time_classification = 'VALID_TIME'
      AND flow_time >= now() - INTERVAL 1 HOUR
      AND dst_asn = 0
),
resolved AS (
    SELECT
        dst_ip, bytes,
        dictGetOrDefault('flowdb.asn_prefix_dict', 'asn', dst_ip, 0) AS eff_asn
    FROM unresolved
)
SELECT
    sum(bytes)                                          AS bytes_0,
    sumIf(bytes, eff_asn > 0)                           AS bytes_resolvable,
    round(sumIf(bytes, eff_asn > 0) / sum(bytes), 4)    AS coverage_bytes,
    uniqExact(dst_ip)                                   AS distinct_ips_0,
    uniqExactIf(dst_ip, eff_asn > 0)                    AS distinct_ips_resolvable,
    round(uniqExactIf(dst_ip, eff_asn > 0) / uniqExact(dst_ip), 4) AS coverage_distinct_ips,
    sumIf(bytes, eff_asn = 0)                           AS residual_bytes_0,
    round(sumIf(bytes, eff_asn = 0) / sum(bytes), 4)    AS residual_unresolved_bytes
FROM resolved;

-- ----------------------------------------------------------------------------
-- FASE F — benchmark 1h (sem dictionary vs com dictionary)
-- ----------------------------------------------------------------------------
-- (a) baseline sem lookup
SELECT toStartOfMinute(flow_time) AS minute, sensor, input_if, output_if,
       dst_asn, dst_as_name, sum(bytes), sum(packets), sum(flow_count)
FROM flowdb.flow_raw
WHERE time_classification = 'VALID_TIME'
  AND flow_time >= now() - INTERVAL 1 HOUR
GROUP BY minute, sensor, input_if, output_if, dst_asn, dst_as_name;

-- (b) com lookup (mesma forma da MV v2)
SELECT toStartOfMinute(flow_time) AS minute, sensor, input_if, output_if,
       if(dst_asn > 0, dst_asn,
          dictGetOrDefault('flowdb.asn_prefix_dict', 'asn', dst_ip, 0)) AS eff_asn,
       sum(bytes), sum(packets), sum(flow_count)
FROM flowdb.flow_raw
WHERE time_classification = 'VALID_TIME'
  AND flow_time >= now() - INTERVAL 1 HOUR
GROUP BY minute, sensor, input_if, output_if, eff_asn;

-- metricas por query_id no system.query_log
SELECT query_duration_ms, read_rows, read_bytes, result_rows, memory_usage,
       ProfileEvents['OSCPUVirtualTimeMicroseconds'] AS cpu_us
FROM system.query_log
WHERE type = 'QueryFinish' AND query_id = '<query_id>'
ORDER BY event_time DESC LIMIT 1;

-- ----------------------------------------------------------------------------
-- FASE H — cardinalidade compacta em amostra 1h (sem dictionary vs compacta)
-- ----------------------------------------------------------------------------
WITH s AS (
    SELECT toStartOfMinute(flow_time) AS minute, sensor,
           toString(exporter_ip) AS exporter_ip, input_if, output_if, sample_rate,
           src_asn, src_as_name, src_ip, dst_asn, dst_as_name, dst_ip
    FROM flowdb.flow_raw
    WHERE time_classification = 'VALID_TIME'
      AND flow_time >= now() - INTERVAL 1 HOUR
)
SELECT
    -- SRC: chave atual (com IP individual)
    uniqExact((minute, sensor, exporter_ip, input_if, output_if, sample_rate,
               src_asn, src_as_name, src_ip)) AS current_key_groups_src,
    -- SRC: chave compacta (IP resolvido via dictionary)
    uniqExact((minute, sensor, exporter_ip, input_if, output_if, sample_rate,
               if(src_asn > 0, src_asn, dictGetOrDefault('flowdb.asn_prefix_dict','asn', src_ip, 0)),
               if(src_asn > 0, src_as_name, ''))) AS compact_key_groups_src,
    -- DST
    uniqExact((minute, sensor, exporter_ip, input_if, output_if, sample_rate,
               dst_asn, dst_as_name, dst_ip)) AS current_key_groups_dst,
    uniqExact((minute, sensor, exporter_ip, input_if, output_if, sample_rate,
               if(dst_asn > 0, dst_asn, dictGetOrDefault('flowdb.asn_prefix_dict','asn', dst_ip, 0)),
               if(dst_asn > 0, dst_as_name, ''))) AS compact_key_groups_dst
FROM s;
