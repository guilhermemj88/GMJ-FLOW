-- ============================================================================
-- ASN prefix source table + IP_TRIE dictionary (ClickHouse 24.8)
-- Fase aditiva: NAO cria tabelas/MVs v2, NAO altera TTL, NAO drop.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1) Source table (uma tabela, IPv4 mapeado em IPv6 + IPv6 nativo)
--    IPv4 1.2.3.0/24 chega como ::ffff:1.2.3.0/120 (conversao feita pelo loader).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS flowdb.asn_prefixes_ch
(
    prefix    String,
    asn       UInt32,
    as_name   String,
    country   LowCardinality(String),
    source    LowCardinality(String),
    loaded_at DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY prefix;

-- ----------------------------------------------------------------------------
-- 2) Dictionary IP_TRIE (chave = prefix String CIDR; um unico dicionario)
--
--    Sintaxe validada (doc oficial CH 24.8):
--      * PRIMARY KEY = atributo `prefix` (String CIDR). Nao existe coluna `ip`.
--      * dictGet aceita UInt32 (IPv4) OU FixedString(16)/IPv6.
--      * Um dicionario pode conter IPv4 e IPv6 misturados.
--    Como carregamos IPv4 como IPv4-mapped IPv6, TODOS os prefixos sao IPv6 e o
--    lookup usa o proprio src_ip/dst_ip (ja IPv6) — sem endianess, sem regex.
-- ----------------------------------------------------------------------------
CREATE DICTIONARY IF NOT EXISTS flowdb.asn_prefix_dict
(
    prefix  String,
    asn     UInt32,
    as_name String,
    country String
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(
    host '127.0.0.1'
    port 9000
    user 'default'
    password ''
    db 'flowdb'
    table 'asn_prefixes_ch'
))
LAYOUT(IP_TRIE)
LIFETIME(MIN 600 MAX 3600);

-- ----------------------------------------------------------------------------
-- 3) Observabilidade
-- ----------------------------------------------------------------------------
SELECT name, status, element_count, bytes_allocated,
       loading_start_time, last_exception, source
FROM system.dictionaries
WHERE name = 'asn_prefix_dict';
