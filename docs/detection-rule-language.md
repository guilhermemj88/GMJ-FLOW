# GMJ-FLOW — Linguagem de Regras (DSL) e Flow Search

> **Status:** Fases 1 e 2 entregues (catálogo/dicionário + Flow Search por expressão) · **Criado:** 2026-10-05
> **Fonte de verdade do código:** `backend/app/services/detection_dsl/` (pacote puro, apenas stdlib).
> **Fonte de verdade do dicionário:** `backend/app/services/detection_dsl/catalog.py`.
> **Endpoint de leitura:** `GET /api/rule-language/catalog`.

Este documento é **canônico** para a linguagem de regras do GMJ-FLOW. Qualquer IA/agente
que for evoluir a DSL, o Flow Search por expressão ou os Vetores de Ataque deve ler este
documento **antes** de alterar código.

Nas **Fases 1 e 2** não há migration, não há AST persistida, não há alteração de
`attack_vectors`/`detection_template_rules` e o detector atual permanece intocado. A Fase 1
consolidou o vocabulário/dicionário; a **Fase 2** liga a DSL ao **Flow Search** por
expressão (`GET /api/flows/search?expression=...`, somente leitura) através de um
compilador seguro.

---

## 1. Objetivo

Criar **uma única linguagem** para:

1. descrever o **MATCH** de uma regra/consulta (atributos do flow);
2. descrever o **TRIGGER** (métricas agregadas acima de um limiar);
3. descrever **EVIDENCE** (o que anexar ao evento/resultado);
4. filtrar **Flow Search** por expressão (Fase 2);
5. servir de base ao **Builder visual** e ao **Dicionário** da UI.

Princípios:

- **uma fonte de verdade** — `catalog.py`; parser, validator, UI e (futuro) compiler leem o mesmo catálogo;
- **nunca SQL livre** — a expressão é sempre interpretada, nunca concatenada;
- **canonicalização na AST** — aliases são aceitos na entrada, mas a AST/serializer usam só a forma canônica;
- **as colunas históricas do banco não mudam** — a canonicalização acontece só na AST.

---

## 2. Arquitetura

```
Texto da DSL ──► parser ──► AST v1 ──► validator ──► (Fase 2) compiler ──► ClickHouse
                  ▲                        ▲
                  └──── catalog.py (dicionário) ────┘
```

| Módulo | Papel |
|---|---|
| `catalog.py` | dicionário canônico: campos, tipos, operadores, aliases, unidades, group_by, dedupe, capabilities e disponibilidade por tipo |
| `units.py` | unidades decimais (`k`/`M`/`G`/`T`) e durações (`s`/`m`/`h`/`d`) |
| `parser.py` | tokenizador + parser de seções/expressão → `RuleAst` (ou `BooleanNode` puro via `parse_expression`) |
| `ast.py` | AST versionada (`RuleAst`, `Condition`, `BooleanGroup`, `NotNode`, …) |
| `validator.py` | validação semântica/capability → `ValidationResult` estruturado (não levanta exceção) |
| `serializer.py` | AST → texto canônico determinístico (round-trip estável) |
| `errors.py` | exceções com `code`/`message`/`line`/`column`/`token`/`suggestion` |

O pacote é **stdlib-only** e não importa banco, detector ou FastAPI. A única integração com
o backend é o endpoint de leitura `GET /api/rule-language/catalog`, que devolve
`catalog_json()` sem duplicar catálogo no frontend.

---

## 3. Gramática

Uma regra completa é organizada em **seções** (palavra-chave em caixa alta no início da linha):

```
MATCH        # atributos do flow (filtro)
WARNING      # gatilho de severidade warning (métricas agregadas)
CRITICAL     # gatilho de severidade critical (métricas agregadas)
EVIDENCE     # campos a anexar (lista separada por vírgula)
ADVANCED     # window, consecutive, cooldown, group_by, dedupe, requires
RESPONSE     # mode e parâmetros de resposta/mitigação
```

Cabeçalho opcional: `RULE`, `DISPLAY_NAME`, `ENABLED`, `SEVERITY`.

Dentro de `MATCH`/`WARNING`/`CRITICAL` a expressão booleana usa:

- `and`, `or`, `not` e parênteses (precedência: `not` > `and` > `or`);
- comparações `campo operador valor`.

Uma **expressão pura** (sem seções) pode ser usada diretamente para Flow Search:

```text
proto == udp and src_port == 53 and direction == inbound
```

No Python: `parse_expression(texto)` devolve o `BooleanNode` e
`validate_expression(texto)` devolve o `ValidationResult` (seção `MATCH`).

---

## 4. Aliases

O parser aceita as formas legadas e **canonicaliza na AST**; o serializer **nunca** emite a
forma legada.

| Entrada aceita | Canônico na AST |
|---|---|
| `=` , `==` , `eq` | `==` |
| `<>` , `!=` , `ne` | `!=` |
| `in` | `IN` |
| `not in` | `NOT IN` |
| `contains` | `CONTAINS` |
| `not contains` | `NOT CONTAINS` |
| `matches` | `MATCHES` |

Direção (relação com o alvo interno):

| Entrada aceita | Canônico | Semântica |
|---|---|---|
| `receives`, `download`, `in`, `entrando` | `inbound` | destino é interno |
| `transmits`, `sends`, `upload`, `out`, `saindo` | `outbound` | origem é interna |
| `both` | `both` | ambos |

Campo `proto` (texto da DSL) ↔ coluna `proto` do banco ↔ campo canônico `protocol` (AST).

Métricas: `pps` → `packets_s`, `bps` → `bits_s`, `flows` → `flows_s`.

---

## 5. Campos (dicionário V1)

Cada campo do catálogo declara `name`, `aliases`, `label`, `description`, `type`, `origin`,
`operators`, `unit`, `enum_values`, `examples`, `MATCH allowed`, `GROUP BY allowed`,
`TRIGGER allowed`, `EVIDENCE allowed`, `capability`, `ClickHouse availability`,
`exporter reliability` e `status`.

### 5.1 MATCH — atributos do flow

`protocol` (`proto`), `direction`, `decoder`, `src_ip`, `dst_ip`, `src_cidr`, `dst_cidr`,
`src_port`, `dst_port`, `tcp_flags` (experimental), `sensor` (`sensor_name`), `sensor_id`,
`exporter_ip`, `input_if` (`in_if`), `output_if` (`out_if`), `src_asn`, `dst_asn`,
`icmp_type`, `icmp_code`, `flow_count`, `bytes`, `packets`.

### 5.2 TRIGGER — métricas agregadas

`pps` (`packets_s`), `bps` (`bits_s`), `flows` (`flows_s`), `unique_src_ips`,
`unique_dst_ips`, `unique_src_ports`, `unique_dst_ports`.

### 5.3 EVIDENCE

`pps`, `bps`, `flows`, `packets`, `bytes`, `unique_src_ips`, `unique_dst_ips`,
`unique_src_ports`, `unique_dst_ports`, `avg_packet_bytes`, `top_src_ips`, `top_dst_ips`,
`top_src_ports`, `top_dst_ports`.

### 5.4 Tipos e `tcp_flags`

- `tcp_flags` é **flags**: só aceita `contains` / `not contains` (nunca `>`, `==`, `in`);
- `sensor` é o **único campo textual** que aceita regex (`matches`);
- IP aceita endereço e, em `IN`/`NOT IN`, também rede (`src_ip in 100.64.0.0/10`);
- `bytes`/`packets`/`flow_count` aparecem em MATCH e EVIDENCE.

> **Disponibilidade:** `tcp_flags` é `experimental` (nem todo exporter entrega flags
> confiáveis) e hoje é coberto em 100% dos flows TCP do ambiente real; o validator emite
> `CAPABILITY_EXPERIMENTAL` como **warning** (não bloqueia).

---

## 6. Operadores

| Tipo | Operadores permitidos |
|---|---|
| numérico / métrica / derivado | `==` `!=` `>` `>=` `<` `<=` `IN` `NOT IN` `BETWEEN` |
| porta / inteiro | `==` `!=` `>` `>=` `<` `<=` `IN` `NOT IN` `BETWEEN` |
| enum | `==` `!=` `IN` `NOT IN` |
| IP / CIDR | `==` `!=` `IN` `NOT IN` |
| flags | `CONTAINS` `NOT CONTAINS` |
| texto | `==` `!=` `MATCHES` |
| lista (evidence) | — (não usado em condição) |

Booleanos: `and`, `or`, `not`, parênteses.

**Regex (`matches`)** é permitido **apenas** em campos textuais explicitamente liberados
(hoje só `sensor`). Nunca em IP, porta, número, flags ou enum. Regex inválida é reportada
como erro estruturado.

---

## 7. Unidades

Escala **decimal** (1000), nunca binária:

| Sufixo | Fator |
|---|---|
| `k` | 1 000 |
| `M` | 1 000 000 |
| `G` | 1 000 000 000 |
| `T` | 1 000 000 000 000 |

Durações: `s`, `m`, `h`, `d` (ex.: `60s`, `5m`, `1h`). Unidade com espaço (`1 G`) é
rejeitada com sugestão.

---

## 8. MATCH, TRIGGER, EVIDENCE e GROUP BY

- **MATCH** opera sobre **atributos do flow**
  (ex.: `proto == udp and src_port == 53 and direction == inbound`).
- **TRIGGER** opera sobre **métricas agregadas**
  (ex.: `pps >= 100k and unique_src_ips >= 500`).
- **EVIDENCE** lista o que anexar ao evento
  (ex.: `unique_src_ips, avg_packet_bytes, flows, top_src_ips`).
- **GROUP BY** usa uma **allowlist segura**; não é liberado campo arbitrário.

O validator conhece a seção de cada campo e recusa (ex.: usar `pps` no MATCH ou `src_ip`
no TRIGGER) com o código `FIELD_NOT_ALLOWED_IN_SECTION`.

### Group by — presets e campos

Presets: `conversation`, `target_conversation`, `target_port`, `prefix`, `zone`, `interface`.

Campos permitidos: `src_ip`, `dst_ip`, `src_cidr`, `dst_cidr`, `src_port`, `dst_port`,
`protocol`, `direction`, `decoder`, `sensor`, `sensor_id`, `exporter_ip`,
`interface_if_index`, `input_if`, `output_if`, `src_asn`, `dst_asn`.

Exemplos: `dst_ip` · `src_ip` · `dst_ip,src_port,proto` · `src_ip,dst_ip` · `interface`.

---

## 9. Exemplos

### 9.1 Expressões válidas (MATCH)

```text
proto == udp and src_port == 53 and direction == inbound
proto == udp and src_port in [53,123,1900,11211] and direction == inbound
proto == tcp and tcp_flags contains syn and direction == inbound
proto == tcp and tcp_flags contains syn and tcp_flags contains ack and direction == inbound
proto == icmp and direction == inbound
src_ip in 100.64.0.0/10
sensor matches "^FIBINET-"
```

### 9.2 Expressões inválidas (com o código retornado)

| Expressão | Código | Motivo |
|---|---|---|
| `src_port matches "^53$"` | `REGEX_NOT_ALLOWED` | regex só em campo textual |
| `tcp_flags > 10` | `INVALID_OPERATOR` | flags só aceitam `CONTAINS`/`NOT CONTAINS` |
| `direction == banana` | `INVALID_ENUM` | direção deve ser `inbound`/`outbound`/`both` |
| `proto == udp; DROP TABLE flow_raw` | `FORBIDDEN_CHARACTER` | a DSL nunca aceita SQL livre |
| `unknown_field == 1` | `UNKNOWN_FIELD` | campo precisa existir no dicionário |
| `bps contains syn` | `CONTAINS_REQUIRES_FLAGS` | `CONTAINS` só em flags (`tcp_flags`) |

### 9.3 Regra completa (golden)

```text
MATCH
proto == udp
AND direction == inbound
AND decoder == DNS
AND src_port == 53
AND dst_port >= 1024

WARNING
pps >= 100k OR bps >= 1G

CRITICAL
pps >= 200k OR bps >= 2G

EVIDENCE
unique_src_ips, avg_packet_bytes, flows

ADVANCED
window = 60s
consecutive = 1
group_by = target_port
dedupe = anomaly_event_default

RESPONSE
mode = manual_approval
```

O serializer é determinístico: `parse(serialize(ast))` é semanticamente igual a `ast` e
`serialize` produz sempre a mesma forma canônica (round-trip estável).

---

## 10. Flow Search por expressão

O `GET /api/flows/search` continua aceitando **todos** os filtros por coluna. De forma
aditiva, aceita `expression=<DSL>` (apenas a seção **MATCH**):

```http
GET /api/flows/search?range_minutes=60&expression=proto%20==%20udp%20and%20src_port%20==%2053
```

- Se `expression` não for informado, o comportamento antigo é **100% preservado**.
- `expression` + filtros legados são combinados com **AND**:
  `(expression) AND (filtros legados)`. A resposta devolve `expression` e
  `expression_canonical` para não haver ambiguidade silenciosa.
- Nenhuma nova agregação: o resultado continua sendo **linhas reais de `flow_raw`** com as
  colunas atuais.
- Nesta fase **não** são aceitos no Flow Search: `pps`, `bps`, `flows`, `unique_*`,
  `TRIGGER`, `GROUP BY` e `EVIDENCE` (pertencem ao modelo agregado/detector).

### 10.1 Validação/preview (somente leitura, sem executar query)

```http
GET /api/flows/expression/validate?expression=sensor%20matches%20%22%5EFIBINET-%22
```

Resposta: `valid`, `canonical_expression`, `ast` (resumida), `conditions`, `fields`,
`errors` e `warnings` estruturados. É `GET` de propósito — o preview `:8081` bloqueia
`POST` genérico.

O `GET /api/rule-language/catalog` também devolve `flow_search_allowed` por campo (calculado
a partir do schema físico do `flow_raw`), para a UI não oferecer no Dicionário campos que o
compilador recusaria (ex.: `sensor_id`, `icmp_type`, `icmp_code`, métricas agregadas).

### 10.2 Como a expressão vira SQL

```text
texto -> parse_expression() -> AST -> validate_expression(section=MATCH) -> compiler
      -> fragmento WHERE + parâmetros vinculados ({expr_0:UInt16}, ...)
```

- **Nunca** há concatenação de texto do usuário no SQL: todo valor vira parâmetro vinculado.
- `direction == inbound` → `isIPAddressInRange(dst_ip, <redes internas>)`; `outbound` →
  `src_ip`; `both` → ambos. As redes internas vêm, nesta ordem: `GMJFLOW_FLOW_INTERNAL_CIDRS`
  (override explícito) → **prefixos ativos de `ip_zones`** (mesma noção de "interno"/cliente
  que o detector e as zonas usam) → default do catálogo (RFC1918 + loopback + link-local +
  CGNAT `100.64.0.0/10` + ULA). Em ambientes com prefixos públicos de cliente, o default
  RFC1918 não representa o cliente — por isso as zonas ativas têm prioridade.
- `proto == udp` → `proto = {p:UInt8}`; `proto == ip` significa "qualquer protocolo".
- `tcp_flags contains syn` → `bitAnd(tcp_flags, {p:UInt16}) != 0` (bitmask, mesma semântica
  do detector). **Atenção:** o filtro legado `tcp_flags=syn` é **igualdade exata** — o
  resultado de `contains` é um superconjunto quando o flow tem outros bits setados
  (ex.: SYN+ACK).
- `decoder == X` reutiliza o mesmo `decoder_clickhouse_condition` do detector.
- IP/CIDR usam as mesmas funções do backend (`clickhouse_ip_string_param` /
  `clickhouse_cidr_string_param`, com o mapeamento `::ffff:` das colunas IPv6).
- Campos sem coluna física no `flow_raw` (`sensor_id`, `icmp_type`, `icmp_code`) são
  recusados com `FIELD_NOT_AVAILABLE_IN_FLOW_SEARCH` (use `sensor` ou o filtro legado
  `sensor_id`).

### 10.3 Limites de custo

Além do `range_minutes` e do `limit` já existentes:

| Limite | Valor |
|---|---|
| comprimento da expressão | 2000 caracteres |
| profundidade da AST | 12 |
| número de condições | 40 |
| itens por lista `IN`/`NOT IN` | 64 |
| tamanho da regex (`matches`) | 200 caracteres |

Violações retornam `400` com `code` estável: `EXPRESSION_TOO_LONG`, `AST_TOO_DEEP`,
`TOO_MANY_CONDITIONS`, `IN_LIST_TOO_LARGE`, `REGEX_TOO_LONG`.

### 10.4 Erros estruturados

`400` com `{"detail": {"code", "message", "errors": [{code, message, field, ...}]}}`.
Exemplos: `FORBIDDEN_CHARACTER` (SQL livre), `FIELD_NOT_ALLOWED_IN_SECTION` (usar `pps` no
Flow Search), `UNKNOWN_FIELD`, `REGEX_NOT_ALLOWED`, `CONTAINS_REQUIRES_FLAGS`.

### 10.5 Exemplos para o operador

```text
proto == udp and src_port == 53 and direction == inbound      # DNS reflection inbound
proto == udp and src_port == 123 and direction == inbound     # NTP reflection inbound
proto == udp and src_port == 1900 and direction == inbound    # SSDP inbound
proto == udp and src_port == 11211 and direction == inbound   # Memcached inbound
proto == tcp and tcp_flags contains syn and direction == inbound
proto == tcp and tcp_flags contains syn and tcp_flags contains ack and direction == inbound
proto == icmp and direction == inbound
src_ip in 100.64.0.0/10
sensor matches "^FIBINET-"
```

Esses exemplos são **queries de investigação**, não vetores.

### 10.6 Comparação legacy × expressão (dados reais, **mesmo snapshot**, 60 min)

As contagens abaixo saem de **uma única query** (`countIf`), sem desvio de tráfego:

| Consulta | Legacy | Expressão |
|---|---|---|
| `proto=udp` + `src_port=53` | 44 110 | 44 110 |
| `proto=udp` + `src_port=123` | 684 | 684 |
| `src_ip=100.64.0.0/10` | 62 133 | 62 133 |
| `dst_ip=45.163.144.0/22` (prefixo real de zona) | 135 109 | 135 109 |
| `if_index=90` | 1 068 260 | 1 068 260 |
| `expression(proto==udp)` + `src_port=53` | — | 44 152 (igual à expressão completa) |
| `tcp_flags=syn` (igualdade) | 68 183 | 107 829 (`contains syn`, bitmask) |

`direction` (sem equivalente legado) na mesma janela: `inbound` = 3 878 761,
`outbound` = 3 103 498, `both` = 6 797 575; o exemplo DNS inbound
(`proto == udp and src_port == 53 and direction == inbound`) = 26 590 linhas.

Validado também que toda linha retornada por `proto == udp and src_port == 53` tem
`proto=17` e `src_port=53`, e que `direction == inbound/outbound` não devolveu nenhuma
linha com o lado interno fora das redes de zona.

---

## 11. Segurança

- **Nunca SQL livre:** `;`, `'` e backtick são rejeitados na tokenização
  (`FORBIDDEN_CHARACTER`) antes de qualquer interpretação.
- **Regex só em texto liberado** e validada (`re.compile`); regex inválida gera erro.
- **Listas** exigem ao menos um valor (`INVALID_LIST`).
- **Sem valores mágicos:** `any` só é aceito com `==` e remove a condição.
- **Validação por tipo**: cada operador só é aceito nos tipos previstos pelo catálogo.
- **Allowlist de group_by** e de campos por seção.
- **Nada de execução em produção nesta fase**: catálogo/dicionário e parsing são puros.

---

## 12. Compatibilidade histórica

- As colunas históricas do banco (`proto`, `direction` em `anomaly_events` etc.) **não mudam**.
- A canonicalização (`transmits` → `outbound`, `proto` → `protocol`, `pps` → `packets_s`)
  acontece **só na AST**.
- O parser continua aceitando as formas legadas (`=`, `receives`, `sends`, `flows`, …); o
  serializer emite apenas a forma canônica nova (`==`, `inbound`, `flows`).
- O detector atual **não foi alterado** nesta fase.

---

## 13. Relação com Flow Search e Vetores de Ataque

- **Vetores de Ataque (hoje):** cada vetor é um conjunto de colunas fixas
  (`domain`, `direction`, `decoder`, `metric`, `comparison`, thresholds). A DSL é o
  vocabulário que permitirá representar esse mesmo vetor como regra (`MATCH` + `TRIGGER`)
  sem duplicar regra no frontend.
- **Flow Search (Fase 2, entregue):** `GET /api/flows/search` aceita filtros por coluna
  (`src_ip`, `dst_ip`, `port`, `proto`, `tcp_flags`, `decoder`, …) **e** `expression=`
  (seção `MATCH`), combinados com AND; a AST é compilada para o `WHERE` do ClickHouse com
  parâmetros vinculados. Ver seção 10.
- **Dicionário/UI:** a UI deve consumir `GET /api/rule-language/catalog`; **não** duplicar
  o catálogo no frontend.

---

## 14. Como validar / testar

```bash
python3 -m unittest tests.test_detection_dsl_catalog tests.test_detection_dsl_parser \
  tests.test_detection_dsl_roundtrip tests.test_detection_dsl_units \
  tests.test_detection_dsl_validator tests.test_detection_dsl_language \
  tests.test_detection_dsl_compiler
```

Testes cobertos: parser, aliases, canonicalização de `direction`, unidades, operador por
tipo, regex permitido/bloqueado, MATCH vs TRIGGER, group_by, campos inválidos, SQL injection
rejeitado, round-trip do serializer, dicionário, endpoint, compilador (igualdade,
desigualdade, `IN`/`NOT IN`, `BETWEEN`, CIDR, direction, flags, `matches`, AND/OR/NOT,
parênteses, aliases, parâmetros vinculados e limites de complexidade).

---

## 15. Próximos passos (Fase 3)

1. Builder visual de regras (UI) reaproveitando `catalog_json()` e o `summarize()` da AST;
2. representar os **Vetores de Ataque** existentes como `MATCH` + `TRIGGER` (sem migrar nem
   consolidar regras produtivas nesta etapa);
3. avaliar persistência versionada da AST (migration) somente quando o modelo estiver estável;
4. reavaliar o gap temporal do detector e as 28 regras duplicadas — **fora** do escopo da DSL.

Regra: qualquer alteração de arquitetura/fluxo deve atualizar este documento **no mesmo
trabalho**.
