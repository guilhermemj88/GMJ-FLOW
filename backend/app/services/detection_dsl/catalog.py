"""Catalogo/Dicionario canonico da linguagem de regras (DSL) do GMJ-FLOW.

FASE 1 - consolidacao do vocabulario. Este modulo e a fonte unica de verdade
para parser, validator, Builder visual, Dicionario da UI e (na proxima fase)
Flow Search por expressao. Nenhuma regra de dominio deve ser duplicada fora
daqui.

Regras desta fase (nao violar):

- a DSL NAO executa consulta em producao;
- nenhuma migration, nenhuma alteracao de attack_vectors / detection_template_rules;
- o detector atual permanece intocado;
- a AST pode ser canonizada, mas as colunas historicas do banco nao mudam.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import (
    CONTAINS_REQUIRES_FLAGS,
    FORBIDDEN_CHARACTER,
    INVALID_ENUM,
    INVALID_OPERATOR,
    REGEX_NOT_ALLOWED,
    UNKNOWN_FIELD,
)
from .units import UNIT_DOCUMENTATION

LANGUAGE_NAME = "gmjflow-rule-language"

# --- Secoes da linguagem ---------------------------------------------------
SECTION_MATCH = "match"
SECTION_WARNING = "warning"
SECTION_CRITICAL = "critical"
SECTION_EVIDENCE = "evidence"
SECTION_ADVANCED = "advanced"
SECTION_RESPONSE = "response"
SECTIONS = (
    SECTION_MATCH,
    SECTION_WARNING,
    SECTION_CRITICAL,
    SECTION_EVIDENCE,
    SECTION_ADVANCED,
    SECTION_RESPONSE,
)

# --- Tipos de campo --------------------------------------------------------
TYPE_METRIC = "metric"
TYPE_INT = "int"
TYPE_PORT = "port"
TYPE_ENUM = "enum"
TYPE_IP = "ip"
TYPE_CIDR = "cidr"
TYPE_FLAGS = "flags"
TYPE_TEXT = "text"
TYPE_LIST = "list"
TYPE_DERIVED = "derived"

TYPES = (
    TYPE_METRIC,
    TYPE_INT,
    TYPE_PORT,
    TYPE_ENUM,
    TYPE_IP,
    TYPE_CIDR,
    TYPE_FLAGS,
    TYPE_TEXT,
    TYPE_LIST,
    TYPE_DERIVED,
)

# --- Operadores canonicos --------------------------------------------------
OP_EQ = "=="
OP_NE = "!="
OP_GT = ">"
OP_GE = ">="
OP_LT = "<"
OP_LE = "<="
OP_IN = "IN"
OP_NOT_IN = "NOT IN"
OP_BETWEEN = "BETWEEN"
OP_CONTAINS = "CONTAINS"
OP_NOT_CONTAINS = "NOT CONTAINS"
OP_MATCHES = "MATCHES"

NUMERIC_OPERATORS = (OP_EQ, OP_NE, OP_GT, OP_GE, OP_LT, OP_LE, OP_IN, OP_NOT_IN, OP_BETWEEN)
ENUM_OPERATORS = (OP_EQ, OP_NE, OP_IN, OP_NOT_IN)
IP_OPERATORS = (OP_EQ, OP_NE, OP_IN, OP_NOT_IN)
CIDR_OPERATORS = (OP_EQ, OP_NE, OP_IN, OP_NOT_IN)
FLAGS_OPERATORS = (OP_CONTAINS, OP_NOT_CONTAINS)
TEXT_OPERATORS = (OP_EQ, OP_NE, OP_MATCHES)
LIST_OPERATORS: tuple[str, ...] = ()
DERIVED_OPERATORS = (OP_EQ, OP_NE, OP_GT, OP_GE, OP_LT, OP_LE, OP_IN, OP_NOT_IN, OP_BETWEEN)

OPERATORS_BY_TYPE: dict[str, tuple[str, ...]] = {
    TYPE_METRIC: NUMERIC_OPERATORS,
    TYPE_INT: NUMERIC_OPERATORS,
    TYPE_PORT: NUMERIC_OPERATORS,
    TYPE_ENUM: ENUM_OPERATORS,
    TYPE_IP: IP_OPERATORS,
    TYPE_CIDR: CIDR_OPERATORS,
    TYPE_FLAGS: FLAGS_OPERATORS,
    TYPE_TEXT: TEXT_OPERATORS,
    TYPE_LIST: LIST_OPERATORS,
    TYPE_DERIVED: DERIVED_OPERATORS,
}

# Aliases de entrada aceitos pelo parser. A AST/serializer sempre usam o
# operador canonico acima (nunca a forma legada).
OPERATOR_INPUT_ALIASES: dict[str, str] = {
    "=": OP_EQ,
    "==": OP_EQ,
    "EQ": OP_EQ,
    "<>": OP_NE,
    "!=": OP_NE,
    "NE": OP_NE,
    ">": OP_GT,
    ">=": OP_GE,
    "<": OP_LT,
    "<=": OP_LE,
    "IN": OP_IN,
    "NOT IN": OP_NOT_IN,
    "BETWEEN": OP_BETWEEN,
    "CONTAINS": OP_CONTAINS,
    "NOT CONTAINS": OP_NOT_CONTAINS,
    "MATCHES": OP_MATCHES,
}


def canonical_operator(token: str) -> str | None:
    """Normaliza um operador de entrada (ex.: '=' -> '==')."""
    raw = str(token).strip()
    if raw in OPERATOR_INPUT_ALIASES:
        return OPERATOR_INPUT_ALIASES[raw]
    upper = raw.upper()
    if upper in OPERATOR_INPUT_ALIASES:
        return OPERATOR_INPUT_ALIASES[upper]
    return None


OPERATOR_DOCUMENTATION = (
    {"op": OP_EQ, "label": "igual", "types": ("int", "port", "metric", "derived", "enum", "ip", "cidr", "text"),
     "example": "proto == udp"},
    {"op": OP_NE, "label": "diferente", "types": ("int", "port", "metric", "derived", "enum", "ip", "cidr", "text"),
     "example": "direction != outbound"},
    {"op": OP_GT, "label": "maior que", "types": ("int", "port", "metric", "derived"), "example": "dst_port > 1024"},
    {"op": OP_GE, "label": "maior ou igual", "types": ("int", "port", "metric", "derived"), "example": "pps >= 100k"},
    {"op": OP_LT, "label": "menor que", "types": ("int", "port", "metric", "derived"), "example": "packets < 10"},
    {"op": OP_LE, "label": "menor ou igual", "types": ("int", "port", "metric", "derived"), "example": "bps <= 1G"},
    {"op": OP_IN, "label": "pertence a lista/CIDR", "types": ("int", "port", "metric", "derived", "enum", "ip", "cidr"),
     "example": "src_port in [53,123,1900]"},
    {"op": OP_NOT_IN, "label": "nao pertence a lista", "types": ("int", "port", "metric", "derived", "enum", "ip", "cidr"),
     "example": "src_port not in [53,123]"},
    {"op": OP_BETWEEN, "label": "intervalo inclusivo", "types": ("int", "port", "metric", "derived"),
     "example": "dst_port between 1024 and 65535"},
    {"op": OP_CONTAINS, "label": "contem flag", "types": ("flags",), "example": "tcp_flags contains syn"},
    {"op": OP_NOT_CONTAINS, "label": "nao contem flag", "types": ("flags",), "example": "tcp_flags not contains rst"},
    {"op": OP_MATCHES, "label": "regex (somente texto)", "types": ("text",), "example": 'sensor matches "^FIBINET-"'},
)

STATUS_SUPPORTED = "supported"
STATUS_EXPERIMENTAL = "experimental"
STATUS_UNAVAILABLE = "unavailable"

EXPORTER_RELIABLE = "reliable"
EXPORTER_UNVERIFIED = "unverified"
EXPORTER_UNKNOWN = "unknown"

CAPABILITY_STATUSES = (STATUS_SUPPORTED, STATUS_EXPERIMENTAL, STATUS_UNAVAILABLE)


@dataclass(frozen=True)
class CapabilitySpec:
    name: str
    status: str
    description: str


CAPABILITIES: dict[str, CapabilitySpec] = {
    "conversation_grouping": CapabilitySpec(
        "conversation_grouping", STATUS_SUPPORTED, "Agrupamento por conversa (src+dst+porta+protocolo)."
    ),
    "prefix_aggregation": CapabilitySpec(
        "prefix_aggregation", STATUS_SUPPORTED, "Agregacao por prefixo/CIDR."
    ),
    "tcp_flags": CapabilitySpec(
        "tcp_flags", STATUS_EXPERIMENTAL, "Filtro por flags TCP; nem todo exporter entrega flags confiaveis."
    ),
    "derived_metric_avg_packet_bytes": CapabilitySpec(
        "derived_metric_avg_packet_bytes",
        STATUS_SUPPORTED,
        "Metrica derivada sum(bytes)/sum(packets); indefinida quando packets=0.",
    ),
    "custom_dedupe": CapabilitySpec("custom_dedupe", STATUS_SUPPORTED, "Perfil de dedupe customizado."),
    "response_profile": CapabilitySpec(
        "response_profile", STATUS_SUPPORTED, "Vinculo com response profile cadastrado."
    ),
    "flowspec_dns_block": CapabilitySpec(
        "flowspec_dns_block", STATUS_UNAVAILABLE, "Mitigacao FlowSpec DNS (Fase 3B, ainda nao integrada)."
    ),
}


@dataclass(frozen=True)
class FieldSpec:
    """Metadados de um campo do dicionario V1.

    `sections` continua sendo a fonte de verdade de onde o campo pode aparecer;
    as flags `match_allowed`/`trigger_allowed`/`evidence_allowed`/`group_by_allowed`
    sao derivadas para consumo da UI/API (nunca duplicar manualmente).
    """

    name: str
    label: str
    description: str
    type: str
    sections: tuple[str, ...]
    operators: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    text_name: str = ""
    unit: str | None = None
    enum_values: tuple[str, ...] = ()
    capability: str | None = None
    status: str = STATUS_SUPPORTED
    introduced: str = "fase1"
    origin: str = "flow_raw"
    examples: tuple[str, ...] = ()
    clickhouse: str = "flow_raw"
    exporter_reliability: str = EXPORTER_UNKNOWN
    regex_allowed: bool = False
    notes: str = ""

    @property
    def display_name(self) -> str:
        return self.text_name or self.name

    @property
    def in_match(self) -> bool:
        return SECTION_MATCH in self.sections

    @property
    def in_trigger(self) -> bool:
        return SECTION_WARNING in self.sections or SECTION_CRITICAL in self.sections

    @property
    def in_evidence(self) -> bool:
        return SECTION_EVIDENCE in self.sections

    @property
    def in_group_by(self) -> bool:
        return self.name in GROUP_BY_ALLOWED_FIELDS

    # Nomes explicitos exigidos pelo Dicionario/API.
    @property
    def match_allowed(self) -> bool:
        return self.in_match

    @property
    def trigger_allowed(self) -> bool:
        return self.in_trigger

    @property
    def evidence_allowed(self) -> bool:
        return self.in_evidence

    @property
    def group_by_allowed(self) -> bool:
        return self.in_group_by

    def all_input_names(self) -> tuple[str, ...]:
        names = {self.name, self.display_name, *self.aliases}
        return tuple(sorted(names))


def _field(
    name: str,
    label: str,
    description: str,
    type_: str,
    sections: tuple[str, ...],
    **kwargs: Any,
) -> FieldSpec:
    operators = kwargs.pop("operators", OPERATORS_BY_TYPE.get(type_, ()))
    return FieldSpec(
        name=name,
        label=label,
        description=description,
        type=type_,
        sections=sections,
        operators=operators,
        **kwargs,
    )


_MATCH = (SECTION_MATCH,)
_TRIGGER = (SECTION_WARNING, SECTION_CRITICAL)
_EVIDENCE = (SECTION_EVIDENCE,)
_TRIGGER_EVIDENCE = (SECTION_WARNING, SECTION_CRITICAL, SECTION_EVIDENCE)
_MATCH_EVIDENCE = (SECTION_MATCH, SECTION_EVIDENCE)

FIELDS: dict[str, FieldSpec] = {}


def _register(spec: FieldSpec) -> None:
    FIELDS[spec.name] = spec


# --- MATCH: atributos do flow ---------------------------------------------
_register(_field(
    "protocol", "Protocolo", "Protocolo de transporte/IP (proto).", TYPE_ENUM, _MATCH,
    enum_values=("tcp", "udp", "icmp", "ip"), text_name="proto", aliases=("proto",),
    origin="flow_raw(proto)", examples=("proto == udp", "proto in [tcp,udp]"),
    notes="Coluna numerica no banco; canonicalizada para nome na AST.",
))
_register(_field(
    "direction", "Direcao", "Direcao do trafego em relacao ao alvo interno.", TYPE_ENUM, _MATCH,
    enum_values=("inbound", "outbound", "both"),
    aliases=("receives", "transmits", "sends", "download", "upload", "in", "out", "entrando", "saindo"),
    origin="derived(direction)", clickhouse="derived",
    examples=("direction == inbound", "direction == sends"),
    notes="receives=inbound (dst interno); transmits/sends=outbound (src interno).",
))
_register(_field(
    "decoder", "Decoder", "Classificacao de primeira classe do sistema.", TYPE_ENUM, _MATCH,
    enum_values=(
        "DNS", "NTP", "SSDP", "CLDAP", "CHARGEN", "MEMCACHED", "QUIC", "UDP+QUIC",
        "HTTP", "HTTPS", "MAIL", "SIP", "IPSEC", "NETBIOS", "IP", "TCP", "TCP+SYN",
        "TCP+SYNACK", "TCP+ACK", "TCP+RST", "TCP+NULL", "TCP+ALL", "UDP", "ICMP",
        "GRE", "ESP", "FLOW+SYN", "FLOWS", "OTHER",
    ),
    origin="derived(decoder)", clickhouse="derived", examples=("decoder == DNS",),
))
_register(_field("src_ip", "IP origem", "IP de origem do flow.", TYPE_IP, _MATCH,
                 examples=("src_ip == 10.0.0.1", "src_ip in [10.0.0.0/8]")))
_register(_field("dst_ip", "IP destino", "IP de destino do flow.", TYPE_IP, _MATCH,
                 examples=("dst_ip == 200.160.0.1",)))
_register(_field("src_cidr", "CIDR origem", "Prefixo de origem.", TYPE_CIDR, _MATCH,
                 examples=("src_cidr == 100.64.0.0/10",)))
_register(_field("dst_cidr", "CIDR destino", "Prefixo de destino.", TYPE_CIDR, _MATCH,
                 examples=("dst_cidr == 192.168.0.0/24",)))
_register(_field("src_port", "Porta origem", "Porta de origem (0-65535).", TYPE_PORT, _MATCH,
                 examples=("src_port == 53", "src_port in [53,123,1900,11211]")))
_register(_field("dst_port", "Porta destino", "Porta de destino (0-65535).", TYPE_PORT, _MATCH,
                 examples=("dst_port >= 1024", "dst_port between 1024 and 65535")))
_register(_field(
    "tcp_flags", "Flags TCP", "Flags TCP do flow (experimental).", TYPE_FLAGS, _MATCH,
    capability="tcp_flags", status=STATUS_EXPERIMENTAL, origin="flow_raw(tcp_flags)",
    exporter_reliability=EXPORTER_UNVERIFIED, examples=("tcp_flags contains syn",),
    notes="Somente CONTAINS/NOT CONTAINS; comparacao numerica nao e permitida.",
))
_register(_field(
    "sensor", "Sensor", "Nome do sensor/coletor (texto).", TYPE_TEXT, _MATCH,
    aliases=("sensor_name",), origin="flow_raw(sensor)", exporter_reliability=EXPORTER_RELIABLE,
    regex_allowed=True, examples=('sensor matches "^FIBINET-"', "sensor == SENSOR-BHE-F1A"),
    notes="Unico campo textual que aceita MATCHES (regex ancorado).",
))
_register(_field("sensor_id", "Sensor (id)", "Id do sensor/coletor.", TYPE_INT, _MATCH,
                 origin="flow_raw(sensor_id)", examples=("sensor_id == 3",)))
_register(_field("exporter_ip", "IP do exporter", "IP do exporter que enviou o flow.", TYPE_IP, _MATCH,
                 origin="flow_raw(exporter_ip)", examples=("exporter_ip == 10.20.0.5",)))
_register(_field("input_if", "Interface de entrada", "ifIndex de entrada.", TYPE_INT, _MATCH,
                 aliases=("in_if",), examples=("input_if == 12",)))
_register(_field("output_if", "Interface de saida", "ifIndex de saida.", TYPE_INT, _MATCH,
                 aliases=("out_if",), examples=("output_if == 12",)))
_register(_field("interface_if_index", "Interface (ifIndex)", "ifIndex da interface (alias de input_if).",
                 TYPE_INT, _MATCH, notes="Mantido por compatibilidade com a AST da Fase 3A."))
_register(_field("src_asn", "ASN origem", "ASN de origem.", TYPE_INT, _MATCH,
                 aliases=("asn_src", "src_as"), examples=("src_asn == 65000",)))
_register(_field("dst_asn", "ASN destino", "ASN de destino.", TYPE_INT, _MATCH,
                 aliases=("asn_dst", "dst_as"), examples=("dst_asn == 65000",)))
_register(_field("icmp_type", "ICMP type", "Tipo ICMP.", TYPE_INT, _MATCH, examples=("icmp_type == 8",)))
_register(_field("icmp_code", "ICMP code", "Codigo ICMP.", TYPE_INT, _MATCH, examples=("icmp_code == 0",)))
_register(_field("flow_count", "Flows", "Numero de flows agregados no registro.", TYPE_INT, _MATCH_EVIDENCE,
                 aliases=("flows_count",), examples=("flow_count >= 100",)))
_register(_field("bytes", "Bytes", "Total de bytes no periodo/flow.", TYPE_INT, _MATCH_EVIDENCE,
                 examples=("bytes >= 1M",)))
_register(_field("packets", "Pacotes", "Total de pacotes no periodo/flow.", TYPE_INT, _MATCH_EVIDENCE,
                 examples=("packets >= 1000",)))

# --- TRIGGER: metricas agregadas ------------------------------------------
_register(_field("packets_s", "PPS", "Pacotes por segundo.", TYPE_METRIC, _TRIGGER_EVIDENCE,
                 aliases=("pps",), text_name="pps", unit="pps",
                 origin="derived(sum packets / janela)", clickhouse="derived",
                 examples=("pps >= 100k",)))
_register(_field("bits_s", "BPS", "Bits por segundo.", TYPE_METRIC, _TRIGGER_EVIDENCE,
                 aliases=("bps",), text_name="bps", unit="bps",
                 origin="derived(sum bytes * 8 / janela)", clickhouse="derived",
                 examples=("bps >= 1G",)))
_register(_field("flows_s", "Flows/s", "Flows por segundo.", TYPE_METRIC, _TRIGGER_EVIDENCE,
                 aliases=("flows",), text_name="flows", unit="flows",
                 origin="derived(sum flow_count / janela)", clickhouse="derived",
                 examples=("flows >= 10",)))
_register(_field("unique_src_ips", "IPs origem unicos", "IPs de origem distintos observados.",
                 TYPE_INT, _TRIGGER_EVIDENCE, aliases=("unique_src", "unique_sources"),
                 origin="derived(countDistinct src_ip)", clickhouse="derived", examples=("unique_src_ips >= 500",)))
_register(_field("unique_dst_ips", "IPs destino unicos", "IPs de destino distintos observados.",
                 TYPE_INT, _TRIGGER_EVIDENCE, aliases=("unique_dst", "unique_destinations"),
                 origin="derived(countDistinct dst_ip)", clickhouse="derived"))
_register(_field("unique_src_ports", "Portas origem unicas", "Portas de origem distintas observadas.",
                 TYPE_INT, _TRIGGER_EVIDENCE, aliases=("unique_src_port",),
                 origin="derived(countDistinct src_port)", clickhouse="derived"))
_register(_field("unique_dst_ports", "Portas destino unicas", "Portas de destino distintas observadas.",
                 TYPE_INT, _TRIGGER_EVIDENCE, aliases=("unique_dst_port",),
                 origin="derived(countDistinct dst_port)", clickhouse="derived"))

# --- EVIDENCE --------------------------------------------------------------
_register(_field("avg_packet_bytes", "Media de bytes/pacote",
                 "Metrica derivada sum(bytes)/sum(packets); indefinida quando packets=0.",
                 TYPE_DERIVED, _TRIGGER_EVIDENCE, capability="derived_metric_avg_packet_bytes",
                 origin="derived(sum bytes / sum packets)", clickhouse="derived",
                 examples=("avg_packet_bytes >= 1000",),
                 notes=("Aceito em TRIGGER desde a Fase 4 (motor de triggers booleanos, 2026-10-06); "
                        "nunca e media de medias por flow.")))
_register(_field("top_src_ips", "Top IPs origem", "Top IPs de origem (lista).", TYPE_LIST, _EVIDENCE,
                 origin="derived(topK src_ip)", clickhouse="derived"))
_register(_field("top_dst_ips", "Top IPs destino", "Top IPs de destino (lista).", TYPE_LIST, _EVIDENCE,
                 origin="derived(topK dst_ip)", clickhouse="derived"))
_register(_field("top_src_ports", "Top portas origem", "Top portas de origem (lista).", TYPE_LIST, _EVIDENCE,
                 origin="derived(topK src_port)", clickhouse="derived"))
_register(_field("top_dst_ports", "Top portas destino", "Top portas de destino (lista).", TYPE_LIST, _EVIDENCE,
                 origin="derived(topK dst_port)", clickhouse="derived"))

# Alias -> nome canonico.
FIELD_ALIASES: dict[str, str] = {}
for _spec in FIELDS.values():
    for _name in _spec.all_input_names():
        FIELD_ALIASES.setdefault(_name.lower(), _spec.name)


def resolve_field(name: str) -> FieldSpec | None:
    canonical = FIELD_ALIASES.get(str(name).strip().lower())
    return FIELDS.get(canonical) if canonical else None


# --- Direcao ---------------------------------------------------------------
DIRECTION_CANONICAL = ("inbound", "outbound", "both")
DIRECTION_ALIASES: dict[str, str] = {
    "inbound": "inbound",
    "receives": "inbound",
    "download": "inbound",
    "in": "inbound",
    "entrando": "inbound",
    "outbound": "outbound",
    "sends": "outbound",
    "transmits": "outbound",
    "upload": "outbound",
    "out": "outbound",
    "saindo": "outbound",
    "both": "both",
}


def canonical_direction(value: str) -> str | None:
    return DIRECTION_ALIASES.get(str(value).strip().lower())


# --- Decoder ---------------------------------------------------------------
DECODER_CANONICAL = FIELDS["decoder"].enum_values
_DECODER_LOOKUP = {name.lower(): name for name in DECODER_CANONICAL}


def canonical_decoder(value: str) -> str | None:
    return _DECODER_LOOKUP.get(str(value).strip().lower())


# --- Protocolo -------------------------------------------------------------
PROTOCOL_CANONICAL = FIELDS["protocol"].enum_values


def canonical_protocol(value: str) -> str | None:
    lowered = str(value).strip().lower()
    return lowered if lowered in PROTOCOL_CANONICAL else None


# --- Group by --------------------------------------------------------------
GROUP_BY_PRESETS = ("conversation", "target_conversation", "target_port", "prefix", "zone", "interface")
GROUP_BY_ALLOWED_FIELDS = (
    "src_ip", "dst_ip", "src_cidr", "dst_cidr", "src_port", "dst_port",
    "protocol", "direction", "decoder", "sensor", "sensor_id", "exporter_ip",
    "interface_if_index", "input_if", "output_if", "src_asn", "dst_asn",
)
GROUP_BY_EXAMPLES = (
    "dst_ip",
    "src_ip",
    "dst_ip,src_port,proto",
    "src_ip,dst_ip",
    "interface",
)

# --- Dedupe / Response -----------------------------------------------------
DEDUPE_PROFILES = ("anomaly_event_default", "security_anomaly_default", "dns_single_flow")
RESPONSE_MODES = ("detection_only", "suggest_only", "manual_approval", "auto")

# --- AST -------------------------------------------------------------------
AST_VERSION = 1


def capability_status(name: str) -> str | None:
    spec = CAPABILITIES.get(str(name).strip())
    return spec.status if spec else None


def _field_json(spec: FieldSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "text_name": spec.display_name,
        "aliases": list(spec.aliases),
        "label": spec.label,
        "description": spec.description,
        "type": spec.type,
        "sections": list(spec.sections),
        "operators": list(spec.operators),
        "unit": spec.unit,
        "enum_values": list(spec.enum_values),
        "capability": spec.capability,
        "status": spec.status,
        "introduced": spec.introduced,
        "origin": spec.origin,
        "examples": list(spec.examples),
        "clickhouse": spec.clickhouse,
        "exporter_reliability": spec.exporter_reliability,
        "match_allowed": spec.match_allowed,
        "group_by_allowed": spec.group_by_allowed,
        "trigger_allowed": spec.trigger_allowed,
        "evidence_allowed": spec.evidence_allowed,
        "regex_allowed": spec.regex_allowed,
        "notes": spec.notes,
    }


def catalog_json() -> dict[str, Any]:
    """JSON serializavel que alimenta GET /api/rule-language/catalog.

    Nao duplicar este conteudo no frontend: a UI deve consumir este endpoint.
    """
    return {
        "language": LANGUAGE_NAME,
        "ast_version": AST_VERSION,
        "sections": list(SECTIONS),
        "types": list(TYPES),
        "operators": [dict(item) for item in OPERATOR_DOCUMENTATION],
        "operators_by_type": {type_: list(ops) for type_, ops in OPERATORS_BY_TYPE.items()},
        "operator_aliases": dict(OPERATOR_INPUT_ALIASES),
        "fields": [_field_json(spec) for spec in sorted(FIELDS.values(), key=lambda item: item.name)],
        "directions": {
            "canonical": list(DIRECTION_CANONICAL),
            "aliases": dict(DIRECTION_ALIASES),
        },
        "decoders": list(DECODER_CANONICAL),
        "protocols": list(PROTOCOL_CANONICAL),
        "group_by": {
            "presets": list(GROUP_BY_PRESETS),
            "allowed_fields": list(GROUP_BY_ALLOWED_FIELDS),
            "examples": list(GROUP_BY_EXAMPLES),
        },
        "dedupe_profiles": list(DEDUPE_PROFILES),
        "response_modes": list(RESPONSE_MODES),
        "capabilities": [
            {"name": spec.name, "status": spec.status, "description": spec.description}
            for spec in CAPABILITIES.values()
        ],
        "units": [dict(item) for item in UNIT_DOCUMENTATION],
        "examples": {
            "rules": dict(EXAMPLES),
            "valid": list(VALID_EXAMPLES),
            "invalid": [dict(item) for item in INVALID_EXAMPLES],
        },
    }


# --- Exemplos golden (regras completas) ------------------------------------
GOLDEN_DNS_RULE = """MATCH
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
mode = manual_approval"""

# Aliases historicos aceitos no texto continuam validos (ex.: protocol = udp),
# mas o serializer sempre emite a forma canonica acima.
GOLDEN_NTP_RULE = GOLDEN_DNS_RULE.replace("decoder == DNS", "decoder == NTP").replace(
    "src_port == 53", "src_port == 123"
)

EXAMPLES: dict[str, str] = {
    "dns_reflection": GOLDEN_DNS_RULE,
    "ntp_reflection": GOLDEN_NTP_RULE,
}

# --- Exemplos de expressao (secao MATCH) -----------------------------------
VALID_EXAMPLES: tuple[str, ...] = (
    "proto == udp and src_port == 53 and direction == inbound",
    "proto == udp and src_port in [53,123,1900,11211] and direction == inbound",
    "proto == tcp and tcp_flags contains syn and direction == inbound",
    "proto == tcp\nand tcp_flags contains syn\nand tcp_flags contains ack\nand direction == inbound",
    "proto == icmp and direction == inbound",
    "src_ip in 100.64.0.0/10",
    'sensor matches "^FIBINET-"',
)

INVALID_EXAMPLES: tuple[dict[str, str], ...] = (
    {"expression": 'src_port matches "^53$"', "code": REGEX_NOT_ALLOWED,
     "reason": "regex (MATCHES) so e permitido em campo textual (ex.: sensor)"},
    {"expression": "tcp_flags > 10", "code": INVALID_OPERATOR,
     "reason": "tcp_flags aceita apenas CONTAINS/NOT CONTAINS"},
    {"expression": "direction == banana", "code": INVALID_ENUM,
     "reason": "direcao deve ser inbound/outbound/both (aliases: receives/transmits/sends)"},
    {"expression": "proto == udp; DROP TABLE flow_raw", "code": FORBIDDEN_CHARACTER,
     "reason": "a DSL nunca aceita SQL livre"},
    {"expression": "unknown_field == 1", "code": UNKNOWN_FIELD,
     "reason": "campo precisa existir no dicionario"},
    {"expression": "bps contains syn", "code": CONTAINS_REQUIRES_FLAGS,
     "reason": "CONTAINS so e permitido em campo de flags (tcp_flags)"},
)
