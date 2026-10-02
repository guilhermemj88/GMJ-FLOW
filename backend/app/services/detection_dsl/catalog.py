"""Catalogo unico de metadados da DSL (campos, operadores, unidades, etc.).

Esta e a fonte de verdade para parser, validator, Builder e Dicionario. Nada de
regra duplicada entre parser e validator.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .units import UNIT_DOCUMENTATION

# Secoes da linguagem.
SECTION_MATCH = "match"
SECTION_WARNING = "warning"
SECTION_CRITICAL = "critical"
SECTION_EVIDENCE = "evidence"
SECTION_ADVANCED = "advanced"
SECTION_RESPONSE = "response"
SECTIONS = (SECTION_MATCH, SECTION_WARNING, SECTION_CRITICAL, SECTION_EVIDENCE, SECTION_ADVANCED, SECTION_RESPONSE)

# Tipos de campo.
TYPE_METRIC = "metric"
TYPE_INT = "int"
TYPE_PORT = "port"
TYPE_ENUM = "enum"
TYPE_IP = "ip"
TYPE_CIDR = "cidr"
TYPE_FLAGS = "flags"
TYPE_DERIVED = "derived"

# Operadores permitidos por tipo.
NUMERIC_OPERATORS = ("=", "!=", ">", ">=", "<", "<=", "IN", "NOT IN", "BETWEEN")
ENUM_OPERATORS = ("=", "!=", "IN", "NOT IN")
IP_OPERATORS = ("=", "!=", "IN", "NOT IN")
CIDR_OPERATORS = ("=", "!=", "IN", "NOT IN")
FLAGS_OPERATORS = ("=", "!=", "IN", "NOT IN")

OPERATORS_BY_TYPE: dict[str, tuple[str, ...]] = {
    TYPE_METRIC: NUMERIC_OPERATORS,
    TYPE_INT: NUMERIC_OPERATORS,
    TYPE_PORT: NUMERIC_OPERATORS,
    TYPE_ENUM: ENUM_OPERATORS,
    TYPE_IP: IP_OPERATORS,
    TYPE_CIDR: CIDR_OPERATORS,
    TYPE_FLAGS: FLAGS_OPERATORS,
    TYPE_DERIVED: NUMERIC_OPERATORS,
}

STATUS_SUPPORTED = "supported"
STATUS_EXPERIMENTAL = "experimental"
STATUS_UNAVAILABLE = "unavailable"

# Capabilities (registro). "unavailable" tambem cobre o que ainda nao existe
# nesta fase (ex.: mitigacao/FlowSpec DNS).
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
    introduced: str = "3a"

    @property
    def display_name(self) -> str:
        return self.text_name or self.name

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
    return FieldSpec(name=name, label=label, description=description, type=type_, sections=sections, operators=operators, **kwargs)


_MATCH = (SECTION_MATCH,)
_TRIGGER = (SECTION_WARNING, SECTION_CRITICAL)
_EVIDENCE = (SECTION_EVIDENCE,)
_TRIGGER_EVIDENCE = (SECTION_WARNING, SECTION_CRITICAL, SECTION_EVIDENCE)

FIELDS: dict[str, FieldSpec] = {}


def _register(spec: FieldSpec) -> None:
    FIELDS[spec.name] = spec


# --- MATCH ---
_register(_field("protocol", "Protocolo", "Protocolo de transporte/IP.", TYPE_ENUM, _MATCH,
                 enum_values=("tcp", "udp", "icmp", "ip")))
_register(_field("direction", "Direcao", "Direcao do trafego.", TYPE_ENUM, _MATCH,
                 enum_values=("inbound", "outbound", "both")))
_register(_field("decoder", "Decoder", "Classificacao de primeira classe do sistema.",
                 TYPE_ENUM, _MATCH,
                 enum_values=("DNS", "NTP", "UDP", "IP", "TCP", "TCP+SYN", "TCP+SYNACK", "ICMP", "FLOWS")))
_register(_field("src_ip", "IP origem", "IP de origem.", TYPE_IP, _MATCH))
_register(_field("dst_ip", "IP destino", "IP de destino.", TYPE_IP, _MATCH))
_register(_field("src_cidr", "CIDR origem", "Prefixo de origem.", TYPE_CIDR, _MATCH))
_register(_field("dst_cidr", "CIDR destino", "Prefixo de destino.", TYPE_CIDR, _MATCH))
_register(_field("src_port", "Porta origem", "Porta de origem (0-65535).", TYPE_PORT, _MATCH))
_register(_field("dst_port", "Porta destino", "Porta de destino (0-65535).", TYPE_PORT, _MATCH))
_register(_field("sensor_id", "Sensor", "Id do sensor/coletor.", TYPE_INT, _MATCH))
_register(_field("interface_if_index", "Interface (ifIndex)", "ifIndex da interface.", TYPE_INT, _MATCH))
_register(_field("input_if", "Interface de entrada", "ifIndex de entrada.", TYPE_INT, _MATCH))
_register(_field("output_if", "Interface de saida", "ifIndex de saida.", TYPE_INT, _MATCH))
_register(_field("icmp_type", "ICMP type", "Tipo ICMP.", TYPE_INT, _MATCH))
_register(_field("icmp_code", "ICMP code", "Codigo ICMP.", TYPE_INT, _MATCH))
_register(_field("tcp_flags", "Flags TCP", "Flags TCP (experimental).", TYPE_FLAGS, _MATCH,
                 capability="tcp_flags", status=STATUS_EXPERIMENTAL))

# --- TRIGGERS ---
_register(_field("packets_s", "PPS", "Pacotes por segundo.", TYPE_METRIC, _TRIGGER,
                 aliases=("pps",), text_name="pps", unit="pps"))
_register(_field("bits_s", "BPS", "Bits por segundo.", TYPE_METRIC, _TRIGGER,
                 aliases=("bps",), text_name="bps", unit="bps"))
_register(_field("flows_s", "Flows", "Flows por segundo.", TYPE_METRIC, _TRIGGER_EVIDENCE,
                 aliases=("flows",), text_name="flows", unit="flows"))
_register(_field("unique_src", "Unique src", "Origems unicas observadas.", TYPE_INT, _TRIGGER_EVIDENCE,
                 aliases=("unique_sources",)))
_register(_field("unique_dst", "Unique dst", "Destinos unicos observados.", TYPE_INT, _TRIGGER_EVIDENCE,
                 aliases=("unique_destinations",)))

# --- EVIDENCE ---
_register(_field("avg_packet_bytes", "Media de bytes/pacote",
                 "Metrica derivada sum(bytes)/sum(packets); indefinida quando packets=0.",
                 TYPE_DERIVED, _EVIDENCE, capability="derived_metric_avg_packet_bytes"))
_register(_field("bytes", "Bytes", "Total de bytes no periodo.", TYPE_INT, _EVIDENCE))
_register(_field("packets", "Pacotes", "Total de pacotes no periodo.", TYPE_INT, _EVIDENCE))

# Alias -> nome canonico.
FIELD_ALIASES: dict[str, str] = {}
for _spec in FIELDS.values():
    for _name in _spec.all_input_names():
        FIELD_ALIASES.setdefault(_name.lower(), _spec.name)


def resolve_field(name: str) -> FieldSpec | None:
    canonical = FIELD_ALIASES.get(str(name).strip().lower())
    return FIELDS.get(canonical) if canonical else None


# --- Direcao ---
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


# --- Decoder ---
DECODER_CANONICAL = ("DNS", "NTP", "UDP", "IP", "TCP", "TCP+SYN", "TCP+SYNACK", "ICMP", "FLOWS")
_DECODER_LOOKUP = {name.lower(): name for name in DECODER_CANONICAL}


def canonical_decoder(value: str) -> str | None:
    return _DECODER_LOOKUP.get(str(value).strip().lower())


# --- Protocolo ---
PROTOCOL_CANONICAL = ("tcp", "udp", "icmp", "ip")


def canonical_protocol(value: str) -> str | None:
    lowered = str(value).strip().lower()
    return lowered if lowered in PROTOCOL_CANONICAL else None


# --- Group by ---
GROUP_BY_PRESETS = ("conversation", "target_conversation", "target_port", "prefix", "zone")
GROUP_BY_ALLOWED_FIELDS = (
    "src_ip", "dst_ip", "src_cidr", "dst_cidr", "src_port", "dst_port",
    "protocol", "direction", "decoder", "sensor_id", "interface_if_index",
    "input_if", "output_if",
)

# --- Dedupe / Response ---
DEDUPE_PROFILES = ("anomaly_event_default", "security_anomaly_default", "dns_single_flow")
RESPONSE_MODES = ("detection_only", "suggest_only", "manual_approval", "auto")

# --- AST ---
AST_VERSION = 1


def capability_status(name: str) -> str | None:
    spec = CAPABILITIES.get(str(name).strip())
    return spec.status if spec else None


def catalog_json() -> dict[str, Any]:
    """JSON serializavel que alimentara GET /api/.../rule-language/catalog."""
    return {
        "ast_version": AST_VERSION,
        "sections": list(SECTIONS),
        "fields": [
            {
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
            }
            for spec in sorted(FIELDS.values(), key=lambda item: item.name)
        ],
        "operators_by_type": {type_: list(ops) for type_, ops in OPERATORS_BY_TYPE.items()},
        "directions": {
            "canonical": list(DIRECTION_CANONICAL),
            "aliases": dict(DIRECTION_ALIASES),
        },
        "decoders": list(DECODER_CANONICAL),
        "protocols": list(PROTOCOL_CANONICAL),
        "group_by": {
            "presets": list(GROUP_BY_PRESETS),
            "allowed_fields": list(GROUP_BY_ALLOWED_FIELDS),
        },
        "dedupe_profiles": list(DEDUPE_PROFILES),
        "response_modes": list(RESPONSE_MODES),
        "capabilities": [
            {"name": spec.name, "status": spec.status, "description": spec.description}
            for spec in CAPABILITIES.values()
        ],
        "units": list(UNIT_DOCUMENTATION),
        "examples": dict(EXAMPLES),
    }


GOLDEN_DNS_RULE = """MATCH
protocol = udp
AND direction = inbound
AND decoder = DNS
AND src_port = 53
AND dst_port >= 1024

WARNING
pps >= 100k OR bps >= 1G

CRITICAL
pps >= 200k OR bps >= 2G

EVIDENCE
unique_src, avg_packet_bytes, flows

ADVANCED
window = 60s
consecutive = 1
group_by = target_port
dedupe = anomaly_event_default

RESPONSE
mode = manual_approval"""


GOLDEN_NTP_RULE = GOLDEN_DNS_RULE.replace("decoder = DNS", "decoder = NTP").replace("src_port = 53", "src_port = 123")

EXAMPLES: dict[str, str] = {
    "dns_reflection": GOLDEN_DNS_RULE,
    "ntp_reflection": GOLDEN_NTP_RULE,
}
