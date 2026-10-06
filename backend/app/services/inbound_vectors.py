"""Presets de vetores inbound/download (reflection, query flood e floods).

Catalogo em CODIGO (nao grava regras, nao ativa nada): cada preset descreve
MATCH, GROUP BY, TRIGGER (WARNING/CRITICAL booleanos na DSL), EVIDENCE e WINDOW,
e sabe gerar o payload de `detection_template_rules` para materializacao manual.

ATENCAO: nenhum preset e ativado por este modulo. `preset_rule_payload` gera
payloads com `enabled=False`; ativacao em producao exige decisao explicita do
operador (replay historico + revisao de falsos positivos).

Vocabulario canonico da DSL: `direction == inbound` (alias historico
`receives`). O payload usa o formato do motor atual (`receives`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator

# Portas classicas de reflexao/amplificacao conhecidas (documentacao e
# dicionario). NAO existe uma regra generica unica: cada familia tem seu preset
# nomeado, como pedido no plano de vetores inbound.
REFLECTION_PORTS: tuple[int, ...] = (19, 53, 123, 137, 389, 1900, 3702, 5353, 11211)
REFLECTION_PORT_LABELS: dict[int, str] = {
    19: "CHARGEN",
    53: "DNS",
    123: "NTP",
    137: "NetBIOS",
    389: "CLDAP",
    1900: "SSDP",
    3702: "WS-Discovery",
    5353: "mDNS",
    11211: "Memcached",
}

WINDOW_OPTIONS: tuple[int, ...] = (30, 60)
DEFAULT_WINDOW_SECONDS = 60


@dataclass(frozen=True)
class InboundVectorPreset:
    id: str
    name: str
    family: str
    description: str
    protocol: str
    direction: str = "receives"
    src_port: str = "any"
    dst_port: str = "any"
    metric: str = "packets_s"
    warning_value: float = 0.0
    critical_value: float = 0.0
    warning_expr: str = ""
    critical_expr: str = ""
    multi_target: bool = True
    warning_multi_expr: str = ""
    critical_multi_expr: str = ""
    warning_multi_value: float = 0.0
    critical_multi_value: float = 0.0
    evidence: tuple[str, ...] = ()
    match_dsl: str = ""
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    multi_mode_note: str = ""

    def vector_name(self, multi: bool = False) -> str:
        base = f"{self.id.upper()}_INBOUND"
        return f"{base}_MULTI" if multi else base

    def supports_multi(self) -> bool:
        return bool(self.multi_target and self.warning_multi_expr and self.critical_multi_expr)


_REFLECTION_EVIDENCE = (
    "bits_s",
    "packets_s",
    "flows_s",
    "avg_packet_bytes",
    "unique_src_ips",
    "unique_src_ports",
    "unique_dst_ips",
)
_FLOOD_EVIDENCE = (
    "bits_s",
    "packets_s",
    "flows_s",
    "avg_packet_bytes",
    "unique_src_ips",
    "unique_dst_ips",
    "unique_dst_ports",
)

_CARPET_NOTE = (
    "carpet bombing: muitos alvos atras de um mesmo prefixo/cliente; "
    "unique_dst_ips >= 8/16 confirma a distribuicao (evita alerta de alvo unico)"
)
_FLOOD_MULTI_NOTE = (
    "flood distribuido contra muitos IPs do prefixo; modo single cobre o alvo "
    "pontual e o multi cobre o ataque agregado no cliente"
)
_RESOLVER_NOTE = (
    "resolvers internos sao enumeraveis (modo single); o cenario distribuido "
    "fica coberto pelo preset generico UDP_FLOOD_INBOUND_MULTI"
)


def _reflection_multi_warning() -> str:
    return "(bps >= 50M OR pps >= 10k) AND unique_dst_ips >= 8"


def _reflection_multi_critical() -> str:
    return "(bps >= 100M OR pps >= 20k) AND unique_dst_ips >= 16"


def _flood_multi(expr_single: str, dst_min: int) -> str:
    expression = f"({expr_single})" if " OR " in expr_single else expr_single
    return f"{expression} AND unique_dst_ips >= {dst_min}"


PRESET_ORDER: tuple[str, ...] = (
    "dns_reflection",
    "dns_query_flood",
    "ntp_reflection",
    "ssdp_reflection",
    "cldap_reflection",
    "memcached_amplification",
    "udp_flood",
    "tcp_syn_flood",
    "tcp_synack_flood",
    "tcp_ack_flood",
    "icmp_flood",
)

PRESETS: dict[str, InboundVectorPreset] = {}


def _register(preset: InboundVectorPreset) -> None:
    PRESETS[preset.id] = preset


_register(InboundVectorPreset(
    id="dns_reflection",
    name="DNS Reflection",
    family="reflection",
    description=(
        "Respostas DNS (src_port 53) refletidas para alvos internos. Band-split: "
        "cede a faixa de WARNING dos legados de amplificacao DNS (bps > 80M "
        "ou pps > 20k), evitando evento duplicado sobre eles."
    ),
    protocol="UDP",
    src_port="53",
    metric="bits_s",
    warning_value=15_000_000.0,
    critical_value=30_000_000.0,
    warning_expr="(bps >= 15M OR pps >= 3k) AND NOT (bps > 80M OR pps > 20k)",
    critical_expr="(bps >= 30M OR pps >= 8k) AND NOT (bps > 80M OR pps > 20k)",
    warning_multi_expr=_reflection_multi_warning(),
    critical_multi_expr=_reflection_multi_critical(),
    warning_multi_value=50_000_000.0,
    critical_multi_value=100_000_000.0,
    evidence=_REFLECTION_EVIDENCE,
    match_dsl="proto == udp and src_port == 53 and direction == inbound",
    multi_mode_note=_CARPET_NOTE,
))

_register(InboundVectorPreset(
    id="dns_query_flood",
    name="DNS Query Flood",
    family="query",
    description="Flood de consultas DNS (dst_port 53) contra resolvers internos.",
    protocol="UDP",
    dst_port="53",
    metric="packets_s",
    warning_value=5_000.0,
    critical_value=10_000.0,
    warning_expr="bps >= 15M OR pps >= 5k",
    critical_expr="bps >= 30M OR pps >= 10k",
    multi_target=False,
    evidence=(
        "bits_s",
        "packets_s",
        "flows_s",
        "avg_packet_bytes",
        "unique_src_ips",
        "unique_dst_ips",
    ),
    match_dsl="proto == udp and dst_port == 53 and direction == inbound",
    multi_mode_note=_RESOLVER_NOTE,
))

for _id, _name, _port in (
    ("ntp_reflection", "NTP Reflection", "123"),
    ("ssdp_reflection", "SSDP Reflection", "1900"),
    ("cldap_reflection", "CLDAP Reflection", "389"),
):
    _register(InboundVectorPreset(
        id=_id,
        name=_name,
        family="reflection",
        description=f"Respostas {_name.split()[0]} (src_port {_port}) refletidas para alvos internos.",
        protocol="UDP",
        src_port=_port,
        metric="bits_s",
        warning_value=15_000_000.0,
        critical_value=30_000_000.0,
        warning_expr="bps >= 15M OR pps >= 3k",
        critical_expr="bps >= 30M OR pps >= 8k",
        warning_multi_expr=_reflection_multi_warning(),
        critical_multi_expr=_reflection_multi_critical(),
        warning_multi_value=50_000_000.0,
        critical_multi_value=100_000_000.0,
        evidence=_REFLECTION_EVIDENCE,
        match_dsl=f"proto == udp and src_port == {_port} and direction == inbound",
        multi_mode_note=_CARPET_NOTE,
    ))

_register(InboundVectorPreset(
    id="memcached_amplification",
    name="Memcached Amplification",
    family="reflection",
    description="Amplificacao Memcached (src_port 11211) contra alvos internos (fator de amplificacao muito alto).",
    protocol="UDP",
    src_port="11211",
    metric="bits_s",
    warning_value=50_000_000.0,
    critical_value=100_000_000.0,
    warning_expr="bps >= 50M OR pps >= 5k",
    critical_expr="bps >= 100M OR pps >= 10k",
    warning_multi_expr="(bps >= 100M OR pps >= 10k) AND unique_dst_ips >= 8",
    critical_multi_expr="(bps >= 300M OR pps >= 20k) AND unique_dst_ips >= 16",
    warning_multi_value=100_000_000.0,
    critical_multi_value=300_000_000.0,
    evidence=_REFLECTION_EVIDENCE,
    match_dsl="proto == udp and src_port == 11211 and direction == inbound",
    multi_mode_note=_CARPET_NOTE,
))

_register(InboundVectorPreset(
    id="udp_flood",
    name="UDP Flood",
    family="flood",
    description="Flood UDP volumetrico (porta de origem qualquer) contra alvos internos.",
    protocol="UDP",
    metric="packets_s",
    warning_value=100_000.0,
    critical_value=300_000.0,
    warning_expr="pps >= 100k OR bps >= 1G",
    critical_expr="pps >= 300k OR bps >= 3G",
    warning_multi_expr=_flood_multi("pps >= 100k OR bps >= 1G", 8),
    critical_multi_expr=_flood_multi("pps >= 300k OR bps >= 3G", 16),
    warning_multi_value=100_000.0,
    critical_multi_value=300_000.0,
    evidence=_FLOOD_EVIDENCE,
    match_dsl="proto == udp and direction == inbound",
    multi_mode_note=_FLOOD_MULTI_NOTE,
))

_register(InboundVectorPreset(
    id="tcp_syn_flood",
    name="TCP SYN Flood",
    family="flood",
    description="Flood de SYNs (SYN sem ACK) contra alvos internos.",
    protocol="TCP+SYN-NO-ACK",
    metric="packets_s",
    warning_value=50_000.0,
    critical_value=150_000.0,
    warning_expr="pps >= 50k",
    critical_expr="pps >= 150k",
    warning_multi_expr=_flood_multi("pps >= 50k", 8),
    critical_multi_expr=_flood_multi("pps >= 150k", 16),
    warning_multi_value=50_000.0,
    critical_multi_value=150_000.0,
    evidence=_FLOOD_EVIDENCE,
    match_dsl="proto == tcp and tcp_flags contains syn and tcp_flags not contains ack and direction == inbound",
    multi_mode_note=_FLOOD_MULTI_NOTE,
))

_register(InboundVectorPreset(
    id="tcp_synack_flood",
    name="TCP SYN-ACK Flood",
    family="flood",
    description="Flood de SYN+ACK (respostas de conexoes que nunca completam) contra alvos internos.",
    protocol="TCP+SYNACK",
    metric="packets_s",
    warning_value=50_000.0,
    critical_value=150_000.0,
    warning_expr="pps >= 50k",
    critical_expr="pps >= 150k",
    warning_multi_expr=_flood_multi("pps >= 50k", 8),
    critical_multi_expr=_flood_multi("pps >= 150k", 16),
    warning_multi_value=50_000.0,
    critical_multi_value=150_000.0,
    evidence=_FLOOD_EVIDENCE,
    match_dsl="proto == tcp and tcp_flags contains syn and tcp_flags contains ack and direction == inbound",
    multi_mode_note=_FLOOD_MULTI_NOTE,
))

_register(InboundVectorPreset(
    id="tcp_ack_flood",
    name="TCP ACK Flood",
    family="flood",
    description="Flood de ACKs (ACK sem SYN) contra alvos internos.",
    protocol="TCP+ACK-NO-SYN",
    metric="packets_s",
    warning_value=100_000.0,
    critical_value=300_000.0,
    warning_expr="pps >= 100k",
    critical_expr="pps >= 300k",
    warning_multi_expr=_flood_multi("pps >= 100k", 8),
    critical_multi_expr=_flood_multi("pps >= 300k", 16),
    warning_multi_value=100_000.0,
    critical_multi_value=300_000.0,
    evidence=_FLOOD_EVIDENCE,
    match_dsl="proto == tcp and tcp_flags contains ack and tcp_flags not contains syn and direction == inbound",
    multi_mode_note=_FLOOD_MULTI_NOTE,
))

_register(InboundVectorPreset(
    id="icmp_flood",
    name="ICMP Flood",
    family="flood",
    description="Flood ICMP (echo/echo-reply e derivados) contra alvos internos.",
    protocol="ICMP",
    metric="packets_s",
    warning_value=20_000.0,
    critical_value=50_000.0,
    warning_expr="pps >= 20k OR bps >= 200M",
    critical_expr="pps >= 50k OR bps >= 500M",
    warning_multi_expr=_flood_multi("pps >= 20k OR bps >= 200M", 8),
    critical_multi_expr=_flood_multi("pps >= 50k OR bps >= 500M", 16),
    warning_multi_value=20_000.0,
    critical_multi_value=50_000.0,
    evidence=_FLOOD_EVIDENCE,
    match_dsl="proto == icmp and direction == inbound",
    multi_mode_note=_FLOOD_MULTI_NOTE,
))


def list_presets() -> list[InboundVectorPreset]:
    """Presets na ordem canonica do plano (A..K)."""
    return [PRESETS[preset_id] for preset_id in PRESET_ORDER]


def get_preset(preset_id: str) -> InboundVectorPreset:
    key = str(preset_id or "").strip().lower()
    if key not in PRESETS:
        raise KeyError(f"preset inbound desconhecido: {preset_id!r}")
    return PRESETS[key]


def iter_preset_variants() -> Iterator[tuple[InboundVectorPreset, bool]]:
    """(preset, multi) na ordem canonica — base de materializacao/replay."""
    for preset in list_presets():
        yield preset, False
        if preset.supports_multi():
            yield preset, True


def preset_rule_payload(
    preset: InboundVectorPreset,
    *,
    multi: bool = False,
    window_seconds: int | None = None,
    enabled: bool = False,
) -> dict[str, Any]:
    """Payload pronto para `detection_template_rules` (default: DESABILITADO).

    Nao grava nada: devolve o dict que a API/persistencia usaria, com os campos
    de trigger booleano (`trigger_warning_expr`/`trigger_critical_expr`) e
    `evidence`. Os valores numericos `warning_value`/`critical_value` sao o
    espelho da metrica primaria (ordenacao do top-N e compatibilidade com o
    caminho legado); a semantica de match e SEMPRE a expressao DSL.
    """
    use_multi = bool(multi)
    if use_multi and not preset.supports_multi():
        raise ValueError(f"preset '{preset.id}' nao possui modo multi-target")
    if use_multi:
        expr_warning = preset.warning_multi_expr
        expr_critical = preset.critical_multi_expr
        mirror_warning = preset.warning_multi_value
        mirror_critical = preset.critical_multi_value
        domain, group_by = "subnet", ""
    else:
        expr_warning = preset.warning_expr
        expr_critical = preset.critical_expr
        mirror_warning = preset.warning_value
        mirror_critical = preset.critical_value
        domain, group_by = "internal_ip", "dst_ip"
    window = int(window_seconds or preset.window_seconds)
    return {
        "vector": preset.vector_name(use_multi),
        "display_name": preset.name if not use_multi else f"{preset.name} (multi-target)",
        "domain": domain,
        "direction": preset.direction,
        "protocol": preset.protocol,
        "metric": preset.metric,
        "comparison": "over",
        "warning_value": float(mirror_warning),
        "critical_value": float(mirror_critical),
        "window_seconds": window,
        "group_by": group_by,
        "src_port": preset.src_port,
        "dst_port": preset.dst_port,
        "trigger_warning_expr": expr_warning,
        "trigger_critical_expr": expr_critical,
        "evidence": ",".join(preset.evidence),
        "response": "DETECTION_ONLY",
        "enabled": bool(enabled),
        "notes": (
            f"preset inbound '{preset.id}' de inbound_vectors.py; thresholds iniciais "
            "sujeitos a calibracao (replay historico); ativacao manual e explicita"
        ),
    }


def preset_dsl_text(
    preset: InboundVectorPreset,
    *,
    multi: bool = False,
    window_seconds: int | None = None,
) -> str:
    """Texto DSL completo (MATCH/WARNING/CRITICAL/EVIDENCE/ADVANCED) do preset."""
    use_multi = bool(multi)
    if use_multi and not preset.supports_multi():
        raise ValueError(f"preset '{preset.id}' nao possui modo multi-target")
    expr_warning = preset.warning_multi_expr if use_multi else preset.warning_expr
    expr_critical = preset.critical_multi_expr if use_multi else preset.critical_expr
    window = int(window_seconds or preset.window_seconds)
    group_by = "prefix/subnet (domain = subnet)" if use_multi else "dst_ip"
    lines = [
        "MATCH",
        preset.match_dsl,
        "",
        "WARNING",
        expr_warning,
        "",
        "CRITICAL",
        expr_critical,
    ]
    if preset.evidence:
        lines += ["", "EVIDENCE", ", ".join(preset.evidence)]
    lines += ["", "ADVANCED", f"window = {window}s", f"group_by = {group_by}"]
    return "\n".join(lines)
