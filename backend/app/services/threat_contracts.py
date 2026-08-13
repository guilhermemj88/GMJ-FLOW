from __future__ import annotations


THREAT_CLASSIFICATIONS = (
    "NORMAL",
    "SUSPICIOUS",
    "PORT_SCAN_VERTICAL",
    "PORT_SCAN_HORIZONTAL",
    "NETWORK_SWEEP",
    "LOW_SLOW_SCAN",
    "SSH_BRUTE_FORCE",
    "SYN_FLOOD",
    "DISTRIBUTED_SYN_FLOOD",
    "SPOOFED_SYN_FLOOD",
    "UDP_FLOOD",
    "DISTRIBUTED_UDP_FLOOD",
    "UDP_REFLECTION_SUSPECTED",
    "CARPET_BOMBING",
    "SCANNING_CAMPAIGN",
    "COORDINATED_SCANNING",
    "COORDINATED_DDOS",
    "BOTNET_LIKELY",
    "MULTI_VECTOR_DDOS",
    "UNKNOWN_ANOMALY",
)


THREAT_CLASSIFICATION_SCHEMA = {
    "type": "object",
    "required": ["classification", "confidence", "reason"],
    "additionalProperties": False,
    "properties": {
        "classification": {"type": "string", "enum": list(THREAT_CLASSIFICATIONS)},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
    },
}


SCAN_FAMILY = "SCAN_FAMILY"
FLOOD_FAMILY = "FLOOD_FAMILY"
OTHER_FAMILY = "OTHER_FAMILY"

SCAN_ATTACK_TYPES = frozenset({
    "PORT_SCAN_VERTICAL",
    "PORT_SCAN_HORIZONTAL",
    "NETWORK_SWEEP",
    "LOW_SLOW_SCAN",
    "SSH_BRUTE_FORCE",
    "SCANNING_CAMPAIGN",
    "COORDINATED_SCANNING",
})

FLOOD_ATTACK_TYPES = frozenset({
    "SYN_FLOOD",
    "DISTRIBUTED_SYN_FLOOD",
    "SPOOFED_SYN_FLOOD",
    "UDP_FLOOD",
    "DISTRIBUTED_UDP_FLOOD",
    "UDP_REFLECTION_SUSPECTED",
    "CARPET_BOMBING",
    "COORDINATED_DDOS",
    "MULTI_VECTOR_DDOS",
})

SECURITY_VERDICTS = (
    "INFO",
    "SUSPICIOUS",
    "WARNING",
    "LIKELY_ATTACK",
    "CONFIRMED_ATTACK",
)

AI_EVENT_VERDICTS = ("BENIGN", "SUSPICIOUS", "LIKELY_ATTACK", "CONFIRMED_ATTACK")

SECURITY_EVENT_ANALYSIS_SCHEMA = {
    "type": "object",
    "required": [
        "summary",
        "confidence",
        "assessment",
        "why_detected",
        "important_sources",
        "threat_intelligence_findings",
        "possible_false_positive_factors",
        "recommended_checks",
        "recommended_actions",
        "mitigation_advisory",
        "limitations",
    ],
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string"},
        "confidence": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
        "assessment": {"type": "string"},
        "why_detected": {"type": "array", "items": {"type": "string"}},
        "important_sources": {"type": "array", "items": {"type": "string"}},
        "threat_intelligence_findings": {"type": "array", "items": {"type": "string"}},
        "possible_false_positive_factors": {"type": "array", "items": {"type": "string"}},
        "recommended_checks": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "mitigation_advisory": {"type": "string"},
        "limitations": {"type": "array", "items": {"type": "string"}},
    },
}


def attack_family(attack_type: str) -> str:
    normalized = str(attack_type or "").strip().upper()
    if normalized in SCAN_ATTACK_TYPES:
        return SCAN_FAMILY
    if normalized in FLOOD_ATTACK_TYPES:
        return FLOOD_FAMILY
    return OTHER_FAMILY


def detector_verdict(score: int | float, *, persistent_windows: int = 1) -> str:
    value = max(0.0, min(100.0, float(score or 0)))
    if value >= 90 and persistent_windows >= 3:
        return "CONFIRMED_ATTACK"
    if value >= 75 and persistent_windows >= 2:
        return "LIKELY_ATTACK"
    if value >= 55:
        return "WARNING"
    if value >= 30:
        return "SUSPICIOUS"
    return "INFO"
