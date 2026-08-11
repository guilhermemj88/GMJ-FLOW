from __future__ import annotations


THREAT_CLASSIFICATIONS = (
    "NORMAL",
    "SUSPICIOUS",
    "PORT_SCAN_VERTICAL",
    "PORT_SCAN_HORIZONTAL",
    "NETWORK_SWEEP",
    "LOW_SLOW_SCAN",
    "SYN_FLOOD",
    "DISTRIBUTED_SYN_FLOOD",
    "SPOOFED_SYN_FLOOD",
    "UDP_FLOOD",
    "DISTRIBUTED_UDP_FLOOD",
    "UDP_REFLECTION_SUSPECTED",
    "CARPET_BOMBING",
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
