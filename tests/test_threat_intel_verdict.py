from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.threat_intel_verdict import (  # noqa: E402
    ABUSE_SCANNER,
    AGING,
    BOTNET_DDOS,
    C2_CONFIRMED,
    FRESH,
    HIGH,
    LOW,
    LOW_SIGNAL,
    MALWARE_COMPROMISED,
    MEDIUM,
    RC_BLOCKLIST_ABUSE,
    RC_EXPLICIT_C2,
    RC_FEODO_BOTNET,
    RC_GREYNOISE_MALICIOUS,
    RC_GREYNOISE_SCANNER,
    RC_GREYNOISE_SUSPICIOUS,
    RC_MULTI_PROVIDER_CORROBORATION,
    RC_PROVIDER_FEED_STALE,
    RC_STALE_CONFIDENCE_CAP,
    RC_STALE_INDICATOR,
    STALE,
    UNKNOWN,
    UNKNOWN_FRESHNESS,
    aggregate_threat_intel_evidence,
    freshness_label,
    normalize_provider_evidence,
    verdict_from_matches,
)


def _now() -> datetime:
    return datetime(2026, 9, 17, 20, 0, 0, tzinfo=timezone.utc)


def _iso(hours_ago: float) -> str:
    return (_now() - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Layer 1: provider normalization
# ---------------------------------------------------------------------------
class ProviderNormalizationTest(unittest.TestCase):
    def test_cereal2_explicit_c2(self):
        ev = normalize_provider_evidence(
            {
                "provider": "CEREAL2",
                "indicator_type": "C2",
                "ip": "104.250.100.138",
                "classification": "c2",
                "first_seen": _iso(200),
                "last_seen": _iso(0.5),
                "botnet_family": "",
                "metadata": {},
            },
            _now(),
        )
        self.assertEqual(ev["canonical_verdict"], C2_CONFIRMED)
        self.assertEqual(ev["confidence"], HIGH)
        self.assertIn(RC_EXPLICIT_C2, ev["reason_codes"])
        self.assertEqual(ev["first_seen"], _iso(200))
        self.assertEqual(ev["freshness"], FRESH)

    def test_feodo_c2_with_botnet_family(self):
        ev = normalize_provider_evidence(
            {
                "provider": "FEODO",
                "indicator_type": "C2",
                "ip": "178.62.3.223",
                "classification": "c2",
                "botnet_family": "QakBot",
                "first_seen": _iso(300),
                "last_seen": _iso(2),
                "metadata": {"port": 443, "status": "online"},
            },
            _now(),
        )
        self.assertEqual(ev["canonical_verdict"], C2_CONFIRMED)
        self.assertIn(RC_FEODO_BOTNET, ev["reason_codes"])
        self.assertIn(RC_EXPLICIT_C2, ev["reason_codes"])
        self.assertEqual(ev["raw_metadata"]["port"], 443)

    def test_feodo_stale_lowers_confidence(self):
        # Feodo currently serves last_seen ~6 months old -> STALE, confidence down.
        stale = (_now() - timedelta(days=190)).isoformat().replace("+00:00", "Z")
        ev = normalize_provider_evidence(
            {
                "provider": "FEODO",
                "indicator_type": "C2",
                "ip": "27.133.154.218",
                "classification": "c2",
                "botnet_family": "QakBot",
                "last_seen": stale,
                "metadata": {},
            },
            _now(),
        )
        self.assertEqual(ev["canonical_verdict"], C2_CONFIRMED)  # verdict preserved
        self.assertEqual(ev["freshness"], STALE)
        self.assertEqual(ev["confidence"], MEDIUM)  # HIGH -1
        self.assertIn(RC_STALE_INDICATOR, ev["reason_codes"])

    def test_greynoise_malicious_is_not_c2(self):
        ev = normalize_provider_evidence(
            {
                "provider": "GREYNOISE",
                "indicator_type": "IP",
                "ip": "8.8.8.8",
                "classification": "malicious",
                "last_seen": _iso(1),
                "tags": [],
                "metadata": {},
            },
            _now(),
        )
        self.assertEqual(ev["canonical_verdict"], ABUSE_SCANNER)
        self.assertNotEqual(ev["canonical_verdict"], C2_CONFIRMED)
        self.assertEqual(ev["confidence"], MEDIUM)
        self.assertIn(RC_GREYNOISE_MALICIOUS, ev["reason_codes"])

    def test_greynoise_scanner_tag(self):
        ev = normalize_provider_evidence(
            {
                "provider": "GREYNOISE",
                "indicator_type": "IP",
                "ip": "8.8.4.4",
                "classification": "suspicious",
                "last_seen": _iso(0.2),
                "tags": [{"slug": "ssh-scan", "name": "SSH Scanner", "category": "activity", "intention": "scanning"}],
                "metadata": {},
            },
            _now(),
        )
        self.assertEqual(ev["canonical_verdict"], ABUSE_SCANNER)
        self.assertIn(RC_GREYNOISE_SCANNER, ev["reason_codes"])

    def test_greynoise_suspicious(self):
        ev = normalize_provider_evidence(
            {
                "provider": "GREYNOISE",
                "indicator_type": "IP",
                "ip": "8.8.4.4",
                "classification": "suspicious",
                "last_seen": _iso(3),
                "tags": [],
                "metadata": {},
            },
            _now(),
        )
        self.assertEqual(ev["canonical_verdict"], LOW_SIGNAL)
        self.assertEqual(ev["confidence"], LOW)
        self.assertIn(RC_GREYNOISE_SUSPICIOUS, ev["reason_codes"])

    def test_blocklist_abuse(self):
        ev = normalize_provider_evidence(
            {
                "provider": "BLOCKLIST_DE",
                "indicator_type": "IP",
                "ip": "1.0.164.165",
                "classification": "reported_attack_source",
                "metadata": {
                    "retrieved_at": _iso(0.1),
                    "expires_at": _iso(-48),
                },
            },
            _now(),
        )
        self.assertEqual(ev["canonical_verdict"], ABUSE_SCANNER)
        self.assertEqual(ev["confidence"], LOW)
        self.assertIn(RC_BLOCKLIST_ABUSE, ev["reason_codes"])

    def test_blocklist_feed_stale_reason(self):
        ev = normalize_provider_evidence(
            {
                "provider": "BLOCKLIST_DE",
                "indicator_type": "IP",
                "ip": "1.0.164.165",
                "classification": "reported_attack_source",
                "metadata": {"retrieved_at": _iso(100)},  # feed >48h old
            },
            _now(),
        )
        self.assertEqual(ev["freshness"], STALE)
        self.assertIn(RC_PROVIDER_FEED_STALE, ev["reason_codes"])

    def test_team_cymru_bogon_excluded(self):
        ev = normalize_provider_evidence(
            {
                "provider": "TEAM_CYMRU",
                "indicator_type": "BOGON",
                "ip": "9.9.9.9",
                "network": "9.0.0.0/8",
                "classification": "anomalous_source",
            },
            _now(),
        )
        self.assertIsNone(ev)

    def test_unknown_provider_ignored(self):
        ev = normalize_provider_evidence(
            {"provider": "SOME_FUTURE_PROVIDER", "classification": "c2", "ip": "1.1.1.1"},
            _now(),
        )
        self.assertIsNone(ev)


# ---------------------------------------------------------------------------
# Layer 2: aggregation
# ---------------------------------------------------------------------------
def _evidence(provider: str, verdict: str, confidence: str, freshness: str, **extra: Any) -> dict[str, Any]:
    base = {
        "provider": provider,
        "indicator": extra.pop("indicator", "1.1.1.1"),
        "indicator_type": "IP",
        "provider_category": "",
        "canonical_verdict": verdict,
        "confidence": confidence,
        "first_seen": extra.pop("first_seen", None),
        "last_seen": extra.pop("last_seen", None),
        "feed_updated_at": None,
        "feed_freshness": freshness,
        "freshness": freshness,
        "reason_codes": extra.pop("reason_codes", []),
        "raw_metadata": {},
    }
    base.update(extra)
    return base


class AggregationTest(unittest.TestCase):
    def test_no_evidence(self):
        result = aggregate_threat_intel_evidence([], _now())
        self.assertEqual(result["verdict"], UNKNOWN)
        self.assertEqual(result["confidence"], LOW)
        self.assertEqual(result["freshness"], UNKNOWN_FRESHNESS)
        self.assertEqual(result["corroboration_count"], 0)

    def test_c2_beats_scanner(self):
        c2 = _evidence("FEODO", C2_CONFIRMED, HIGH, FRESH, reason_codes=[RC_EXPLICIT_C2])
        scanner = _evidence("GREYNOISE", ABUSE_SCANNER, MEDIUM, FRESH, reason_codes=[RC_GREYNOISE_MALICIOUS])
        result = aggregate_threat_intel_evidence([scanner, c2], _now())
        self.assertEqual(result["verdict"], C2_CONFIRMED)
        self.assertEqual(len(result["evidences"]), 2)  # both preserved
        self.assertEqual(result["corroboration_count"], 2)

    def test_scanner_plus_scanner_stays_scanner(self):
        a = _evidence("GREYNOISE", ABUSE_SCANNER, LOW, FRESH)
        b = _evidence("BLOCKLIST_DE", ABUSE_SCANNER, LOW, FRESH)
        result = aggregate_threat_intel_evidence([a, b], _now())
        self.assertEqual(result["verdict"], ABUSE_SCANNER)  # never C2
        self.assertEqual(result["corroboration_count"], 2)

    def test_conflict_abuse_vs_malware(self):
        abuse = _evidence("BLOCKLIST_DE", ABUSE_SCANNER, LOW, FRESH)
        malware = _evidence("GREYNOISE", MALWARE_COMPROMISED, MEDIUM, FRESH)
        result = aggregate_threat_intel_evidence([abuse, malware], _now())
        self.assertEqual(result["verdict"], MALWARE_COMPROMISED)  # precedence
        self.assertEqual(len(result["evidences"]), 2)  # both visible

    def test_duplicate_same_provider_no_inflate(self):
        a = _evidence("FEODO", C2_CONFIRMED, HIGH, FRESH)
        b = _evidence("FEODO", C2_CONFIRMED, HIGH, AGING)
        result = aggregate_threat_intel_evidence([a, b], _now())
        self.assertEqual(result["corroboration_count"], 1)
        self.assertEqual(result["provider_count"], 1)

    def test_corroboration_raises_confidence(self):
        a = _evidence("GREYNOISE", ABUSE_SCANNER, LOW, FRESH)
        b = _evidence("BLOCKLIST_DE", ABUSE_SCANNER, LOW, FRESH)
        result = aggregate_threat_intel_evidence([a, b], _now())
        self.assertEqual(result["confidence"], MEDIUM)  # LOW +1
        self.assertIn(RC_MULTI_PROVIDER_CORROBORATION, result["reason_codes"])

    def test_verdict_freshness_follows_winner(self):
        fresh_c2 = _evidence("FEODO", C2_CONFIRMED, HIGH, FRESH, last_seen=_iso(0.5))
        stale_scanner = _evidence("GREYNOISE", ABUSE_SCANNER, LOW, STALE, last_seen=_iso(100))
        result = aggregate_threat_intel_evidence([stale_scanner, fresh_c2], _now())
        self.assertEqual(result["freshness"], FRESH)

    def test_first_seen_min_last_seen_max(self):
        a = _evidence("FEODO", C2_CONFIRMED, HIGH, FRESH, first_seen=_iso(300), last_seen=_iso(2))
        b = _evidence("CEREAL2", C2_CONFIRMED, HIGH, FRESH, first_seen=_iso(200), last_seen=_iso(1))
        result = aggregate_threat_intel_evidence([a, b], _now())
        self.assertEqual(result["first_seen"], _iso(300))  # min (older)
        self.assertEqual(result["last_seen"], _iso(1))  # max (newer)


# ---------------------------------------------------------------------------
# Stale confidence cap (P5.1F fix)
# ---------------------------------------------------------------------------
class StaleConfidenceCapTest(unittest.TestCase):
    def test_case_a_single_fresh_c2_high(self):
        r = aggregate_threat_intel_evidence(
            [_evidence("CEREAL2", C2_CONFIRMED, HIGH, FRESH)], _now()
        )
        self.assertEqual(r["confidence"], HIGH)

    def test_case_b_two_fresh_c2_high(self):
        r = aggregate_threat_intel_evidence(
            [
                _evidence("CEREAL2", C2_CONFIRMED, HIGH, FRESH),
                _evidence("FEODO", C2_CONFIRMED, HIGH, FRESH),
            ],
            _now(),
        )
        self.assertEqual(r["confidence"], HIGH)
        self.assertEqual(r["corroboration_count"], 2)

    def test_case_c_single_stale_c2_medium(self):
        r = aggregate_threat_intel_evidence(
            [_evidence("CEREAL2", C2_CONFIRMED, MEDIUM, STALE)], _now()
        )
        self.assertEqual(r["confidence"], MEDIUM)

    def test_case_d_two_stale_c2_never_high(self):
        r = aggregate_threat_intel_evidence(
            [
                _evidence("CEREAL2", C2_CONFIRMED, MEDIUM, STALE),
                _evidence("FEODO", C2_CONFIRMED, MEDIUM, STALE),
            ],
            _now(),
        )
        self.assertEqual(r["verdict"], C2_CONFIRMED)
        self.assertEqual(r["corroboration_count"], 2)
        self.assertEqual(r["confidence"], MEDIUM)
        self.assertNotEqual(r["confidence"], HIGH)
        self.assertIn(RC_STALE_CONFIDENCE_CAP, r["reason_codes"])

    def test_case_e_two_stale_abuse_not_above_medium(self):
        r = aggregate_threat_intel_evidence(
            [
                _evidence("BLOCKLIST_DE", ABUSE_SCANNER, LOW, STALE),
                _evidence("GREYNOISE", ABUSE_SCANNER, LOW, STALE),
            ],
            _now(),
        )
        self.assertEqual(r["verdict"], ABUSE_SCANNER)
        self.assertIn(r["confidence"], (LOW, MEDIUM))  # never above MEDIUM

    def test_case_f_two_fresh_abuse_corroboration_within_bounds(self):
        r = aggregate_threat_intel_evidence(
            [
                _evidence("BLOCKLIST_DE", ABUSE_SCANNER, LOW, FRESH),
                _evidence("GREYNOISE", ABUSE_SCANNER, LOW, FRESH),
            ],
            _now(),
        )
        self.assertEqual(r["verdict"], ABUSE_SCANNER)  # category unchanged
        self.assertEqual(r["confidence"], MEDIUM)  # LOW +1

    def test_case_g_mixed_fresh_stale_same_verdict(self):
        # Freshness follows the winning evidence (first-highest-precedence, here
        # the fresh Cereal2) -> FRESH; confidence stays HIGH.
        r = aggregate_threat_intel_evidence(
            [
                _evidence("CEREAL2", C2_CONFIRMED, HIGH, FRESH, last_seen=_iso(0.5)),
                _evidence("FEODO", C2_CONFIRMED, MEDIUM, STALE, last_seen=_iso(200)),
            ],
            _now(),
        )
        self.assertEqual(r["verdict"], C2_CONFIRMED)
        self.assertEqual(r["freshness"], FRESH)
        self.assertEqual(r["confidence"], HIGH)

    def test_case_h_stale_c2_beats_fresh_scanner(self):
        # Verdict by precedence (C2 wins); evidence preserved; confidence follows
        # the winning evidence freshness (STALE -> capped at MEDIUM).
        r = aggregate_threat_intel_evidence(
            [
                _evidence("FEODO", C2_CONFIRMED, MEDIUM, STALE),
                _evidence("GREYNOISE", ABUSE_SCANNER, LOW, FRESH),
            ],
            _now(),
        )
        self.assertEqual(r["verdict"], C2_CONFIRMED)
        self.assertEqual(len(r["evidences"]), 2)
        self.assertEqual(r["freshness"], STALE)
        self.assertEqual(r["confidence"], MEDIUM)


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------
class FreshnessTest(unittest.TestCase):
    def test_cereal2_thresholds(self):
        now = _now()
        self.assertEqual(freshness_label("CEREAL2", now.isoformat(), now), FRESH)
        self.assertEqual(freshness_label("CEREAL2", (now - timedelta(hours=2)).isoformat(), now), AGING)
        self.assertEqual(freshness_label("CEREAL2", (now - timedelta(days=2)).isoformat(), now), STALE)

    def test_provider_aware_greynoise(self):
        now = _now()
        # 5h old: FRESH for GreyNoise (8h threshold), but AGING for Cereal2 (1h).
        ts = (now - timedelta(hours=5)).isoformat()
        self.assertEqual(freshness_label("GREYNOISE", ts, now), FRESH)
        self.assertEqual(freshness_label("CEREAL2", ts, now), AGING)

    def test_no_timestamp_unknown(self):
        self.assertEqual(freshness_label("CEREAL2", "", _now()), UNKNOWN_FRESHNESS)
        self.assertEqual(freshness_label("CEREAL2", None, _now()), UNKNOWN_FRESHNESS)
        self.assertEqual(freshness_label("CEREAL2", "garbage", _now()), UNKNOWN_FRESHNESS)

    def test_mixed_timestamp_formats(self):
        now = _now()
        space = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(freshness_label("CEREAL2", space, now), FRESH)
        date_only = (now - timedelta(days=3)).strftime("%Y-%m-%d")
        self.assertEqual(freshness_label("CEREAL2", date_only, now), STALE)


# ---------------------------------------------------------------------------
# Verdict matrix (runbook section 41)
# ---------------------------------------------------------------------------
class VerdictMatrixTest(unittest.TestCase):
    def test_case1_feodo_explicit_c2(self):
        r = verdict_from_matches(
            [{"provider": "FEODO", "indicator_type": "C2", "ip": "1.2.3.4", "classification": "c2",
              "botnet_family": "Emotet", "last_seen": _iso(1), "metadata": {}}],
            _now(),
        )
        self.assertEqual(r["verdict"], C2_CONFIRMED)

    def test_case2_greynoise_scanner_not_c2(self):
        r = verdict_from_matches(
            [{"provider": "GREYNOISE", "indicator_type": "IP", "ip": "1.2.3.4", "classification": "malicious",
              "tags": [{"slug": "scan"}], "last_seen": _iso(1), "metadata": {}}],
            _now(),
        )
        self.assertEqual(r["verdict"], ABUSE_SCANNER)

    def test_case3_blocklist_abuse_only(self):
        r = verdict_from_matches(
            [{"provider": "BLOCKLIST_DE", "indicator_type": "IP", "ip": "1.2.3.4",
              "classification": "reported_attack_source", "metadata": {"retrieved_at": _iso(0.1)}}],
            _now(),
        )
        self.assertEqual(r["verdict"], ABUSE_SCANNER)

    def test_case4_generic_malicious_not_c2(self):
        # Generic malicious (no provider-specific mapping path) never becomes C2.
        ev = _evidence("SOME_FUTURE", ABUSE_SCANNER, LOW, FRESH)
        result = aggregate_threat_intel_evidence([ev], _now())
        self.assertNotEqual(result["verdict"], C2_CONFIRMED)

    def test_case5_c2_plus_scanner_corroboration(self):
        r = verdict_from_matches(
            [
                {"provider": "FEODO", "indicator_type": "C2", "ip": "1.2.3.4", "classification": "c2",
                 "botnet_family": "QakBot", "last_seen": _iso(1), "metadata": {}},
                {"provider": "GREYNOISE", "indicator_type": "IP", "ip": "1.2.3.4", "classification": "malicious",
                 "tags": [{"slug": "scan"}], "last_seen": _iso(1), "metadata": {}},
            ],
            _now(),
        )
        self.assertEqual(r["verdict"], C2_CONFIRMED)
        self.assertEqual(r["corroboration_count"], 2)
        self.assertEqual(len(r["evidences"]), 2)

    def test_case6_scanner_plus_scanner(self):
        r = verdict_from_matches(
            [
                {"provider": "GREYNOISE", "indicator_type": "IP", "ip": "1.2.3.4", "classification": "malicious",
                 "tags": [{"slug": "scan"}], "last_seen": _iso(1), "metadata": {}},
                {"provider": "BLOCKLIST_DE", "indicator_type": "IP", "ip": "1.2.3.4",
                 "classification": "reported_attack_source", "metadata": {"retrieved_at": _iso(0.1)}},
            ],
            _now(),
        )
        self.assertEqual(r["verdict"], ABUSE_SCANNER)

    def test_case7_stale_verdict_preserved(self):
        stale = (_now() - timedelta(days=190)).isoformat().replace("+00:00", "Z")
        r = verdict_from_matches(
            [{"provider": "FEODO", "indicator_type": "C2", "ip": "1.2.3.4", "classification": "c2",
              "botnet_family": "QakBot", "last_seen": stale, "metadata": {}}],
            _now(),
        )
        self.assertEqual(r["verdict"], C2_CONFIRMED)  # preserved
        self.assertEqual(r["freshness"], STALE)

    def test_case8_feed_stale(self):
        r = verdict_from_matches(
            [{"provider": "BLOCKLIST_DE", "indicator_type": "IP", "ip": "1.2.3.4",
              "classification": "reported_attack_source", "metadata": {"retrieved_at": _iso(100)}}],
            _now(),
        )
        self.assertEqual(r["verdict"], ABUSE_SCANNER)
        self.assertIn(RC_PROVIDER_FEED_STALE, r["reason_codes"])

    def test_case9_no_timestamp(self):
        r = verdict_from_matches(
            [{"provider": "BLOCKLIST_DE", "indicator_type": "IP", "ip": "1.2.3.4",
              "classification": "reported_attack_source", "metadata": {}}],
            _now(),
        )
        self.assertEqual(r["freshness"], UNKNOWN_FRESHNESS)

    def test_case10_no_providers(self):
        r = verdict_from_matches([], _now())
        self.assertEqual(r["verdict"], UNKNOWN)


if __name__ == "__main__":
    unittest.main()
