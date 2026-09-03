"""Testes do registry de codecs de serviço (flow_codecs).

Cobre: seed idempotente, matcher (protocolo/portas/direção/roles/provider),
ordenação por prioridade, múltiplos matches, CRUD e proteção de builtin.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.flow_codecs import (  # noqa: E402
    classify_flow_codecs,
    create_flow_codec,
    delete_flow_codec,
    duplicate_flow_codec,
    ensure_flow_codecs_schema,
    get_flow_codec,
    list_flow_codecs,
    match_flow_codec,
    seed_builtin_flow_codecs,
    update_flow_codec,
)
from app.services.behavioral_detection import FlowObservation  # noqa: E402


def _flow(protocol="UDP", src_port=50000, dst_port=53, direction="ANY", tcp_flags=0, icmp_type=None, icmp_code=None):
    return {
        "protocol": protocol,
        "source_port": src_port,
        "destination_port": dst_port,
        "direction": direction,
        "tcp_flags": tcp_flags,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
    }


class FlowCodecTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "codecs.sqlite")
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        ensure_flow_codecs_schema(self.conn)
        seed_builtin_flow_codecs(self.conn)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def _codecs(self, active_only=True):
        return list_flow_codecs(self.conn, active_only=active_only)

    def _names(self, flow, source_context=None, destination_context=None):
        return [
            item["name"]
            for item in classify_flow_codecs(flow, self._codecs(), source_context, destination_context)
        ]

    # ---- Seed idempotente --------------------------------------------------
    def test_seed_is_idempotent(self):
        before = len(list_flow_codecs(self.conn))
        seed_builtin_flow_codecs(self.conn)
        self.conn.commit()
        after = len(list_flow_codecs(self.conn))
        self.assertEqual(before, after)
        self.assertGreaterEqual(before, 20)

    # ---- Classificação básica ----------------------------------------------
    def test_dns_query_udp(self):
        self.assertEqual(["DNS_QUERY_UDP"], self._names(_flow(dst_port=53)))

    def test_dns_response_udp(self):
        self.assertEqual(["DNS_RESPONSE_UDP"], self._names(_flow(src_port=53, dst_port=50000)))

    def test_ntp_query(self):
        self.assertEqual(["NTP_QUERY"], self._names(_flow(dst_port=123)))

    def test_ntp_response(self):
        self.assertEqual(["NTP_RESPONSE"], self._names(_flow(src_port=123, dst_port=50000)))

    def test_quic_client(self):
        self.assertEqual(["QUIC_CLIENT"], self._names(_flow(dst_port=443)))

    def test_quic_return(self):
        self.assertEqual(["QUIC_RETURN"], self._names(_flow(src_port=443, dst_port=50000)))

    def test_https_client(self):
        self.assertEqual(["HTTPS_CLIENT"], self._names(_flow(protocol="TCP", dst_port=443)))

    def test_https_return(self):
        self.assertEqual(["HTTPS_RETURN"], self._names(_flow(protocol="TCP", src_port=443, dst_port=50000)))

    def test_http_client(self):
        self.assertEqual(["HTTP_CLIENT"], self._names(_flow(protocol="TCP", dst_port=80)))

    # ---- Wildcard ----------------------------------------------------------
    def test_port_zero_is_wildcard(self):
        custom = create_flow_codec(
            self.conn,
            {"name": "WILDCARD_SRC", "protocol": "UDP", "source_port": 0, "destination_port": 7777},
        )
        self.conn.commit()
        self.assertTrue(match_flow_codec(_flow(src_port=12345, dst_port=7777), custom))
        self.assertTrue(match_flow_codec(_flow(src_port=1, dst_port=7777), custom))

    def test_none_port_is_wildcard(self):
        custom = create_flow_codec(
            self.conn,
            {"name": "WILDCARD_NONE", "protocol": "UDP", "source_port": None, "destination_port": 7777},
        )
        self.conn.commit()
        self.assertTrue(match_flow_codec(_flow(src_port=60000, dst_port=7777), custom))

    # ---- Wrong protocol / disabled ----------------------------------------
    def test_wrong_protocol_no_match(self):
        self.assertEqual([], self._names(_flow(protocol="TCP", dst_port=123)))

    def test_disabled_codec_no_match(self):
        codec_id = get_flow_codec(self.conn, next(c["id"] for c in self._codecs() if c["name"] == "DNS_QUERY_UDP"))["id"]
        update_flow_codec(self.conn, codec_id, {"name": "DNS_QUERY_UDP", "active": 0})
        self.conn.commit()
        self.assertNotIn("DNS_QUERY_UDP", self._names(_flow(dst_port=53)))

    # ---- Role / provider restrictions --------------------------------------
    def test_source_role_restriction(self):
        create_flow_codec(
            self.conn,
            {"name": "CDN_ONLY", "protocol": "UDP", "source_port": 443, "destination_port": None, "source_role": "CDN_CACHE"},
        )
        self.conn.commit()
        flow = _flow(src_port=443, dst_port=50000)
        self.assertIn("CDN_ONLY", self._names(flow, source_context={"role": "CDN_CACHE", "provider": "GOOGLE"}))
        self.assertNotIn("CDN_ONLY", self._names(flow, source_context={"role": "OTHER", "provider": "GOOGLE"}))
        self.assertNotIn("CDN_ONLY", self._names(flow))

    def test_provider_restriction(self):
        create_flow_codec(
            self.conn,
            {"name": "GOOGLE_QUIC", "protocol": "UDP", "source_port": 443, "destination_port": None, "provider": "GOOGLE"},
        )
        self.conn.commit()
        flow = _flow(src_port=443, dst_port=50000)
        self.assertIn("GOOGLE_QUIC", self._names(flow, source_context={"role": "CDN_CACHE", "provider": "GOOGLE"}))
        self.assertNotIn("GOOGLE_QUIC", self._names(flow, source_context={"role": "CDN_CACHE", "provider": "NETFLIX"}))

    # ---- Prioridade e ordenação --------------------------------------------
    def test_priority_order(self):
        # Priority 100 antes de 10 para a mesma porta.
        create_flow_codec(self.conn, {"name": "PRIO_10", "protocol": "UDP", "destination_port": 8888, "specificity_priority": 10})
        create_flow_codec(self.conn, {"name": "PRIO_100", "protocol": "UDP", "destination_port": 8888, "specificity_priority": 100})
        self.conn.commit()
        names = self._names(_flow(dst_port=8888))
        self.assertEqual(["PRIO_100", "PRIO_10"], names)

    def test_multiple_match_returns_all_ordered(self):
        # QUIC_CLIENT (dst443) + um genérico UDP wildcard: ambos aparecem.
        create_flow_codec(self.conn, {"name": "UDP_GENERIC", "protocol": "UDP", "specificity_priority": 0})
        self.conn.commit()
        names = self._names(_flow(dst_port=443))
        self.assertIn("QUIC_CLIENT", names)
        self.assertIn("UDP_GENERIC", names)
        self.assertEqual("QUIC_CLIENT", names[0])  # mais específico/prioritário primeiro

    # ---- CRUD --------------------------------------------------------------
    def test_create_custom_codec(self):
        custom = create_flow_codec(
            self.conn,
            {
                "name": "CUSTOM_GAME_X",
                "protocol": "UDP",
                "source_port": None,
                "destination_port": 7777,
                "direction": "ANY",
                "specificity_priority": 50,
                "exclusive_group": "UDP_SERVICE",
                "consume_traffic": True,
            },
        )
        self.conn.commit()
        self.assertEqual(0, custom["builtin"])
        self.assertIn("CUSTOM_GAME_X", self._names(_flow(dst_port=7777)))

    def test_duplicate_name_rejected(self):
        with self.assertRaises(ValueError):
            create_flow_codec(self.conn, {"name": "DNS_QUERY_UDP", "protocol": "UDP", "destination_port": 53})

    def test_invalid_port_rejected(self):
        with self.assertRaises(ValueError):
            create_flow_codec(self.conn, {"name": "BAD_PORT", "protocol": "UDP", "destination_port": 70000})

    def test_invalid_protocol_rejected(self):
        with self.assertRaises(ValueError):
            create_flow_codec(self.conn, {"name": "BAD_PROTO", "protocol": "SCTP", "destination_port": 53})

    def test_delete_custom(self):
        custom = create_flow_codec(self.conn, {"name": "TO_DELETE", "protocol": "UDP", "destination_port": 6666})
        self.conn.commit()
        changed, status = delete_flow_codec(self.conn, custom["id"])
        self.conn.commit()
        self.assertEqual("deleted", status)
        self.assertIsNone(get_flow_codec(self.conn, custom["id"]))

    def test_delete_builtin_protected(self):
        builtin_id = next(c["id"] for c in self._codecs() if c["name"] == "DNS_QUERY_UDP")
        changed, status = delete_flow_codec(self.conn, builtin_id)
        self.assertEqual("builtin_protected", status)
        self.assertIsNotNone(get_flow_codec(self.conn, builtin_id))

    def test_duplicate_builtin_creates_custom(self):
        builtin_id = next(c["id"] for c in self._codecs() if c["name"] == "DNS_QUERY_UDP")
        copy = duplicate_flow_codec(self.conn, builtin_id)
        self.conn.commit()
        self.assertEqual(0, copy["builtin"])
        self.assertNotEqual("DNS_QUERY_UDP", copy["name"])
        self.assertEqual(53, copy["destination_port"])

    def test_builtin_identity_protected(self):
        builtin_id = next(c["id"] for c in self._codecs() if c["name"] == "DNS_QUERY_UDP")
        with self.assertRaises(ValueError):
            update_flow_codec(self.conn, builtin_id, {"name": "DNS_QUERY_UDP", "destination_port": 99})
        # Ativação/metadata de builtin é permitida.
        updated = update_flow_codec(self.conn, builtin_id, {"name": "DNS_QUERY_UDP", "display_name": "DNS query editado", "active": 1})
        self.conn.commit()
        self.assertEqual("DNS query editado", updated["display_name"])
        self.assertEqual(53, updated["destination_port"])

    # ---- Matcher com FlowObservation (integração futura) ------------------
    def test_match_flow_observation(self):
        codecs = self._codecs()
        obs = FlowObservation(
            observed_at=None,
            src_ip="198.18.0.1",
            dst_ip="203.0.113.10",
            src_port=53,
            dst_port=50000,
            protocol=17,
            tcp_flags=0,
            packets=1,
            bytes=60,
            flow_count=1,
        )
        names = [item["name"] for item in classify_flow_codecs(obs, codecs)]
        self.assertEqual(["DNS_RESPONSE_UDP"], names)


if __name__ == "__main__":
    unittest.main()
