from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.dashboard_aggregates import (  # noqa: E402
    ASN_AGGREGATE_TABLES,
    asn_aggregate_version,
)


class AsnAggregateVersionTest(unittest.TestCase):
    def test_default_uses_v2(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_ASN_AGGREGATE_VERSION": ""}):
            self.assertEqual("v2", asn_aggregate_version())

    def test_env_v1_uses_v1(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_ASN_AGGREGATE_VERSION": "v1"}):
            self.assertEqual("v1", asn_aggregate_version())

    def test_env_v2_uses_v2(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_ASN_AGGREGATE_VERSION": "v2"}):
            self.assertEqual("v2", asn_aggregate_version())

    def test_invalid_env_falls_back_v1(self):
        for bad in ("v3", "garbage", "flow_dashboard_asn_src_1m_v2", "V3"):
            with mock.patch.dict(os.environ, {"GMJFLOW_ASN_AGGREGATE_VERSION": bad}):
                self.assertEqual("v1", asn_aggregate_version())

    def test_table_mapping_structure(self):
        self.assertEqual("flow_dashboard_asn_src_1m", ASN_AGGREGATE_TABLES["asn_src"]["v1"])
        self.assertEqual("flow_dashboard_asn_src_1m_v2", ASN_AGGREGATE_TABLES["asn_src"]["v2"])
        self.assertEqual("flow_dashboard_asn_dst_1m", ASN_AGGREGATE_TABLES["asn_dst"]["v1"])
        self.assertEqual("flow_dashboard_asn_dst_1m_v2", ASN_AGGREGATE_TABLES["asn_dst"]["v2"])


if __name__ == "__main__":
    unittest.main()
