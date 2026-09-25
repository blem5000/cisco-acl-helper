"""Tests for device/subnet sort keys (App statics). Headless-safe."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import App


class SortKeyTest(unittest.TestCase):
    def test_host_ips_numeric_then_names(self):
        hosts = ["10.0.0.10", "10.0.0.9", "sw-core", "10.0.0.2",
                 "SW-Agg", ""]
        self.assertEqual(sorted(hosts, key=App._host_key),
                         ["10.0.0.2", "10.0.0.9", "10.0.0.10",
                          "", "SW-Agg", "sw-core"])

    def test_subnet_network_order(self):
        subs = ["10.0.0.0/24", "10.0.0.128/25", "9.0.0.0/8"]
        self.assertEqual(sorted(subs, key=App._subnet_key),
                         ["9.0.0.0/8", "10.0.0.0/24", "10.0.0.128/25"])


if __name__ == "__main__":
    unittest.main()
