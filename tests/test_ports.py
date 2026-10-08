"""Tests for unused-port finder (show interfaces parsing). Headless-safe."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ports

SAMPLE = """
GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is aaaa.bbbb.cccc (bia aaaa.bbbb.cccc)
  Description: Uplink to core
  Last input 3w4d, output 00:00:12, output hang never
  Last clearing of "show interface" counters never
GigabitEthernet1/0/2 is administratively down, line protocol is down (disabled)
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
Vlan57 is up, line protocol is up
  Last input never, output 00:00:01, output hang never
  Last clearing of "show interface" counters never
Port-channel1 is down, line protocol is down
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
TenGigabitEthernet1/1/1 is down, line protocol is down (notconnect)
  Description: Camera 5
  Last input 5w0d, output 6w0d, output hang never
  Last clearing of "show interface" counters 4w2d
Loopback0 is up, line protocol is up
  Last input never, output never, output hang never
"""


class ParseAgeTest(unittest.TestCase):
    def test_formats(self):
        self.assertIsNone(ports.parse_age("never"))
        self.assertIsNone(ports.parse_age(""))
        self.assertEqual(ports.parse_age("00:00:00"), 0)
        self.assertEqual(ports.parse_age("00:00:12"), 12)
        self.assertEqual(ports.parse_age("1d05h"), 86400 + 5 * 3600)
        self.assertEqual(ports.parse_age("3w4d"), 3 * 7 * 86400 + 4 * 86400)
        self.assertEqual(ports.parse_age("5w0d"), 5 * 7 * 86400)


class ParseInterfacesTest(unittest.TestCase):
    def test_fields(self):
        ifs = ports.parse_show_interfaces(SAMPLE)
        self.assertEqual(len(ifs), 6)
        up = ifs[0]
        self.assertEqual(up["name"], "GigabitEthernet1/0/1")
        self.assertEqual(up["status"], "up")
        self.assertEqual(up["description"], "Uplink to core")
        self.assertEqual(up["last_input"], "3w4d")
        self.assertEqual(up["last_output"], "00:00:12")
        self.assertEqual(ifs[1]["status"], "admin down")
        self.assertEqual(ifs[3]["name"], "Port-channel1")

    def test_physical_filter(self):
        for yes in ("Gi1/0/1", "GigabitEthernet1/0/1", "Te1/1/1",
                    "Twe1/0/13", "TwentyFiveGigE1/0/13", "Fa0/1",
                    "FiveGigabitEthernet1/0/2", "Fo1/0/1", "Hu1/0/49"):
            self.assertTrue(ports.is_physical(yes), yes)
        for no in ("Vlan57", "Port-channel1", "Po10", "Loopback0",
                   "Tunnel0", "Null0", "StackPort1", ""):
            self.assertFalse(ports.is_physical(no), no)


class FindUnusedTest(unittest.TestCase):
    def test_threshold_and_direction(self):
        ifs = ports.parse_show_interfaces(SAMPLE)
        # 3 months: Gi1/0/1 alive via output, Te1/1/1 alive (5-6w < 3m);
        # Gi1/0/2 (never) unused; Vlan/Po/Loopback never listed
        got = [e["name"] for e in ports.find_unused(ifs, 3)]
        self.assertEqual(got, ["GigabitEthernet1/0/2"])
        # 1 month: Te pair joins (input 5w + output 6w both older);
        # Gi1/0/1 stays used via fresh output 00:00:12
        got1 = [e["name"] for e in ports.find_unused(ifs, 1)]
        self.assertEqual(got1, ["GigabitEthernet1/0/2",
                                "TenGigabitEthernet1/1/1"])

    def test_output_keeps_port_used(self):
        ifs = [{"name": "Gi1/0/9", "status": "up", "protocol": "up",
               "description": "", "last_input": "never",
               "last_output": "00:01:00", "last_clearing": "never"}]
        self.assertEqual(ports.find_unused(ifs, 3), [])

    def test_common_clearing(self):
        ifs = ports.parse_show_interfaces(SAMPLE)
        self.assertEqual(ports.common_clearing(ifs), "never")


if __name__ == "__main__":
    unittest.main()
