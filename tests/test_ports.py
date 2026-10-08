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
        # SFP excluded by default: 3 months -> only Gi1/0/2 (never);
        # Gi1/0/1 alive via fresh output, Te alive (5-6w < 3m) anyway
        got = [e["name"] for e in ports.find_unused(ifs, 3)]
        self.assertEqual(got, ["GigabitEthernet1/0/2"])
        # without the SFP skip, 1 month also catches the Te pair
        got1 = [e["name"]
                for e in ports.find_unused(ifs, 1, skip_sfp=False)]
        self.assertEqual(got1, ["GigabitEthernet1/0/2",
                                "TenGigabitEthernet1/1/1"])

    def test_sfp_skip(self):
        for yes in ("Te1/0/1", "TenGigabitEthernet1/1/1", "Twe1/0/13",
                    "TwentyFiveGigE1/0/13", "Hu1/0/49", "Fo1/0/1"):
            self.assertTrue(ports.is_sfp(yes), yes)
        for no in ("Gi1/0/1", "Fa0/1", "FiveGigabitEthernet1/0/2",
                   "Vlan1", "Port-channel1", ""):
            self.assertFalse(ports.is_sfp(no), no)
        ifs = ports.parse_show_interfaces(SAMPLE)
        self.assertNotIn("TenGigabitEthernet1/1/1",
                         [e["name"] for e in ports.find_unused(ifs, 120)])

    def test_stocked_sfp_cages_skipped(self):
        inv = ('NAME: "Switch 1", DESCR: "WS-C2960S-48"\n'
               'NAME: "GigabitEthernet1/0/50", DESCR: "1000BASE-SX SFP"\n'
               'NAME: "GigabitEthernet1/0/52", DESCR: "1000BASE-LX SFP"\n'
               'NAME: "Power Supply 0", DESCR: "Power Supply"\n')
        stocked = ports.parse_inventory_transceivers(inv)
        self.assertEqual(stocked,
                         {"GigabitEthernet1/0/50", "GigabitEthernet1/0/52"})
        ifs = [{"name": "GigabitEthernet1/0/50", "status": "down",
               "protocol": "down", "description": "", "last_input": "never",
               "last_output": "never", "last_clearing": "never"},
               {"name": "GigabitEthernet1/0/20", "status": "down",
               "protocol": "down", "description": "", "last_input": "never",
               "last_output": "never", "last_clearing": "never"}]
        got = [e["name"] for e in ports.find_unused(ifs, 3, True, stocked)]
        self.assertEqual(got, ["GigabitEthernet1/0/20"])
        got_all = [e["name"] for e in ports.find_unused(ifs, 3, False)]
        self.assertEqual(got_all, ["GigabitEthernet1/0/50",
                                   "GigabitEthernet1/0/20"])

    def test_output_keeps_port_used(self):
        ifs = [{"name": "Gi1/0/9", "status": "up", "protocol": "up",
               "description": "", "last_input": "never",
               "last_output": "00:01:00", "last_clearing": "never"}]
        self.assertEqual(ports.find_unused(ifs, 3), [])

    def test_common_clearing(self):
        ifs = ports.parse_show_interfaces(SAMPLE)
        self.assertEqual(ports.common_clearing(ifs), "never")

    def test_status_types_real_world(self):
        status = ("Port      Name               Status       Vlan       Duplex  Speed Type\n"
                  "Gi1/0/48  ==AP122==          connected    trunk      a-full a-1000 10/100/1000BaseTX\n"
                  "Gi1/0/49                     connected    trunk      a-full a-1000 1000BaseSX SFP\n"
                  "Gi1/0/50                     notconnect   1            auto   auto Not Present\n"
                  "Gi1/0/51                     connected    trunk      a-full a-1000 1000BaseSX SFP\n")
        types = ports.parse_status_types(status)
        self.assertEqual(types["gigabitethernet1/0/48"], "10/100/1000BaseTX")
        self.assertEqual(types["gigabitethernet1/0/50"], "Not Present")
        self.assertFalse(ports.is_fiber_type(types["gigabitethernet1/0/48"]))
        for p in ("gigabitethernet1/0/49", "gigabitethernet1/0/50",
                  "gigabitethernet1/0/51"):
            self.assertTrue(ports.is_fiber_type(types[p]), p)
        # empty cage + populated SFP both skipped via the status set
        ifs = [{"name": "GigabitEthernet1/0/48", "status": "down",
               "protocol": "down", "description": "", "last_input": "never",
               "last_output": "never", "last_clearing": "never"},
               {"name": "GigabitEthernet1/0/50", "status": "down",
               "protocol": "down", "description": "", "last_input": "never",
               "last_output": "never", "last_clearing": "never"}]
        stocked = {n for n, t in types.items() if ports.is_fiber_type(t)}
        got = [e["name"] for e in ports.find_unused(ifs, 3, True, stocked)]
        self.assertEqual(got, ["GigabitEthernet1/0/48"])


if __name__ == "__main__":
    unittest.main()
