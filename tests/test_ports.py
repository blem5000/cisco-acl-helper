"""Tests for unused-port finder (show interfaces parsing). Headless-safe."""

import ast
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ports
import tab_ports

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
                   "Tunnel0", "Null0", "StackPort1", "",
                   "FastEthernet0", "Fa0", "GigabitEthernet0/0",
                   "Gi0/0", "TenGigabitEthernet0/0"):
            self.assertFalse(ports.is_physical(no), no)
        # member-0 switching ports on old platforms stay physical
        self.assertTrue(ports.is_physical("Fa0/1"))

    def test_management_ports_all_platforms(self):
        for mgmt in ("FastEthernet0", "Fa0", "GigabitEthernet0",
                     "GigabitEthernet0/0", "Gi0/0", "TenGigabitEthernet0/0",
                     "mgmt0", "MGMT0", "Management0/0", "Management0/1",
                     "MgmtEth0/RP0/CPU0/0"):
            self.assertTrue(ports.is_management(mgmt), mgmt)
            # never listed, even if idle since forever
            ifs = [{"name": mgmt, "status": "up", "protocol": "up",
                   "description": "", "last_input": "never",
                   "last_output": "never", "last_clearing": "never"}]
            self.assertEqual(ports.find_unused(ifs, 120), [], mgmt)
        # three-part 0/0/0 carries data on ISRs - stays listed
        self.assertFalse(ports.is_management("GigabitEthernet0/0/0"))
        self.assertTrue(ports.is_physical("GigabitEthernet0/0/0"))


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


class RackHelpersTest(unittest.TestCase):
    DEVS = [{"host": "10.0.0.2", "group": "Serwerownia"},
            {"host": "10.0.0.1", "group": "Serwerownia"},
            {"host": "10.0.0.3", "group": ""},
            {"host": "10.0.0.4"},
            {"host": "10.0.0.5", "group": "Magazyn"},
            {"host": "", "group": "Serwerownia"}]

    def test_names_sorted_unique(self):
        self.assertEqual(tab_ports.rack_names(self.DEVS),
                         ["Magazyn", "Serwerownia"])
        self.assertEqual(tab_ports.rack_names([]), [])

    def test_devices_in_list_order_skip_empty_host(self):
        got = [d["host"] for d in tab_ports.rack_devices(self.DEVS,
                                                         "Serwerownia")]
        self.assertEqual(got, ["10.0.0.2", "10.0.0.1"])
        self.assertEqual(tab_ports.rack_devices(self.DEVS, "Brak"), [])


POWER_IOS = """
Available:370.0(w)  Used:28.0(w)  Remaining:342.0(w)

Interface Admin  Oper       Power   Device              Class Max
                            (Watts)
--------- ------ ---------- ------- ------------------- ----- ----
Gi1/0/1   auto   on         6.3     IP Phone 7960       2     15.4
Gi1/0/2   auto   off        0.0     n/a                 n/a   15.4
Gi1/0/3   auto   on         15.4    Ieee PD             0     15.4
Gi1/0/4   never  off        0.0     n/a                 n/a   15.4
"""

POWER_XE = """
Module   Available     Used     Remaining
          (Watts)     (Watts)    (Watts)
------   ---------   --------   ---------
1          1090.0       88.0       1002.0
2           740.0       21.7        718.3
"""


class PowerInlineTest(unittest.TestCase):
    def test_ios_header_and_ports(self):
        poe = ports.parse_power_inline(POWER_IOS)
        self.assertEqual(poe["available"], 370.0)
        self.assertEqual(poe["used"], 28.0)
        self.assertEqual(poe["remaining"], 342.0)
        self.assertEqual(poe["ports"]["gigabitethernet1/0/1"],
                         {"admin": "auto", "oper": "on", "watts": 6.3})
        self.assertEqual(poe["ports"]["gigabitethernet1/0/4"]["oper"], "off")

    def test_module_table(self):
        poe = ports.parse_power_inline(POWER_XE)
        self.assertEqual(poe["available"], 1830.0)
        self.assertEqual(poe["used"], 109.7)
        self.assertEqual(poe["remaining"], 1720.3)
        self.assertEqual(poe["ports"], {})

    def test_derives_remaining(self):
        poe = ports.parse_power_inline(
            "Available:370.0(w)  Used:45.2(w)")
        self.assertAlmostEqual(poe["remaining"], 324.8)

    def test_empty(self):
        poe = ports.parse_power_inline("")
        self.assertIsNone(poe["available"])
        self.assertIsNone(poe["used"])
        self.assertIsNone(poe["remaining"])
        self.assertEqual(poe["ports"], {})


class IdleMonthsTest(unittest.TestCase):
    def test_uses_the_newer_direction(self):
        self.assertAlmostEqual(
            ports.port_idle_months({"last_input": "3w4d",
                                    "last_output": "1w0d"}), 7 / 30)
        self.assertLess(
            ports.port_idle_months({"last_input": "never",
                                    "last_output": "00:00:01"}), 0.001)

    def test_never_is_none(self):
        self.assertIsNone(ports.port_idle_months(
            {"last_input": "never", "last_output": "never"}))
        self.assertIsNone(ports.port_idle_months({}))


class SnapshotTest(unittest.TestCase):
    @staticmethod
    def entry(name, last_input="never", last_output="never"):
        return {"name": name, "status": "down", "protocol": "down",
                "description": "", "last_input": last_input,
                "last_output": last_output, "last_clearing": "never"}

    def test_poe_split(self):
        physical = [self.entry("Gi1/0/1"), self.entry("Gi1/0/2"),
                    self.entry("Gi1/0/3"), self.entry("Gi1/0/4")]
        unused = physical[:2]
        snap = ports.switch_snapshot("sw1", physical, unused, 0,
                                     ports.parse_power_inline(POWER_IOS))
        self.assertEqual(snap["total"], 4)
        self.assertEqual(snap["used"], 2)
        self.assertEqual(snap["free"], 2)
        self.assertEqual(snap["idle_count"], 2)
        self.assertEqual(snap["idle_poe_ports"], 1)
        self.assertEqual(snap["idle_poe_watts"], 6.3)
        self.assertEqual(snap["active_poe"], 1)
        self.assertEqual(snap["active_watts"], 15.4)
        # both idle PoE ports count as free (the powered one is cleanup too)
        self.assertEqual(snap["poe_free"], 2)
        self.assertEqual(snap["poe_left"], 342.0)
        self.assertEqual(snap["idle_never"], 2)

    def test_without_poe_data(self):
        phys = [self.entry("Gi1/0/1"), self.entry("Gi1/0/2")]
        snap = ports.switch_snapshot("sw1", phys, phys[:1], 0, {})
        self.assertEqual((snap["total"], snap["used"], snap["free"]),
                         (2, 1, 1))
        self.assertEqual(snap["active_poe"], 0)
        self.assertIsNone(snap["poe_left"])


class PlanReductionTest(unittest.TestCase):
    @staticmethod
    def sw(host, total, used, poe_free=0, left=0.0, poe_ports=0,
           watts=0.0, avg=0.0):
        return {"host": host, "total": total, "used": used,
                "free": total - used, "poe_free": poe_free,
                "poe_left": left, "active_poe": poe_ports,
                "active_watts": watts, "idle_avg": avg, "idle_count": 1,
                "poe_used": 0.0, "poe_available": left,
                "idle_poe_ports": 0, "idle_poe_watts": 0.0, "err": ""}

    def test_empty_and_single_switch(self):
        self.assertEqual(ports.plan_reduction([])["reason"], "no_data")
        got = ports.plan_reduction([self.sw("A", 48, 10)])
        self.assertEqual(got["reason"], "single")
        self.assertEqual(got["removable"], [])

    def test_removes_underused_switches(self):
        a = self.sw("A", 48, 40, poe_free=5, left=100.0, poe_ports=3,
                    watts=20.0, avg=4)
        b = self.sw("B", 48, 2, poe_free=30, left=300.0, poe_ports=2,
                    watts=10.0, avg=8)
        c = self.sw("C", 48, 5, poe_free=20, left=200.0, poe_ports=1,
                    watts=6.3, avg=2)
        got = ports.plan_reduction([a, b, c])
        self.assertEqual([x["host"] for x in got["removable"]], ["B", "C"])
        self.assertEqual(got["kept"], ["A"])
        self.assertEqual(got["needed"], 1)

    def test_blocks_on_ports(self):
        a = self.sw("A", 48, 40, poe_free=5, left=100.0, avg=4)
        b = self.sw("B", 24, 20, poe_free=0, left=0.0, avg=10)
        got = ports.plan_reduction([a, b])
        self.assertEqual(got["removable"], [])
        self.assertEqual(got["failed"][0]["reason"], "ports")

    def test_blocks_on_power(self):
        a = self.sw("A", 48, 40, poe_free=5, left=30.0, poe_ports=3,
                    watts=20.0, avg=4)
        b = self.sw("B", 24, 1, poe_free=10, left=5.0, poe_ports=1,
                    watts=60.0, avg=10)
        got = ports.plan_reduction([a, b])
        self.assertEqual(got["removable"], [])
        self.assertEqual(got["failed"][0]["reason"], "power")

    def test_blocks_when_poe_budget_unknown(self):
        a = self.sw("A", 48, 40, poe_free=5, left=None, avg=4)
        b = self.sw("B", 24, 1, poe_free=10, left=None, poe_ports=1,
                    watts=10.0, avg=10)
        got = ports.plan_reduction([a, b])
        self.assertEqual(got["removable"], [])
        self.assertEqual(got["failed"][0]["reason"], "poe_unknown")

    def test_idle_poe_draw_returns_to_budget(self):
        a = self.sw("A", 48, 10, poe_free=2, left=0.0, avg=4)
        a["idle_poe_watts"] = 10.0
        b = self.sw("B", 24, 1, poe_free=0, left=0.0, poe_ports=1,
                    watts=6.3, avg=10)
        got = ports.plan_reduction([a, b])
        self.assertEqual([x["host"] for x in got["removable"]], ["B"])
        self.assertAlmostEqual(got["removable"][0]["target_info"][0]["left"],
                               10.0)
        self.assertAlmostEqual(got["removable"][0]["left_watts"], 10.0)


class FetchPortsDataTest(unittest.TestCase):
    dev = {"host": "10.0.0.1", "username": "u", "password": "p"}

    def test_optimization_also_fetches_power_inline(self):
        responses = {
            "show interfaces": SAMPLE,
            "show inventory": "",
            "show interfaces status": "",
            "show power inline": POWER_IOS,
        }
        with mock.patch.object(tab_ports.cisco_ssh, "run_commands",
                               return_value=responses) as run:
            data = tab_ports.fetch_ports_data(
                self.dev, 3, True, with_power=True)
        self.assertIn("show power inline", run.call_args.kwargs["commands"])
        self.assertEqual(data["poe"]["remaining"], 342.0)

    def test_check_does_not_fetch_power_inline(self):
        responses = {
            "show interfaces": SAMPLE,
            "show inventory": "",
            "show interfaces status": "",
        }
        with mock.patch.object(tab_ports.cisco_ssh, "run_commands",
                               return_value=responses) as run:
            data = tab_ports.fetch_ports_data(self.dev, 3, True)
        self.assertNotIn("show power inline", run.call_args.kwargs["commands"])
        self.assertEqual(data["poe"], {})


class TabStructureTest(unittest.TestCase):
    def test_apply_only_uses_widgets_built_at_startup(self):
        # regression: the buttons block once slipped into a method that
        # runs after unlock, while _apply_* runs at startup -> AttributeError
        src_path = os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))), "tab_ports.py")
        with open(src_path, encoding="utf-8") as fh:
            src = fh.read()
        tree = ast.parse(src)
        methods = {n.name: n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef)}
        built = set()
        for n in ast.walk(methods["_build_ports_tab"]):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                    and n.value.id == "self" and isinstance(n.ctx, ast.Store):
                built.add(n.attr)
        used = set()
        for n in ast.walk(methods["_apply_ports_language"]):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                    and n.value.id == "self" and isinstance(n.ctx, ast.Load):
                used.add(n.attr)
        # self.lang is set by App, not the tab
        self.assertEqual(used - built, {"lang"})


if __name__ == "__main__":
    unittest.main()

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

    def test_status_types_9200l_empty_cages(self):
        # 9200L uplink cages: populated GLC-TE vs empty ("unknown")
        status = ("Port      Name               Status       Vlan       Duplex  Speed Type\n"
                  "Gi1/0/33                     connected    56         a-full a-1000 10/100/1000BaseTX\n"
                  "Gi1/1/1                      disabled     trunk        auto   auto unknown\n"
                  "Gi1/1/4                      connected    trunk      a-full a-1000 10/100/1000BaseTX SFP\n")
        types = ports.parse_status_types(status)
        self.assertFalse(ports.is_fiber_type(types["gigabitethernet1/0/33"]))
        self.assertTrue(ports.is_fiber_type(types["gigabitethernet1/1/1"]))
        self.assertTrue(ports.is_fiber_type(types["gigabitethernet1/1/4"]))


if __name__ == "__main__":
    unittest.main()
