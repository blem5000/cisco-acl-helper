"""Natural, case-insensitive device ordering. Headless-safe."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import devsort


def _label(d):
    hn = (d.get("hostname") or "").strip()
    h = d.get("host", "")
    return f"{hn} {h}".strip() if hn else h


def _order(devs):
    return [d["hostname"] for d in
            sorted(devs, key=lambda d: devsort.device_sort_key(d, _label))]


class NaturalKeyTest(unittest.TestCase):
    def test_case_insensitive(self):
        # 'b' must beat 'L': plain sorted() put LGEMA first (L=76 < b=98)
        self.assertEqual(
            sorted(["LGEMA_PROD_1_3", "backbone1"], key=devsort.natural_key),
            ["backbone1", "LGEMA_PROD_1_3"])

    def test_upper_and_lower_are_adjacent(self):
        items = ["Delta", "alpha", "CHARLIE", "bravo"]
        self.assertEqual(
            sorted(items, key=devsort.natural_key),
            ["alpha", "bravo", "CHARLIE", "Delta"])

    def test_numbers_compare_as_numbers(self):
        self.assertEqual(
            sorted(["sw10", "sw2", "sw1"], key=devsort.natural_key),
            ["sw1", "sw2", "sw10"])

    def test_mixed_digits_and_letters(self):
        self.assertEqual(
            sorted(["MAQ_2F_1T_2_5", "MAQ_2F_1T_1_5"],
                   key=devsort.natural_key),
            ["MAQ_2F_1T_1_5", "MAQ_2F_1T_2_5"])

    def test_different_shapes_do_not_raise(self):
        # ints and strings must never be compared directly
        try:
            sorted(["1sw", "asw", "2", "sw"], key=devsort.natural_key)
        except TypeError:
            self.fail("natural_key must be comparable across shapes")

    def test_empty_text(self):
        self.assertEqual(devsort.natural_key(""), ())
        self.assertEqual(devsort.natural_key(None), ())


class DeviceOrderTest(unittest.TestCase):
    DEVS = [
        {"host": "10.202.118.11", "hostname": "LGEMA_PROD_1_3", "l3": True},
        {"host": "10.202.118.15", "hostname": "LGEMA_PROD_1_5", "l3": True},
        {"host": "10.202.118.13", "hostname": "LGEMA_IDM2_1_3", "l3": True},
        {"host": "1.1.1.1", "hostname": "backbone1", "l3": True},
        {"host": "172.26.60.3", "hostname": "MAQ_2F_1T_1_5", "l3": False},
    ]

    def test_l3_first_then_natural(self):
        self.assertEqual(_order(self.DEVS),
                         ["backbone1", "LGEMA_IDM2_1_3", "LGEMA_PROD_1_3",
                          "LGEMA_PROD_1_5", "MAQ_2F_1T_1_5"])

    def test_l3_group_stays_above_l2(self):
        order = _order(self.DEVS)
        self.assertLess(order.index("LGEMA_PROD_1_5"),
                        order.index("MAQ_2F_1T_1_5"))

    def test_l2_sorted_naturally_too(self):
        devs = [{"host": "1.1.1.1", "hostname": "zeta"},
                {"host": "1.1.1.2", "hostname": "Alpha"},
                {"host": "1.1.1.3", "hostname": "beta"}]
        self.assertEqual(_order(devs), ["Alpha", "beta", "zeta"])

    def test_missing_l3_flag_treated_as_l2(self):
        devs = [{"host": "1.1.1.1", "hostname": "zzz"},
                {"host": "1.1.1.2", "hostname": "aaa", "l3": True}]
        self.assertEqual(_order(devs), ["aaa", "zzz"])

    def test_screenshot_case(self):
        # the exact names from the screenshot, backbone added
        order = _order(self.DEVS)
        self.assertEqual(order[0], "backbone1")
        self.assertLess(order.index("LGEMA_IDM2_1_3"),
                        order.index("LGEMA_PROD_1_3"))


if __name__ == "__main__":
    unittest.main()
