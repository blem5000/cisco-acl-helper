"""Zrzut vs sortowanie: sprawdzenie na dokladnych nazwach z ekranu."""
import os
import sys

sys.path.insert(0, r"C:\Users\admin\acl-release")

from tab_gen import GeneratorTabMixin


class V:
    def __init__(self, v):
        self.v = v

    def get(self):
        return self.v


class H(GeneratorTabMixin):
    pass


DEVS = [
    {"host": "10.202.118.11", "hostname": "LGEMA_PROD_1_3", "l3": True},
    {"host": "10.202.118.15", "hostname": "LGEMA_PROD_1_5", "l3": True},
    {"host": "10.202.118.13", "hostname": "LGEMA_IDM2_1_3", "l3": True},
    {"host": "172.26.60.3", "hostname": "MAQ_2F_1T_1_5", "l3": False},
    {"host": "172.26.60.4", "hostname": "MAQ_2F_1T_2_5", "l3": False},
]


def show(title, devs):
    h = H()
    h.only_l3_var = V(False)
    h.devices = [dict(d) for d in devs]
    h.dev_label = lambda d: (
        f"{d.get('hostname')} {d.get('host')}".strip()
        if d.get("hostname") else d.get("host", ""))
    print(f"--- {title} ---")
    for d in h._visible_devices():
        print(("L3 " if d.get("l3") else "L2 "), h.dev_label(d))
    print()


show("wszystkie L3 (IDM2 tez L3)", DEVS)
show("IDM2 jest L2", [dict(d, l3=False) if d["hostname"] == "LGEMA_IDM2_1_3"
                      else d for d in DEVS])
