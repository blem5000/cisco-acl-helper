"""Natural, case-insensitive ordering for device labels.

Plain ``sorted()`` compares by code point, which puts every uppercase name
before every lowercase one: ``"LGEMA_PROD_1_3"`` sorts before
``"backbone1"`` because ``"L"`` (76) < ``"b"`` (98). It also treats digits
as text, so ``sw10`` lands before ``sw2``. Neither matches how people read a
switch list.

``natural_key`` fixes both: text is folded to lower case and digit runs are
compared as numbers. The result is a plain tuple, so it composes with other
sort fields (e.g. "L3 first, then this").
"""

from __future__ import annotations

import re

_DIGITS = re.compile(r"(\d+)")


def natural_key(text: str) -> tuple:
    """Sort key for one label: case-insensitive, numbers compared as numbers.

    Returns a tuple of ``(kind, value)`` pairs where kind 0 marks a number
    and kind 1 marks text. The kind tag keeps comparisons type-safe when two
    labels differ in shape (``"1sw"`` vs ``"asw"``); a naive mixed tuple of
    ints and strings raises TypeError there.
    """
    out: list[tuple] = []
    for part in _DIGITS.split((text or "").casefold()):
        if not part:
            continue
        if part.isdigit():
            out.append((0, int(part)))
        else:
            out.append((1, part))
    return tuple(out)


def device_sort_key(device: dict, label) -> tuple:
    """Sort key for a device row: L3 switches first, then natural label.

    `label` is the caller's formatter (device -> display string), so this
    module stays independent of the UI layer.
    """
    return (0 if device.get("l3", False) else 1, natural_key(label(device)))
