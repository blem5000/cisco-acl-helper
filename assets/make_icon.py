"""Generate assets/app.ico (stdlib only, no Pillow needed).

Motif: Cisco-blue rounded square with a white ACL entry list and a
green check badge. Rerun after tweaks:  python assets/make_icon.py
"""

import os
import struct
import zlib

SIZE = 256
BG_TOP = (6, 159, 217, 255)      # Cisco blue
BG_BOTTOM = (2, 110, 165, 255)
EDGE = (1, 80, 125, 255)
WHITE = (255, 255, 255, 235)
GREEN = (46, 170, 70, 255)
GREEN_DARK = (30, 130, 55, 255)


def _lerp(a, b, t):
    return tuple(int(x + (y - x) * t) for x, y in zip(a, b))


class Canvas:
    def __init__(self, size):
        self.s = size
        self.px = bytearray(size * size * 4)

    def set(self, x, y, color):
        if 0 <= x < self.s and 0 <= y < self.s:
            i = (y * self.s + x) * 4
            self.px[i:i + 4] = bytes(color)

    def disc(self, cx, cy, r, color):
        for y in range(int(cy - r), int(cy + r) + 1):
            for x in range(int(cx - r), int(cx + r) + 1):
                if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                    self.set(x, y, color)

    def rect(self, x0, y0, x1, y1, color, radius=0):
        for y in range(y0, y1):
            for x in range(x0, x1):
                if radius:
                    cx = min(max(x, x0 + radius), x1 - radius - 1)
                    cy = min(max(y, y0 + radius), y1 - radius - 1)
                    if (x - cx) ** 2 + (y - cy) ** 2 > radius * radius:
                        continue
                self.set(x, y, color)

    def thick_line(self, x0, y0, x1, y1, w, color):
        dx, dy = x1 - x0, y1 - y0
        steps = max(abs(dx), abs(dy), 1) * 2
        for i in range(steps + 1):
            t = i / steps
            self.disc(x0 + dx * t, y0 + dy * t, w / 2, color)


def draw(size):
    c = Canvas(size)
    k = size / 256.0

    def R(v):
        return int(v * k)

    # background: vertical gradient rounded square + edge
    for y in range(R(8), R(248)):
        t = (y - R(8)) / max(R(248) - R(8) - 1, 1)
        c.rect(R(8), y, R(248), y + 1, _lerp(BG_TOP, BG_BOTTOM, t))
    # round the corners by clearing outside a rounded rect
    rad = R(48)
    for y in range(size):
        for x in range(size):
            cx = min(max(x, R(8) + rad), R(248) - rad - 1)
            cy = min(max(y, R(8) + rad), R(248) - rad - 1)
            if (x - cx) ** 2 + (y - cy) ** 2 > rad * rad:
                c.set(x, y, (0, 0, 0, 0))
    # inner edge
    for y in range(R(8), R(248)):
        for x in (R(8), R(9), R(10), R(245), R(246), R(247)):
            c.set(x, y, EDGE)
    for x in range(R(8), R(248)):
        for y in (R(8), R(9), R(10), R(245), R(246), R(247)):
            c.set(x, y, EDGE)

    # ACL entry list: bullets + bars
    for i, yy in enumerate((72, 122, 172)):
        y0 = R(yy)
        c.rect(R(48), y0, R(72), y0 + R(22), WHITE, radius=R(5))
        c.rect(R(84), y0, R(176 - i * 18), y0 + R(22), WHITE, radius=R(8))

    # green check badge
    bx, by, br = R(188), R(188), R(54)
    c.disc(bx, by, br, (255, 255, 255, 255))
    c.disc(bx, by, br - R(7), GREEN)
    c.thick_line(bx - R(22), by + R(1), bx - R(6), by + R(17), R(15), WHITE)
    c.thick_line(bx - R(6), by + R(17), bx + R(24), by - R(15), R(15), WHITE)
    _ = GREEN_DARK
    return c.px


def downscale(px256, dst):
    """Area-average 256px RGBA buffer down to dst x dst."""
    src = 256
    out = bytearray(dst * dst * 4)
    for y in range(dst):
        for x in range(dst):
            rs = gs = bs = als = cnt = 0
            for yy in range(y * src // dst, (y + 1) * src // dst):
                for xx in range(x * src // dst, (x + 1) * src // dst):
                    i = (yy * src + xx) * 4
                    r, g, b, a = px256[i:i + 4]
                    rs += r * a
                    gs += g * a
                    bs += b * a
                    als += a
                    cnt += 1
            j = (y * dst + x) * 4
            if als and cnt:
                out[j:j + 4] = bytes((rs // als, gs // als, bs // als,
                                      als // cnt))
            else:
                out[j:j + 4] = bytes((0, 0, 0, 0))
    return bytes(out)


def png(size, px):
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + px[y * size * 4:(y + 1) * size * 4]
                   for y in range(size))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6,
                                         0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def ico(path):
    base = draw(256)
    images = []
    for size in (256, 48, 32, 16):
        px = base if size == 256 else downscale(base, size)
        images.append(png(size, px))
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for size, data in zip((256, 48, 32, 16), images):
        w = 0 if size == 256 else size
        out += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(data),
                           offset)
        offset += len(data)
    for data in images:
        out += data
    with open(path, "wb") as f:
        f.write(out)
    print(f"wrote {path} ({len(out) // 1024} KB)")


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    ico(os.path.join(here, "app.ico"))
