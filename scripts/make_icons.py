"""Generate Vaultnote app icons with no third-party dependencies.

Renders a padlock on a rounded dark square, 3x3 supersampled for clean edges,
and writes the PNG + ICO set that Tauri expects.
"""
import math
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src-tauri", "icons")

BG = (0x0D, 0x11, 0x17)
FG = (0x58, 0xA6, 0xFF)
SS = 3  # supersample factor

SHACKLE_CX, SHACKLE_CY = 0.50, 0.415
SHACKLE_R = 0.215
SHACKLE_W = 0.075

BODY = (0.255, 0.745, 0.425, 0.800)  # x0, x1, y0, y1
BODY_R = 0.075

KEY_CX, KEY_CY, KEY_R = 0.50, 0.565, 0.058
KEY_SLOT = (0.474, 0.526, 0.565, 0.680)


def rounded_rect(px, py, x0, x1, y0, y1, r):
    if not (x0 <= px <= x1 and y0 <= py <= y1):
        return False
    cx = min(max(px, x0 + r), x1 - r)
    cy = min(max(py, y0 + r), y1 - r)
    return math.hypot(px - cx, py - cy) <= r + 1e-9


def sample(px, py):
    """Return (r, g, b, a) for a normalised point."""
    # canvas: rounded dark square
    if not rounded_rect(px, py, 0.0, 1.0, 0.0, 1.0, 0.185):
        return (0, 0, 0, 0.0)

    colour = BG

    # padlock body
    if rounded_rect(px, py, *BODY, BODY_R):
        colour = FG
        # keyhole punched back out to the background colour
        d = math.hypot(px - KEY_CX, py - KEY_CY)
        slot = KEY_SLOT[0] <= px <= KEY_SLOT[1] and KEY_SLOT[2] <= py <= KEY_SLOT[3]
        if d <= KEY_R or slot:
            colour = BG
        return colour + (1.0,)

    # shackle: upper-half ring
    d = math.hypot(px - SHACKLE_CX, py - SHACKLE_CY)
    if py <= SHACKLE_CY + 0.01 and abs(d - SHACKLE_R) <= SHACKLE_W / 2:
        return FG + (1.0,)

    return colour + (1.0,)


def render(size):
    """Supersample a size x size RGBA image, alpha-premultiplied to avoid halos."""
    rows = []
    inv = 1.0 / (size * SS)
    for y in range(size):
        row = bytearray()
        for x in range(size):
            ar = ag = ab = aa = 0.0
            for sy in range(SS):
                for sx in range(SS):
                    px = (x * SS + sx + 0.5) * inv
                    py = (y * SS + sy + 0.5) * inv
                    r, g, b, a = sample(px, py)
                    ar += r * a
                    ag += g * a
                    ab += b * a
                    aa += a
            n = SS * SS
            if aa > 0:
                row += bytes((
                    round(ar / aa), round(ag / aa), round(ab / aa), round(255 * aa / n),
                ))
            else:
                row += b"\x00\x00\x00\x00"
        rows.append(bytes(row))
    return rows


def write_png(path, size, rows):
    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(typ, data):
        return (struct.pack(">I", len(data)) + typ + data
                + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)
    return png


def write_ico(path, entries):
    count = len(entries)
    offset = 6 + 16 * count
    header = struct.pack("<HHH", 0, 1, count)
    dir_entries = b""
    for size, blob in entries:
        dim = 0 if size >= 256 else size
        dir_entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    with open(path, "wb") as fh:
        fh.write(header + dir_entries + b"".join(b for _, b in entries))


def main():
    os.makedirs(OUT, exist_ok=True)

    # (filename, size)
    targets = [
        ("32x32.png", 32),
        ("128x128.png", 128),
        ("128x128@2x.png", 256),
        ("icon.png", 512),
    ]

    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    cache = {}

    def rows_for(size):
        if size not in cache:
            cache[size] = render(size)
        return cache[size]

    for name, size in targets:
        data = write_png(os.path.join(OUT, name), size, rows_for(size))
        print(f"  {name:18s} {size:>4}px  {len(data):>7,} bytes")

    ico_entries = []
    for size in ico_sizes:
        tmp = os.path.join(OUT, f"_tmp_{size}.png")
        blob = write_png(tmp, size, rows_for(size))
        ico_entries.append((size, blob))
        os.remove(tmp)
    write_ico(os.path.join(OUT, "icon.ico"), ico_entries)
    print(f"  {'icon.ico':18s}       {len(ico_entries)} sizes embedded")


if __name__ == "__main__":
    main()