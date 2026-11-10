#!/usr/bin/env python3
"""Convert PNG-compressed .ico files into DIB-compressed .ico files.

Why this exists
---------------
The artwork in ``portappix_icons`` ships as *PNG-compressed* icon files
(every ICO entry is a PNG stream). Windows itself loads those fine, but:

* the Borland resource compiler (``brcc32``) refuses them
  ("Allocate failed"), and
* a PNG-compressed entry is not a valid ``RT_ICON`` resource, so it cannot
  be used as the icon of the built executable.

A classic (DIB/BMP) icon entry is required for both, so this script
re-encodes every entry as 32-bit BGRA + AND mask without changing the
artwork or the size ladder.

The converter is dependency-free (standard library only): PNG decoding is
implemented here with ``zlib`` for the 8-bit RGBA, non-interlaced images
used by these assets.

Usage:
    python scripts/convert_icons.py                 # convert in place layout
    python scripts/convert_icons.py --check         # verify only, no writes

Exit code 0 = success, 1 = failure.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE_DIR = REPO / "portappix_icons"
OUTPUT_DIR = SOURCE_DIR / "dib"

# Every .ico in the artwork folder is converted; the names are stable so
# the resource script (src/PortappixIcons.rc) can reference them.
ICON_NAMES = [
    "portappix.ico",
    "portappix-tray-normal.ico",
    "portappix-tray-running.ico",
    "portappix-tray-paused.ico",
    "portappix-tray-error.ico",
    "portappix-tray-inactive.ico",
]


class ConversionError(Exception):
    """Raised when an icon or a PNG stream cannot be decoded."""


def decode_png(data: bytes) -> tuple[int, int, bytearray]:
    """Decode an 8-bit RGBA, non-interlaced PNG into (width, height, RGBA)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ConversionError("not a PNG stream")
    pos = 8
    width = height = 0
    idat = bytearray()
    while pos + 8 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        payload = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, color, _comp, _filt, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            if depth != 8 or color != 6 or interlace != 0:
                raise ConversionError(
                    f"unsupported PNG format (depth={depth}, color={color}, "
                    f"interlace={interlace}); only 8-bit RGBA is supported"
                )
        elif kind == b"IDAT":
            idat += payload
        elif kind == b"IEND":
            break
        pos += 12 + length
    if width == 0 or height == 0:
        raise ConversionError("PNG without an IHDR chunk")

    raw = zlib.decompress(bytes(idat))
    stride = width * 4
    expected = (stride + 1) * height
    if len(raw) < expected:
        raise ConversionError(
            f"PNG data too short ({len(raw)} bytes, expected {expected})"
        )

    # Undo the per-scanline PNG filters (types 0-4).
    out = bytearray(stride * height)
    prev = bytearray(stride)
    for row in range(height):
        start = row * (stride + 1)
        filter_type = raw[start]
        line = bytearray(raw[start + 1:start + 1 + stride])
        if filter_type == 0:
            pass
        elif filter_type == 1:  # Sub
            for i in range(4, stride):
                line[i] = (line[i] + line[i - 4]) & 0xFF
        elif filter_type == 2:  # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif filter_type == 3:  # Average
            for i in range(stride):
                left = line[i - 4] if i >= 4 else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif filter_type == 4:  # Paeth
            for i in range(stride):
                left = line[i - 4] if i >= 4 else 0
                up = prev[i]
                up_left = prev[i - 4] if i >= 4 else 0
                p = left + up - up_left
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - up_left)
                if pa <= pb and pa <= pc:
                    predictor = left
                elif pb <= pc:
                    predictor = up
                else:
                    predictor = up_left
                line[i] = (line[i] + predictor) & 0xFF
        else:
            raise ConversionError(f"unknown PNG filter type {filter_type}")
        out[row * stride:(row + 1) * stride] = line
        prev = line
    return width, height, out


def dib_from_rgba(width: int, height: int, rgba: bytearray) -> bytes:
    """Build an ICO DIB entry (BITMAPINFOHEADER + BGRA XOR + AND mask)."""
    header = struct.pack(
        "<IiiHHIIiiII",
        40,          # biSize
        width,       # biWidth
        height * 2,  # biHeight: image + mask
        1,           # biPlanes
        32,          # biBitCount
        0,           # biCompression = BI_RGB
        width * height * 4,  # biSizeImage
        0, 0, 0, 0,
    )
    xor = bytearray(width * height * 4)
    for row in range(height):
        src = (height - 1 - row) * width * 4  # DIB rows are bottom-up
        dst = row * width * 4
        for col in range(width):
            s = src + col * 4
            d = dst + col * 4
            xor[d] = rgba[s + 2]      # B
            xor[d + 1] = rgba[s + 1]  # G
            xor[d + 2] = rgba[s]      # R
            xor[d + 3] = rgba[s + 3]  # A
    mask_row = ((width + 31) // 32) * 4  # 1bpp rows padded to 4 bytes
    mask = bytes(mask_row * height)      # transparency lives in the alpha channel
    return bytes(header) + bytes(xor) + mask


def parse_ico(data: bytes) -> list[tuple[int, int, bytes]]:
    """Return [(width, height, image_bytes)] for every entry of an .ico."""
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or kind != 1:
        raise ConversionError("not an icon file")
    entries = []
    for index in range(count):
        width, height, _colors, _res, _planes, _bpp, size, offset = struct.unpack_from(
            "<BBBBHHII", data, 6 + 16 * index
        )
        if offset + size > len(data):
            raise ConversionError(f"entry {index} points outside the file")
        entries.append((width or 256, height or 256, data[offset:offset + size]))
    return entries


def build_ico(entries: list[tuple[int, int, bytes]]) -> bytes:
    out = bytearray(struct.pack("<HHH", 0, 1, len(entries)))
    offset = 6 + 16 * len(entries)
    payloads = []
    for width, height, image in entries:
        out += struct.pack(
            "<BBBBHHII",
            0 if width >= 256 else width,
            0 if height >= 256 else height,
            0, 0, 1, 32, len(image), offset,
        )
        payloads.append(image)
        offset += len(image)
    for image in payloads:
        out += image
    return bytes(out)


def convert_file(source: Path, target: Path) -> str:
    entries = parse_ico(source.read_bytes())
    converted = []
    for width, height, image in entries:
        if image[:8] == b"\x89PNG\r\n\x1a\n":
            png_width, png_height, rgba = decode_png(image)
            if (png_width, png_height) != (width, height):
                raise ConversionError(
                    f"{source.name}: entry {width}x{height} PNG says "
                    f"{png_width}x{png_height}"
                )
            converted.append((width, height, dib_from_rgba(width, height, rgba)))
        else:
            # Already a DIB entry: keep it as-is.
            converted.append((width, height, image))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(build_ico(converted))
    return (f"{source.name}: {len(entries)} entries -> DIB "
            f"({target.stat().st_size} bytes)")


def verify(path: Path) -> None:
    entries = parse_ico(path.read_bytes())
    for width, height, image in entries:
        if image[:8] == b"\x89PNG\r\n\x1a\n":
            raise ConversionError(f"{path.name}: still contains a PNG entry")
        if image[:4] != b"\x28\x00\x00\x00":
            raise ConversionError(f"{path.name}: entry is not a BITMAPINFOHEADER DIB")
        header_w, header_h = struct.unpack_from("<ii", image, 4)
        if header_w != width or header_h != height * 2:
            raise ConversionError(f"{path.name}: DIB size mismatch")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", default=str(SOURCE_DIR))
    parser.add_argument("--output", default=str(OUTPUT_DIR))
    parser.add_argument("--check", action="store_true",
                        help="verify the converted icons without writing")
    args = parser.parse_args(argv)

    source_dir = Path(args.source)
    output_dir = Path(args.output)
    failures = 0
    for name in ICON_NAMES:
        source = source_dir / name
        target = output_dir / name
        if not source.is_file():
            print(f"FAIL: source icon missing: {source}")
            failures += 1
            continue
        try:
            if args.check:
                verify(target)
                print(f"PASS: {target.relative_to(REPO)} is a DIB icon")
            else:
                print("OK: " + convert_file(source, target))
        except (ConversionError, OSError, zlib.error, struct.error) as exc:
            print(f"FAIL: {name}: {exc}")
            failures += 1
    print()
    print(f"Result: {len(ICON_NAMES) - failures} ok, {failures} failed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
