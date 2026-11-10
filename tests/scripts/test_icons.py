#!/usr/bin/env python3
"""Regression tests for the Portappix icon pipeline.

Hand-rolled assertion harness in the same spirit as test_signing_workflow.py
(no test framework).

The artwork in ``portappix_icons`` ships as PNG-compressed .ico files.
Windows loads those, but the Borland resource compiler cannot embed them
(``brcc32`` fails with "Allocate failed") and a PNG entry is not a valid
``RT_ICON`` resource, so the launcher would lose its icon. The pipeline is:

    scripts/convert_icons.py   PNG-compressed .ico -> DIB .ico (portappix_icons/dib)
    src/PortappixIcons.rc      the .rc that embeds them
    brcc32                     -> src/PortappixIcons.res (tracked)
    src/Portappix.Icons.pas    loads the resources at runtime

These tests verify every link of that chain:

  1. The converter turns every artwork .ico into a DIB .ico (no PNG entry
     survives) and keeps the size ladder intact.
  2. The converter is deterministic (same bytes on a second run).
  3. src/PortappixIcons.rc references the CONVERTED icons, not the
     PNG-compressed originals.
  4. src/PortappixIcons.res contains the expected resources: RT_ICON
     entries for every image, an RT_GROUP_ICON per icon file and the
     RT_RCDATA application artwork.
  5. The resource ids the runtime loads (src/Portappix.Icons.pas) exist in
     the compiled resource.

Exit code 0 = all checks passed, 1 = any failure.
"""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ICON_DIR = REPO / "portappix_icons"
RC_FILE = REPO / "src" / "PortappixIcons.rc"
RES_FILE = REPO / "src" / "PortappixIcons.res"
ICON_UNIT = REPO / "src" / "Portappix.Icons.pas"
CONVERTER = REPO / "scripts" / "convert_icons.py"

ARTWORK = [
    "portappix.ico",
    "portappix-tray-normal.ico",
    "portappix-tray-running.ico",
    "portappix-tray-paused.ico",
    "portappix-tray-error.ico",
    "portappix-tray-inactive.ico",
]

RT_ICON = 3
RT_GROUP_ICON = 14
RT_RCDATA = 10

Passed = 0
Failed = 0


def check(condition: bool, name: str) -> bool:
    global Passed, Failed
    if condition:
        Passed += 1
        print(f"PASS: {name}")
    else:
        Failed += 1
        print(f"FAIL: {name}")
    return condition


def parse_ico(data: bytes) -> list[tuple[int, int, bytes]]:
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or kind != 1:
        raise ValueError("not an icon file")
    entries = []
    for index in range(count):
        width, height, _c, _r, _p, _bpp, size, offset = struct.unpack_from(
            "<BBBBHHII", data, 6 + 16 * index
        )
        entries.append((width or 256, height or 256, data[offset:offset + size]))
    return entries


def is_png(data: bytes) -> bool:
    return data[:8] == b"\x89PNG\r\n\x1a\n"


def parse_res(path: Path) -> list[tuple[int, int]]:
    """Return [(type_ordinal, name_ordinal)] of every resource in a .res."""
    data = path.read_bytes()
    entries: list[tuple[int, int]] = []
    pos = 32  # the 32-byte RES header
    while pos + 12 <= len(data):
        data_size, header_size = struct.unpack_from("<II", data, pos)
        p = pos + 8
        type_marker = struct.unpack_from("<H", data, p)[0]
        p += 2
        if type_marker != 0xFFFF:
            break
        type_ordinal = struct.unpack_from("<H", data, p)[0]
        p += 2
        name_marker = struct.unpack_from("<H", data, p)[0]
        p += 2
        if name_marker != 0xFFFF:
            break
        name_ordinal = struct.unpack_from("<I", data, p)[0]
        p += 4
        entries.append((type_ordinal, name_ordinal))
        pos = (pos + header_size + data_size + 3) & ~3
    return entries


def main() -> int:
    python = sys.executable or "python"

    # 1-2. The converter produces DIB icons and is deterministic.
    with tempfile.TemporaryDirectory(prefix="p4a-icons-") as tmp:
        first = Path(tmp) / "first"
        second = Path(tmp) / "second"
        for target in (first, second):
            run = subprocess.run(
                [python, str(CONVERTER), "--output", str(target)],
                capture_output=True, text=True, cwd=str(REPO), timeout=300,
            )
            if not check(run.returncode == 0,
                         f"convert_icons.py succeeds for {target.name}"):
                print(run.stdout[-500:])
                continue
        for name in ARTWORK:
            source = ICON_DIR / name
            converted = first / name
            if not check(source.is_file(), f"artwork {name} exists"):
                continue
            if not check(converted.is_file(),
                         f"converted {name} exists"):
                continue
            try:
                source_entries = parse_ico(source.read_bytes())
                converted_entries = parse_ico(converted.read_bytes())
            except (ValueError, struct.error) as exc:
                check(False, f"{name} parses as an icon ({exc})")
                continue
            check(all(is_png(entry[2]) for entry in source_entries),
                  f"artwork {name} is PNG-compressed (as shipped)")
            check(not any(is_png(entry[2]) for entry in converted_entries),
                  f"converted {name} contains no PNG entry")
            check(all(entry[2][:4] == b"\x28\x00\x00\x00"
                      for entry in converted_entries),
                  f"converted {name} entries are DIB (BITMAPINFOHEADER)")
            check([(w, h) for w, h, _ in source_entries] ==
                  [(w, h) for w, h, _ in converted_entries],
                  f"converted {name} keeps the original size ladder")
            check((first / name).read_bytes() == (second / name).read_bytes(),
                  f"converted {name} is deterministic")

    # 3. The resource script embeds the CONVERTED icons.
    if check(RC_FILE.is_file(), "src/PortappixIcons.rc exists"):
        rc_text = RC_FILE.read_text(encoding="utf-8", errors="replace")
        for name in ARTWORK:
            check(f"portappix_icons\\\\dib\\\\{name}" in rc_text,
                  f"the .rc embeds the converted {name}")
            check(f'"portappix_icons\\\\{name}"' not in rc_text,
                  f"the .rc does not embed the PNG-compressed {name}")
        check("RCDATA" in rc_text and "portappix-app.png" in rc_text,
              "the .rc embeds the application artwork as RCDATA")

    # 4-5. The compiled resource holds the icons and the artwork.
    if check(RES_FILE.is_file(), "src/PortappixIcons.res exists"):
        try:
            entries = parse_res(RES_FILE)
        except (ValueError, struct.error) as exc:
            entries = []
            check(False, f"the .res parses ({exc})")
        icons = [name for kind, name in entries if kind == RT_ICON]
        groups = [name for kind, name in entries if kind == RT_GROUP_ICON]
        rcdatas = [name for kind, name in entries if kind == RT_RCDATA]
        check(len(icons) >= 32,
              f"the .res holds every icon image ({len(icons)} RT_ICON entries)")
        check(len(groups) == len(ARTWORK),
              f"the .res holds one group per icon file ({len(groups)})")
        check(len(rcdatas) == 1, "the .res holds the application artwork")

        # The runtime loads icons 1..6 and the artwork as RCDATA 10.
        for resource_id in range(1, len(ARTWORK) + 1):
            check(resource_id in groups,
                  f"group icon id {resource_id} exists in the resource")
        check(10 in rcdatas, "the RCDATA artwork (id 10) exists in the resource")

        if ICON_UNIT.is_file():
            unit_text = ICON_UNIT.read_text(encoding="utf-8", errors="replace")
            for constant in ("PortappixIconResourceApp",
                             "PortappixIconResourceTrayNormal",
                             "PortappixIconResourceTrayRunning",
                             "PortappixIconResourceTrayPaused",
                             "PortappixIconResourceTrayError",
                             "PortappixIconResourceTrayInactive",
                             "PortappixAppImageResourceId"):
                check(constant in unit_text,
                      f"the runtime unit defines {constant}")

    print()
    print(f"Result: {Passed} passed, {Failed} failed")
    return 0 if Failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
