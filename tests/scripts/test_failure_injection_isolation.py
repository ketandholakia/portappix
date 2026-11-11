#!/usr/bin/env python3
"""Remediation regression tests: failure-injection seam isolation.

Hand-rolled assertion harness in the spirit of test_crash_hook_isolation.py.
The deterministic failure-injection seams (PortappixWriteHook in
Portappix.Common, PortappixRenameHook / PortappixSpawnErrorCode in
Portappix.Update, the PortappixTestInjectMarker constant) exist ONLY in
binaries compiled with {$IFDEF PORTAPPIX_TESTINJECT}. This suite verifies:

  1. Source scan: every code reference to the injection identifiers in
     src/ sits inside an active {$IFDEF PORTAPPIX_TESTINJECT} region, and
     every reference to the rollback-record key override in
     src/Portappix.RecordAuth.pas sits inside an active
     {$IFDEF PORTAPPIX_TESTCRASH} region (0 exposed references, with
     vacuous-scan guards proving the needles really occur).
  2. Byte scans: the production launchers contain NO TESTINJECT marker
     (UTF-16LE and UTF-8); the test-config test binaries (compiled with
     PORTAPPIX_TESTINJECT) DO contain it.
  3. make_release.py staging guard: rejects a launcher carrying the
     TESTINJECT marker, still accepts a production-like launcher, still
     fails closed on empty/unreadable launchers.

By default the artifacts are located under %TEMP% in the remediation build
directories (remed-prod-w32*, remed-prod-w64*, remed-tests-w32-inject*,
remed-tests-w64-inject*). Missing artifacts are a FAILURE: the isolation
claim is only meaningful against real binaries.

Exit code 0 = all checks passed, 1 = any failure.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
sys.path.insert(0, str(SCRIPTS))

from make_release import (  # noqa: E402
    TESTINJECT_MARKER,
    launcher_forbidden_material,
)

TESTINJECT_DEFINE = "PORTAPPIX_TESTINJECT"
TESTCRASH_DEFINE = "PORTAPPIX_TESTCRASH"

# src files that declare or use the failure-injection seams.
INJECT_SOURCE_FILES = [
    "src/Portappix.Common.pas",
    "src/Portappix.Update.pas",
]
INJECT_NEEDLES = [
    "PortappixWriteHook",
    "PortappixRenameHook",
    "PortappixSpawnErrorCode",
    "PortappixTestInjectMarker",
    "DispatchWriteHook",
    "TPortappixWriteHookResult",
    "TPortappixRenameHook",
]
# src file that declares the test-only rollback key override.
KEY_OVERRIDE_FILE = "src/Portappix.RecordAuth.pas"
KEY_OVERRIDE_NEEDLE = "PortappixRecordKeyPathOverride"

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


def find_artifact(pattern: str, name: str = "Launcher.exe") -> Path | None:
    """Newest matching file under %TEMP%\\<pattern>-*/; None if absent."""
    for candidate in sorted(
        Path(tempfile.gettempdir()).glob(f"{pattern}-*/{name}"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        return candidate
    return None


def contains_bytes(data: bytes, needle: str) -> bool:
    """Case-sensitive byte search in both plausible literal encodings."""
    return (
        needle.encode("utf-16-le") in data
        or needle.encode("utf-8") in data
    )


def strip_comments(text: str) -> str:
    """Remove Delphi line comments; keep everything else line-aligned."""
    start = text.find("//")
    return text[:start] if start >= 0 else text


def is_comment_line(line: str) -> bool:
    return line.strip(" \t").startswith("{")


def scan_source_for_needle(path: Path, needle: str, define: str) -> int:
    """Count CODE occurrences of `needle` outside an active
    {$IFDEF <define>} region. Handles nested IFDEF/IFNDEF/ELSE/ENDIF;
    non-Portappix conditions are treated conservatively as inactive.
    """
    stack: list[bool] = []
    exposure = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if is_comment_line(stripped):
                upper = stripped.upper()
                if upper.startswith("{$IFDEF " + define):
                    stack.append(True)
                    continue
                if upper.startswith("{$IFNDEF " + define):
                    stack.append(False)
                    continue
                if upper.startswith("{$IFDEF ") or upper.startswith("{$IF "):
                    stack.append(False)  # unknown/other define: conservative
                    continue
                if upper.startswith("{$ELSE}"):
                    if stack:
                        stack[-1] = not stack[-1]
                    continue
                if upper.startswith("{$ENDIF}") or upper.startswith("{$IFEND}"):
                    if stack:
                        stack.pop()
                    continue
                # Real block-comment text; not code.
                continue
            active = all(stack) if stack else False
            code = strip_comments(line)
            if needle in code and not active:
                exposure += 1
    return exposure


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prod-w32", default=None,
                        help="Path to the production Win32 Launcher.exe")
    parser.add_argument("--prod-w64", default=None,
                        help="Path to the production Win64 Launcher.exe")
    parser.add_argument("--test-w32", default=None,
                        help="Path to the test-config Win32 PortappixTests.exe")
    parser.add_argument("--test-w64", default=None,
                        help="Path to the test-config Win64 PortappixTests.exe")
    args = parser.parse_args(argv)

    prod_w32 = Path(args.prod_w32) if args.prod_w32 else find_artifact("remed-prod-w32")
    prod_w64 = Path(args.prod_w64) if args.prod_w64 else find_artifact("remed-prod-w64")
    test_w32 = Path(args.test_w32) if args.test_w32 else find_artifact(
        "remed-tests-w32-inject", "PortappixTests.exe")
    test_w64 = Path(args.test_w64) if args.test_w64 else find_artifact(
        "remed-tests-w64-inject", "PortappixTests.exe")

    # 1. Source scan: injection seams only inside TESTINJECT regions.
    for name in INJECT_SOURCE_FILES:
        path = REPO / name
        if not check(path.is_file(), f"{name} exists"):
            continue
        for needle in INJECT_NEEDLES:
            if needle not in path.read_text(encoding="utf-8", errors="replace"):
                continue  # needle legitimately absent from this file
            exposure = scan_source_for_needle(path, needle, TESTINJECT_DEFINE)
            check(exposure == 0,
                  f"{name}: {needle} appears only inside active "
                  f"$IFDEF {TESTINJECT_DEFINE} regions ({exposure} exposed)")

    # Vacuous-scan guard: the needles must really occur across the scanned
    # sources, otherwise the exposure checks above prove nothing.
    raw_all = "\n".join(
        (REPO / n).read_text(encoding="utf-8", errors="replace")
        for n in INJECT_SOURCE_FILES
        if (REPO / n).is_file()
    )
    for needle in ("PortappixWriteHook", "PortappixRenameHook",
                   "PortappixSpawnErrorCode", "PortappixTestInjectMarker"):
        check(needle in raw_all,
              f"source scan guard: {needle} does occur in the scanned sources")

    # 1b. The rollback-record key override sits behind TESTCRASH.
    key_path = REPO / KEY_OVERRIDE_FILE
    if check(key_path.is_file(), f"{KEY_OVERRIDE_FILE} exists"):
        exposure = scan_source_for_needle(key_path, KEY_OVERRIDE_NEEDLE,
                                          TESTCRASH_DEFINE)
        check(exposure == 0,
              f"{KEY_OVERRIDE_FILE}: {KEY_OVERRIDE_NEEDLE} appears only inside "
              f"active $IFDEF {TESTCRASH_DEFINE} regions ({exposure} exposed)")
        check(KEY_OVERRIDE_NEEDLE in key_path.read_text(encoding="utf-8",
                                                        errors="replace"),
              f"{KEY_OVERRIDE_FILE}: the key-override scan guard is not vacuous")

    # 2. Binary scans.
    for label, path in [
        ("production Win32", prod_w32),
        ("production Win64", prod_w64),
    ]:
        if not check(path is not None and path.is_file(),
                     f"{label} production artifact exists ({path})"):
            continue
        data = path.read_bytes()
        check(len(data) > 0, f"{label} production artifact is non-empty")
        check(not contains_bytes(data, TESTINJECT_MARKER),
              f"{label} launcher contains no TESTINJECT marker")

    for label, path in [
        ("test-config Win32", test_w32),
        ("test-config Win64", test_w64),
    ]:
        if not check(path is not None and path.is_file(),
                     f"{label} test artifact exists ({path})"):
            continue
        data = path.read_bytes()
        check(len(data) > 0, f"{label} test artifact is non-empty")
        check(contains_bytes(data, TESTINJECT_MARKER),
              f"{label} test binary contains the TESTINJECT marker")

    # 3. make_release.py staging guard behaviors for the new needle.
    with tempfile.TemporaryDirectory(prefix="remed-relguard-") as tmp:
        staging = Path(tmp) / "staging"
        staging.mkdir()

        good = staging / "Launcher.exe"
        good.write_bytes(b"MZ" + bytes(128))
        check(launcher_forbidden_material(good) == [],
              "guard accepts a production-like synthetic launcher")

        marked = staging / "LauncherInjectMarker"
        marked.write_bytes(
            TESTINJECT_MARKER.encode("utf-16-le") + b"MZ" + bytes(128))
        check(launcher_forbidden_material(marked) != [],
              "guard rejects a launcher carrying the TESTINJECT marker")

        marked8 = staging / "LauncherInjectMarker8"
        marked8.write_bytes(
            TESTINJECT_MARKER.encode("utf-8") + b"MZ" + bytes(128))
        check(launcher_forbidden_material(marked8) != [],
              "guard rejects a launcher carrying the TESTINJECT marker (utf-8)")

        empty = staging / "LauncherEmpty"
        empty.write_bytes(b"")
        check(launcher_forbidden_material(empty) != [],
              "guard rejects an empty launcher")

        directory = staging / "LauncherDir"
        directory.mkdir()
        check(launcher_forbidden_material(directory) != [],
              "guard rejects an unreadable launcher (directory path)")

    print()
    print(f"Result: {Passed} passed, {Failed} failed")
    return 0 if Failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
