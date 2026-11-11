#!/usr/bin/env python3
"""Phase 4A regression tests: production / test-mode crash-hook isolation.

Hand-rolled assertion harness in the same spirit as tests/PortappixTests.dpr
and test_signing_workflow.py (no test framework). Covers:

  1-4. Byte scans of the four launcher build artifacts: the production
       launchers contain NEITHER the test-crash marker nor the
       PORTAPPIX_CRASH_AT string; the test-mode launchers contain BOTH.
       Matching is case-sensitive on the exact bytes, checked in both the
       UTF-16LE representation Delphi embeds for string literals and the
       plain UTF-8/ASCII representation.
  5.   Source scan: every CODE reference to PORTAPPIX_CRASH_AT in
       src/Portappix.Transactions.pas and src/Launcher.dpr sits inside an
       active {$IFDEF PORTAPPIX_TESTCRASH} region, so a production compile
       never sees an environment-variable reader.
  6.   Production CLI behavior is identical with and without
       PORTAPPIX_CRASH_AT set (harmless --check-manifest run; the
       production binary never reads the variable at all).
  7.   make_release.py staging guard: accepts a production-like launcher,
       rejects marker / env-string / both, an empty launcher, an unreadable
       launcher, and a staging folder without Launcher.exe, producing no
       package artifacts on failure. A full production-like release run
       still succeeds end to end.
  8.   The existing test_signing_workflow.py regression suite still passes
       (24/24 baseline).

By default the launcher artifacts are found in the fresh %TEMP% build dirs
produced by the Phase 4A build step (p4a-prod-w32-*, p4a-test-w64-*, ...).
Pass --prod-w32/--prod-w64/--test-w32/--test-w64 to point at specific exes.
Missing artifacts are a FAILURE (the isolation claim is only meaningful
against real binaries).

Exit code 0 = all checks passed, 1 = any failure.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
sys.path.insert(0, str(SCRIPTS))

from make_release import (  # noqa: E402
    CRASH_ENV_VAR,
    TESTCRASH_MARKER,
    TESTUPDATE_MARKER,
    INSECURE_RELEASE_URLS_SWITCH,
    DEV_CATALOG_FLAG,
    launcher_forbidden_material,
)

PYTHON = sys.executable or "python"

TESTCRASH_DEFINE = "PORTAPPIX_TESTCRASH"
SIGNING_TESTS = SCRIPTS.parent / "tests" / "scripts" / "test_signing_workflow.py"
CLI_FIXTURE = REPO / "tests" / "suite" / "apps" / "stublauncher" / "app.json"

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


def find_launcher(expected_dir: str) -> Path | None:
    """Newest Launcher.exe under %TEMP%\\<expected_dir>-*; None if absent."""
    for candidate in sorted(
        Path(tempfile.gettempdir()).glob(f"{expected_dir}-*/Launcher.exe"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        return candidate
    return None


@dataclass
class Artifacts:
    prod_w32: Path | None
    prod_w64: Path | None
    test_w32: Path | None
    test_w64: Path | None


def contains_bytes(data: bytes, needle: str) -> bool:
    """Case-sensitive byte search in both plausible literal encodings."""
    return (
        needle.encode("utf-16-le") in data
        or needle.encode("utf-8") in data
    )


# --- check 5: source scan --------------------------------------------------


@dataclass
class Directive:
    text: str


def strip_comments(text: str) -> str:
    """Remove Delphi line comments; keep everything else line-aligned."""
    start = text.find("//")
    return text[:start] if start >= 0 else text


def is_comment_line(line: str) -> bool:
    return line.strip(" \t").startswith("{")


def scan_source_for_env_var(path: Path) -> int:
    """Count CODE occurrences of PORTAPPIX_CRASH_AT outside an active
    {$IFDEF PORTAPPIX_TESTCRASH} region. Handles nested IFDEF/IFNDEF/ELSE/
    ENDIF directives; non-Portappix conditions are treated conservatively as
    inactive (so code in unknown-conditional regions counts as exposed).
    """
    stack: list[bool] = []
    exposure = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if is_comment_line(stripped):
                upper = stripped.upper()
                if upper.startswith("{$IFDEF " + TESTCRASH_DEFINE):
                    stack.append(True)
                    continue
                if upper.startswith("{$IFNDEF " + TESTCRASH_DEFINE):
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
            if TESTCRASH_DEFINE in code and line.lstrip().startswith("{"):
                # {$IFDEF PORTAPPIX_TESTCRASH} mid-line after code: treat as
                # exposed (conservative) and do not consume state.
                pass
            if CRASH_ENV_VAR in code and not active:
                exposure += 1
    return exposure


# --- check 6: production CLI behavior -------------------------------------


def run_check_manifest(exe: Path, extra_env: dict[str, str] | None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.pop("PORTAPPIX_CRASH_AT", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        # --check-manifest validates the fixture manifest and exits; it never
        # creates a transaction or touches the host beyond reading files.
        [str(exe), "--check-manifest", str(CLI_FIXTURE), "--exit-code-file",
         str(tempfile.gettempdir()) + os.sep + "p4a-cli-exit"],
        capture_output=True, text=True, cwd=str(REPO), env=env, timeout=120,
    )


# --- checks 1-8 -----------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prod-w32", default=None)
    parser.add_argument("--prod-w64", default=None)
    parser.add_argument("--test-w32", default=None)
    parser.add_argument("--test-w64", default=None)
    parser.add_argument("--skip-signing-suite", action="store_true",
                        help="Do not re-run test_signing_workflow.py")
    args = parser.parse_args(argv)

    artifacts = Artifacts(
        prod_w32=Path(args.prod_w32) if args.prod_w32 else find_launcher("p4a-prod-w32"),
        prod_w64=Path(args.prod_w64) if args.prod_w64 else find_launcher("p4a-prod-w64"),
        test_w32=Path(args.test_w32) if args.test_w32 else find_launcher("p4a-test-w32"),
        test_w64=Path(args.test_w64) if args.test_w64 else find_launcher("p4a-test-w64"),
    )

    for label, path in [
        ("production Win32", artifacts.prod_w32),
        ("production Win64", artifacts.prod_w64),
        ("test-mode Win32", artifacts.test_w32),
        ("test-mode Win64", artifacts.test_w64),
    ]:
        if not check(path is not None and path.is_file(),
                     f"{label} build artifact exists ({path})"):
            continue
        data = path.read_bytes()
        check(len(data) > 0, f"{label} build artifact is non-empty")

    # 1-2. Production launchers must contain NEITHER string.
    for label, path in [
        ("production Win32", artifacts.prod_w32),
        ("production Win64", artifacts.prod_w64),
    ]:
        if path is None or not path.is_file():
            continue
        data = path.read_bytes()
        for needle in (TESTCRASH_MARKER, TESTUPDATE_MARKER, CRASH_ENV_VAR, INSECURE_RELEASE_URLS_SWITCH, DEV_CATALOG_FLAG):
            check(not contains_bytes(data, needle),
                  f"{label} launcher contains neither {needle} nor "
                  f"the test marker" if needle == CRASH_ENV_VAR else
                  f"{label} launcher does not contain the marker {needle}")

    # 3-4. Test-mode launchers must contain BOTH strings.
    for label, path in [
        ("test-mode Win32", artifacts.test_w32),
        ("test-mode Win64", artifacts.test_w64),
    ]:
        if path is None or not path.is_file():
            continue
        data = path.read_bytes()
        for needle in (TESTCRASH_MARKER, CRASH_ENV_VAR):
            check(contains_bytes(data, needle),
                  f"{label} launcher contains {needle}")

    # 5. Source references sit behind the compile-time define.
    for name in ("src/Portappix.Transactions.pas", "src/Launcher.dpr"):
        path = REPO / name
        if not check(path.is_file(), f"{name} exists"):
            continue
        exposure = scan_source_for_env_var(path)
        check(exposure == 0, name + ": PORTAPPIX_CRASH_AT appears only inside "
              "active $IFDEF PORTAPPIX_TESTCRASH regions (" +
              str(exposure) + " exposed code references)")
        # Vacuous-scan guard: the needle must actually occur in the file
        # (raw text incl. comments), otherwise the exposure check above
        # proves nothing.
        check(CRASH_ENV_VAR in path.read_text(encoding="utf-8", errors="replace"),
              f"{name}: the source scan did find documented raw references "
              f"(guarding against a vacuous scan)")

    # 6. Production CLI behavior unchanged with PORTAPPIX_CRASH_AT set.
    if artifacts.prod_w32 is not None and artifacts.prod_w32.is_file():
        baseline = run_check_manifest(artifacts.prod_w32, None)
        armed = run_check_manifest(artifacts.prod_w32,
                                   {"PORTAPPIX_CRASH_AT": "state:prepared"})
        garbage = run_check_manifest(artifacts.prod_w32,
                                     {"PORTAPPIX_CRASH_AT": "not-a-checkpoint"})
        check(baseline.returncode == armed.returncode == garbage.returncode,
              "production launcher exit code unchanged with PORTAPPIX_CRASH_AT "
              f"({baseline.returncode} / {armed.returncode} / {garbage.returncode})")
        check(baseline.stdout == armed.stdout == garbage.stdout,
              "production launcher stdout unchanged with PORTAPPIX_CRASH_AT")
        check(baseline.stderr == armed.stderr == garbage.stderr,
              "production launcher stderr unchanged with PORTAPPIX_CRASH_AT")
    else:
        check(False, "production CLI behavior comparison had a launcher to run")

    # 7. make_release.py staging guard behaviors.
    with tempfile.TemporaryDirectory(prefix="p4a-relguard-") as tmp:
        root = Path(tmp)
        staging = root / "staging"
        staging.mkdir()
        out = root / "dist"

        good = staging / "Launcher.exe"
        good.write_bytes(b"MZ" + bytes(128))  # production-like synthetic bytes

        check(launcher_forbidden_material(good) == [],
              "guard accepts a production-like synthetic launcher")

        marked = staging / "LauncherMarker"
        marked.write_bytes(
            TESTCRASH_MARKER.encode("utf-16-le") + b"MZ" + bytes(128))
        check(launcher_forbidden_material(marked) != [],
              "guard rejects a launcher carrying the test-crash marker")

        update_marked = staging / "LauncherUpdateMarker"
        update_marked.write_bytes(
            TESTUPDATE_MARKER.encode("utf-16-le") + b"MZ" + bytes(128))
        check(launcher_forbidden_material(update_marked) != [],
              "guard rejects a launcher carrying the test-update marker")

        envstr = staging / "LauncherEnv"
        envstr.write_bytes(
            CRASH_ENV_VAR.encode("utf-8") + b"MZ" + bytes(128))
        check(launcher_forbidden_material(envstr) != [],
              "guard rejects a launcher carrying PORTAPPIX_CRASH_AT")

        insecure_str = staging / "LauncherInsecure"
        insecure_str.write_bytes(
            INSECURE_RELEASE_URLS_SWITCH.encode("utf-8") + b"MZ" + bytes(128))
        check(launcher_forbidden_material(insecure_str) != [],
              "guard rejects a launcher carrying allow-insecure-release-urls")

        insecure_str16 = staging / "LauncherInsecure16"
        insecure_str16.write_bytes(
            INSECURE_RELEASE_URLS_SWITCH.encode("utf-16-le") + b"MZ" + bytes(128))
        check(launcher_forbidden_material(insecure_str16) != [],
              "guard rejects a launcher carrying allow-insecure-release-urls (utf-16-le)")

        devcat_str = staging / "LauncherDevCat"
        devcat_str.write_bytes(
            DEV_CATALOG_FLAG.encode("utf-8") + b"MZ" + bytes(128))
        check(launcher_forbidden_material(devcat_str) != [],
              "guard rejects a launcher carrying AllowUnsignedCatalogs")

        devcat_str16 = staging / "LauncherDevCat16"
        devcat_str16.write_bytes(
            DEV_CATALOG_FLAG.encode("utf-16-le") + b"MZ" + bytes(128))
        check(launcher_forbidden_material(devcat_str16) != [],
              "guard rejects a launcher carrying AllowUnsignedCatalogs (utf-16-le)")

        both = staging / "LauncherBoth"
        both.write_bytes(
            CRASH_ENV_VAR.encode("utf-16-le")
            + TESTCRASH_MARKER.encode("utf-16-le") + b"MZ" + bytes(128))
        findings = launcher_forbidden_material(both)
        check(len(findings) == 2,
              "guard rejects a launcher carrying BOTH strings with two findings")

        empty = staging / "LauncherEmpty"
        empty.write_bytes(b"")
        check(launcher_forbidden_material(empty) != [],
              "guard rejects an empty launcher")

        directory = staging / "LauncherDir"
        directory.mkdir()
        check(launcher_forbidden_material(directory) != [],
              "guard rejects an unreadable launcher (directory path)")

        # Full release run with a production-like synthetic launcher.
        key = root / "key.pem"
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        private = ec.generate_private_key(ec.SECP256R1())
        key.write_bytes(private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        run = subprocess.run(
            [PYTHON, str(SCRIPTS / "make_release.py"),
             "--source", str(staging), "--out", str(out),
             "--version", "9.9.9", "--channel", "stable",
             "--key", str(key)],
            capture_output=True, text=True, cwd=str(REPO), timeout=120)
        check(run.returncode == 0,
              "make_release accepts a production-like staging launcher "
              f"(exit {run.returncode})")
        check((out / "portappix-9.9.9-stable.zip").is_file(),
              "make_release produced the release zip for a valid launcher")
        check((out / "releases.json").is_file()
              and (out / "releases.json.sig").is_file(),
              "make_release produced signed releases.json for a valid launcher")

        # Full release run with a test-mode launcher staged in: refuse, and
        # leave NO package artifacts behind.
        reject_out = root / "reject-dist"
        (staging / "Launcher.exe").write_bytes(
            (TESTCRASH_MARKER + " production filler").encode("utf-16-le"))
        run = subprocess.run(
            [PYTHON, str(SCRIPTS / "make_release.py"),
             "--source", str(staging), "--out", str(reject_out),
             "--version", "9.9.10", "--channel", "stable",
             "--key", str(key)],
            capture_output=True, text=True, cwd=str(REPO), timeout=120)
        check(run.returncode == 1,
              "make_release rejects a marker-carrying staged launcher "
              f"(exit {run.returncode})")
        check(TESTCRASH_MARKER in (run.stdout + run.stderr),
              "the refusal explains the detected marker")
        check(not any(reject_out.glob("*.zip")) if reject_out.exists() else True,
              "the refusal packaged no zip")
        check(not ((reject_out / "releases.json").is_file()
                   if reject_out.exists() else False),
              "the refusal wrote no releases.json")

        # Missing launcher: rejected by the pre-existing staging check.
        nostage = root / "nostage"
        nostage.mkdir()
        run = subprocess.run(
            [PYTHON, str(SCRIPTS / "make_release.py"),
             "--source", str(nostage), "--out", str(root / "none-dist"),
             "--version", "9.9.11", "--channel", "stable",
             "--key", str(key)],
            capture_output=True, text=True, cwd=str(REPO), timeout=120)
        check(run.returncode == 1,
              "make_release rejects a staging folder without Launcher.exe")

    # 8. Existing regression suite still passes.
    if not args.skip_signing_suite:
        run = subprocess.run(
            [PYTHON, str(SIGNING_TESTS)],
            capture_output=True, text=True, cwd=str(REPO), timeout=600)
        check(run.returncode == 0,
              f"test_signing_workflow.py passes (exit {run.returncode})")
        print(run.stdout[-800:] if run.stdout else "")

    print()
    print(f"Result: {Passed} passed, {Failed} failed")
    return 0 if Failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
