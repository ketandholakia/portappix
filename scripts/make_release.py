#!/usr/bin/env python3
"""Build a Portappix launcher release: zip + signed releases.json.

The release description (releases.json) is signed with the same ECDSA P-256
raw r||s scheme as catalog.json (reused from sign_catalog.py), so the
launcher's embedded verifier key accepts both files.

Example:
  python scripts/make_release.py --source staging --out dist \
      --version 1.1.0 --channel stable \
      --key keys/catalog_signing_key.pem \
      --url-base https://example.com/downloads

Creates dist/portappix-<version>-<channel>.zip (a zip of the staging folder
with Launcher.exe at its root), writes dist/releases.json with the zip's
sha256/size/url and signs it as dist/releases.json.sig.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from sign_catalog import load_private_key, sign_bytes  # noqa: E402
from package_guard import check_archive, format_findings, path_findings  # noqa: E402

SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)(\.(0|[1-9]\d*))?(\.(0|[1-9]\d*))?$"
)

# Phase 4A: test-mode crash-injection artifacts must never reach a release
# zip. The production launcher compiles NEITHER string (Launcher.dpr arms
# crash checkpoints only under the PORTAPPIX_TESTCRASH define, and
# Portappix.Transactions declares the crash mechanism only under that
# define). Delphi embeds both literals as UTF-16LE, but matching is
# deliberately case-sensitive on both encodings' exact byte patterns so an
# accidental reformulation can't slip through a lax check either.
TESTCRASH_MARKER = "PORTAPPIX-TESTCRASH-BUILD-2026-11-10"
TESTUPDATE_MARKER = "PORTAPPIX-TESTUPDATE-BUILD-2026-11-10"
CRASH_ENV_VAR = "PORTAPPIX_CRASH_AT"


def launcher_forbidden_material(launcher_path: Path) -> list[str]:
    """Fail-closed inspection of the staged launcher executable.

    Returns human-readable problems; an empty list means the launcher can be
    packaged. Never modifies the file. Fails closed when the file cannot be
    read, is empty, or the inspection itself raises.
    """
    try:
        data = launcher_path.read_bytes()
    except OSError as exc:
        return [f"could not read the staged launcher: {exc}"]
    if not data:
        return ["the staged launcher is empty"]
    findings = []
    for needle in (TESTCRASH_MARKER, TESTUPDATE_MARKER, CRASH_ENV_VAR):
        for encoding in ("utf-16-le", "utf-8"):
            encoded = needle.encode(encoding)
            if encoded in data:
                findings.append(
                    f"staged launcher contains {needle} "
                    f"({encoding} byte pattern); it looks like a "
                    f"test-mode binary"
                )
                break
    return findings

# Developer/IDE directories and files that must never enter a release zip.
# Security rules (Git metadata, private keys, secret files) come from
# package_guard.path_findings; the list here covers build/IDE noise and the
# repository-only documentation/test trees.
DEV_DIR_COMPONENTS = {"__pycache__", "__history", ".vs", ".commandcode", ".idea"}
DEV_FILE_SUFFIXES = (".dproj.local", ".identcache", ".local", ".stat", ".dcu")
DEV_FILE_BASENAMES = {".ds_store", "thumbs.db"}
DEV_TOP_LEVEL_DIRS = {"tests", "docs"}


def is_excluded_source_path(rel_posix: str, include_dev_dirs: bool) -> bool:
    lowered = rel_posix.lower()
    if path_findings(rel_posix):
        return True  # Git metadata, private keys, secret files: never packaged.
    components = lowered.split("/")
    if not include_dev_dirs and components[0] in DEV_TOP_LEVEL_DIRS:
        return True
    if any(component in DEV_DIR_COMPONENTS for component in components):
        return True
    if any(lowered.endswith(suffix) for suffix in DEV_FILE_SUFFIXES):
        return True
    return components[-1] in DEV_FILE_BASENAMES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a signed Portappix release")
    parser.add_argument("--source", required=True,
                        help="Staging folder; must contain Launcher.exe at its root")
    parser.add_argument("--out", default="dist",
                        help="Output folder (default: dist)")
    parser.add_argument("--version", required=True,
                        help="Release version, e.g. 1.1.0 (semantic version)")
    parser.add_argument("--channel", default="stable",
                        help="Release channel (default: stable)")
    parser.add_argument("--key", required=True,
                        help="P-256 private key (PEM) used to sign releases.json")
    parser.add_argument("--url-base", default="",
                        help="https:// base URL for the release zip; when omitted "
                             "the url field is just the zip file name")
    parser.add_argument("--allow-insecure-url-base", action="store_true",
                        help="Test-only: allow an http:// --url-base (local test server)")
    parser.add_argument("--notes", default="",
                        help="Optional release notes stored in releases.json")
    parser.add_argument("--include-dev-dirs", action="store_true",
                        help="Include top-level tests/ and docs/ trees (developer "
                             "content is excluded by default)")
    args = parser.parse_args(argv)

    if not SEMVER_RE.match(args.version):
        print(f"ERROR: --version must be a semantic version (major[.minor[.patch]]), got: {args.version}")
        return 1

    source = Path(args.source)
    if not (source / "Launcher.exe").is_file():
        print(f"ERROR: staging folder must contain Launcher.exe at its root: {source}")
        return 1

    # Phase 4A staging guard: inspect the ACTUAL staged release artifact
    # (not a development binary) for test-mode crash-injection material
    # before anything is packaged. Fails closed on missing, unreadable or
    # empty files and on inspection errors. Runs before the package guard so
    # a test-mode launcher never produces a zip to begin with, and it does
    # not weaken the existing package guard in any way.
    guard_errors = launcher_forbidden_material(source / "Launcher.exe")
    if guard_errors:
        print("ERROR: staged Launcher.exe failed the test-crash isolation "
              "check and must NOT be packaged or published:")
        for problem in guard_errors:
            print(f"  - {problem}")
        print("Rebuild the release launcher without "
              "-DPORTAPPIX_TESTCRASH / -DPORTAPPIX_TESTUPDATE or remove the test "
              "artifact from the staging folder.")
        return 1
    print("Test isolation guard: OK (staged Launcher.exe contains no "
          f"{TESTCRASH_MARKER} / {TESTUPDATE_MARKER} / {CRASH_ENV_VAR} bytes)")

    if args.url_base and not args.url_base.startswith("https://"):
        if not args.allow_insecure_url_base:
            print("ERROR: --url-base must be an https:// URL (or pass --allow-insecure-url-base)")
            return 1
        print("WARNING: insecure http:// url-base is for local test servers only")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    zip_name = f"portappix-{args.version}-{args.channel}.zip"
    zip_path = out / zip_name

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            rel_posix = path.relative_to(source).as_posix()
            if is_excluded_source_path(rel_posix, args.include_dev_dirs):
                print(f"  excluded: {rel_posix}")
                continue
            zf.write(path, rel_posix)

    # Automated package-security verification: enumerate the archive we just
    # built and refuse to publish it if forbidden material made it in anyway.
    findings = check_archive(zip_path)
    if findings:
        print(f"ERROR: release zip contains forbidden material and must NOT be "
              f"uploaded: {zip_path}")
        print(format_findings(findings))
        print("Package guard: FAILED; remove the offending files from the staging "
              "folder and rebuild.")
        return 1
    print("Package guard: OK (no .git/, private keys, or secret files in the release zip)")

    data = zip_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    size = len(data)

    url = f"{args.url_base.rstrip('/')}/{zip_name}" if args.url_base else zip_name
    releases = {
        "schema": 1,
        "channel": args.channel,
        "version": args.version,
        "url": url,
        "sha256": sha256,
        "size": size,
        "releasedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if args.notes:
        releases["notes"] = args.notes

    releases_path = out / "releases.json"
    releases_path.write_text(json.dumps(releases, indent=2) + "\n", encoding="utf-8")

    key = load_private_key(Path(args.key))
    signature = sign_bytes(releases_path.read_bytes(), key)
    signature_path = out / "releases.json.sig"
    signature_path.write_bytes(signature)

    print(f"Release zip: {zip_path} ({size} bytes)")
    print(f"  sha256: {sha256}")
    print(f"releases.json: {releases_path}")
    print(f"Signature: {signature_path}")
    print(f"URL: {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
