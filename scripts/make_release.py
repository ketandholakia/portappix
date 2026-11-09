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

SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)(\.(0|[1-9]\d*))?(\.(0|[1-9]\d*))?$"
)


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
    args = parser.parse_args(argv)

    if not SEMVER_RE.match(args.version):
        print(f"ERROR: --version must be a semantic version (major[.minor[.patch]]), got: {args.version}")
        return 1

    source = Path(args.source)
    if not (source / "Launcher.exe").is_file():
        print(f"ERROR: staging folder must contain Launcher.exe at its root: {source}")
        return 1

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
            if path.is_file():
                zf.write(path, path.relative_to(source).as_posix())

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
