#!/usr/bin/env python3
"""Build or lint a Portappix recipe.

A recipe (recipes/<id>.json, see recipe.schema.json) pins a vendor's official
portable Windows zip archive: download URL, sha256, byte size, plus the
app.json manifest that wraps it into a Portappix package.

Modes:
  --lint-only   Validate the recipe against recipe.schema.json, check URL
                scheme/hash format, and run the Portappix policy rules on the
                embedded manifest. No network access. Used by CI.
  --verify      Additionally download the vendor archive and verify the pinned
                sha256 and byte size (full pin check). Heavy; run on release.
  (default)     Build: like --verify, then inject app.json into the extracted
                archive and re-zip it as a Portappix package. Writes
                <out>/<id>.package.zip and <out>/<id>.build.json (sha256 +
                size of the built package for build_catalog.py).

Never commits vendor binaries: recipes only ever reference vendor URLs plus
pinned hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import requests
from jsonschema import Draft202012Validator, FormatChecker

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR.parent / "scripts"))

from validate_catalog import (  # noqa: E402
    CHUNK_SIZE,
    REQUEST_TIMEOUT,
    USER_AGENT,
    load_json,
    validate_manifest_policy,
    validate_zip_entry_name,
)

CHUNK = CHUNK_SIZE
TIMEOUT = REQUEST_TIMEOUT
USER_AGENT = "Portappix-Recipe-Builder/1.0"
MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 20000


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_recipe(recipe: Any, schema: Any, schema_path: Path) -> list[str]:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = []
    for error in sorted(validator.iter_errors(recipe), key=lambda e: list(e.absolute_path)):
        location = "/".join(str(part) for part in error.absolute_path)
        errors.append(f"{location}: {error.message}" if location else error.message)
    if errors:
        print(f"Recipe schema: FAILED against {schema_path.name}")
        for message in errors:
            print(f"  - {message}")
    else:
        print(f"Recipe schema: OK ({schema_path.name})")
    return errors


def check_recipe_semantics(recipe: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    source = recipe["source"]
    if not source["url"].startswith("https://"):
        problems.append("source.url must use https://")
    if len(source["sha256"]) != 64:
        problems.append("source.sha256 must be 64 hex characters")
    if source["size"] <= 0:
        problems.append("source.size should be the vendor archive's exact byte size")

    manifest_problems = validate_manifest_policy(recipe["manifest"])
    problems.extend(f"manifest: {problem}" for problem in manifest_problems)
    return problems


def stream_download(url: str, destination: Path) -> None:
    with requests.get(
        url, stream=True, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True
    ) as response:
        response.raise_for_status()
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=CHUNK):
                if chunk:
                    handle.write(chunk)


def verify_vendor_archive(recipe: dict[str, Any], archive: Path) -> None:
    source = recipe["source"]
    actual_sha256 = sha256_file(archive)
    if actual_sha256 != source["sha256"].lower():
        raise SystemExit(
            f"ERROR: vendor sha256 mismatch for {recipe['id']}: "
            f"pinned {source['sha256'].lower()} but downloaded {actual_sha256}. "
            "The vendor archive changed; re-pin the recipe."
        )
    actual_size = archive.stat().st_size
    if source["size"] > 0 and actual_size != source["size"]:
        raise SystemExit(
            f"ERROR: vendor size mismatch for {recipe['id']}: "
            f"pinned {source['size']} but downloaded {actual_size}."
        )
    print(f"Vendor archive verified: {actual_size} bytes, sha256 {actual_sha256}")


def safe_extract(archive: Path, destination: Path) -> None:
    total_uncompressed = 0
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        if len(names) > MAX_ENTRIES:
            raise SystemExit(f"ERROR: vendor archive has {len(names)} entries; limit is {MAX_ENTRIES}")
        for index, name in enumerate(names):
            for problem in validate_zip_entry_name(name):
                raise SystemExit(f"ERROR: unsafe vendor zip entry '{name}': {problem}")
            total_uncompressed += zf.infolist()[index].file_size
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise SystemExit("ERROR: vendor archive expands beyond the 2 GiB cap")
        zf.extractall(destination)


def write_app_json(recipe: dict[str, Any], destination: Path) -> None:
    manifest = recipe["manifest"]
    app_json: dict[str, Any] = {
        "schema": 1,
        "id": recipe["id"],
        "name": recipe["name"],
        "version": recipe["version"],
        "category": recipe["category"],
        "exe": manifest["exe"],
    }
    if recipe.get("publisher"):
        app_json["publisher"] = recipe["publisher"]
    if manifest.get("args"):
        app_json["args"] = manifest["args"]
    if manifest.get("dataVersion"):
        app_json["dataVersion"] = manifest["dataVersion"]
    if manifest.get("env"):
        app_json["env"] = manifest["env"]
    if manifest.get("junctions"):
        app_json["junctions"] = manifest["junctions"]
    if manifest.get("registry"):
        app_json["registry"] = manifest["registry"]

    (destination / "app.json").write_text(
        json.dumps(app_json, indent=2) + "\n", encoding="utf-8"
    )


def build_package(recipe: dict[str, Any], archive: Path, out: Path) -> Path:
    with tempfile.TemporaryDirectory(prefix="portappix-recipe-") as temp:
        extract_dir = Path(temp) / "extract"
        extract_dir.mkdir()
        safe_extract(archive, extract_dir)
        write_app_json(recipe, extract_dir)

        package_path = out / f"{recipe['id']}.package.zip"
        with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(extract_dir.rglob("*")):
                if path.is_file():
                    # Fixed timestamp + sorted order keep builds reproducible.
                    info = zipfile.ZipInfo(
                        path.relative_to(extract_dir).as_posix(),
                        date_time=(1980, 1, 1, 0, 0, 0),
                    )
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o644 << 16
                    zf.writestr(info, path.read_bytes())

    package_sha256 = sha256_file(package_path)
    package_size = package_path.stat().st_size
    build_manifest = {
        "schema": 1,
        "id": recipe["id"],
        "version": recipe["version"],
        "package": package_path.name,
        "sha256": package_sha256,
        "size": package_size,
        "source": recipe["source"]["url"],
        "sourceSha256": recipe["source"]["sha256"].lower(),
    }
    build_file = out / f"{recipe['id']}.build.json"
    build_file.write_text(json.dumps(build_manifest, indent=2) + "\n", encoding="utf-8")

    print(f"Built package: {package_path} ({package_size} bytes, sha256 {package_sha256})")
    print(f"Build manifest: {build_file}")
    return package_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or lint a Portappix recipe")
    parser.add_argument("recipe", type=Path, help="Path to recipes/<id>.json")
    parser.add_argument("--schema", type=Path, default=Path("recipe.schema.json"))
    parser.add_argument("--out", type=Path, default=Path("dist"),
                        help="Output folder for the built package (default: dist)")
    parser.add_argument("--lint-only", action="store_true",
                        help="Schema + policy checks only; no network access")
    parser.add_argument("--verify", action="store_true",
                        help="Download the vendor archive and verify the pinned hash")
    args = parser.parse_args(argv)

    recipe_path = args.recipe.resolve()
    recipe = load_json(recipe_path, "recipe")
    schema = load_json(args.schema, "recipe schema")

    errors = validate_recipe(recipe, schema, args.schema)
    if errors:
        return 1
    problems = check_recipe_semantics(recipe)
    if problems:
        print("Recipe semantics: FAILED")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("Recipe semantics: OK (policy + pin format)")

    if args.lint_only:
        print(f"Lint OK: {recipe_path.name}")
        return 0

    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="portappix-download-") as temp:
        archive = Path(temp) / "vendor.zip"
        stream_download(recipe["source"]["url"], archive)
        verify_vendor_archive(recipe, archive)

        if args.verify:
            print(f"Verify OK: {recipe_path.name}")
            return 0

        build_package(recipe, archive, out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
