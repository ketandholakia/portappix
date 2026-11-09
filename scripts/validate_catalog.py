#!/usr/bin/env python3
"""Validate Portappix catalog.json.

Checks performed:
1. JSON Schema validation against catalog.schema.json.
2. For each app entry, stream the package download, compute SHA-256,
   and verify the hash and byte size match the catalog.

Exits with code 1 on any failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import requests
from jsonschema import Draft202012Validator, FormatChecker


CHUNK_SIZE = 1024 * 1024
REQUEST_TIMEOUT = (30, 300)
USER_AGENT = "Portappix-Catalog-Validator/1.0"


def format_json_path(path_parts: list[Any]) -> str:
    if not path_parts:
        return "$"
    result = "$"
    for part in path_parts:
        if isinstance(part, int):
            result += f"[{part}]"
        else:
            result += f".{part}"
    return result


def load_json(path: Path, label: str) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        print(f"ERROR: {label} not found: {path}")
        raise SystemExit(1)
    except json.JSONDecodeError as exc:
        location = f"line {exc.lineno}, column {exc.colno}"
        print(f"ERROR: {label} is not valid JSON ({location}): {exc.msg}")
        raise SystemExit(1)
    except OSError as exc:
        print(f"ERROR: Unable to read {label} '{path}': {exc}")
        raise SystemExit(1)


def validate_schema(catalog: Any, schema: Any, schema_path: Path) -> list[Any]:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(catalog), key=lambda error: list(error.absolute_path))
    if not errors:
        print(f"Schema validation: OK ({schema_path})")
        return []

    print(f"Schema validation: FAILED ({len(errors)} error(s))")
    for error in errors:
        path = format_json_path(list(error.absolute_path))
        print(f"  - {path}: {error.message}")
        if error.validator == "required":
            missing = error.message
            print(f"    required: {missing}")
        if error.validator == "additionalProperties":
            print(f"    details: {error.message}")
    return errors


def app_label(app: dict[str, Any], index: int) -> str:
    name = app.get("name")
    app_id = app.get("id")
    if isinstance(name, str) and name.strip():
        if isinstance(app_id, str) and app_id.strip():
            return f"{name} ({app_id})"
        return name
    if isinstance(app_id, str) and app_id.strip():
        return app_id
    return f"apps[{index}]"


def stream_download_and_hash(url: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    total_size = 0
    headers = {"User-Agent": USER_AGENT}

    with requests.get(url, stream=True, timeout=REQUEST_TIMEOUT, headers=headers) as response:
        response.raise_for_status()
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            if not chunk:
                continue
            digest.update(chunk)
            total_size += len(chunk)

    return digest.hexdigest(), total_size


def verify_app(app: dict[str, Any], index: int) -> bool:
    label = app_label(app, index)
    url = app.get("url")
    expected_hash = str(app.get("sha256", "")).lower()
    expected_size = app.get("size")

    print(f"Validating {label}...")
    print(f"  URL: {url}")

    try:
        actual_hash, actual_size = stream_download_and_hash(str(url))
    except requests.exceptions.RequestException as exc:
        print(f"  Download: FAILED")
        print(f"  ERROR: Unable to download {label}: {exc}")
        return False

    ok = True

    if actual_hash.lower() == expected_hash:
        print(f"  Hash Match: OK ({actual_hash})")
    else:
        print(f"  Hash Match: FAILED")
        print(f"    expected: {expected_hash}")
        print(f"    actual:   {actual_hash}")
        ok = False

    if actual_size == expected_size:
        print(f"  Size Match: OK ({actual_size} bytes)")
    else:
        print(f"  Size Match: FAILED")
        print(f"    expected: {expected_size} bytes")
        print(f"    actual:   {actual_size} bytes")
        ok = False

    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Portappix catalog.json")
    parser.add_argument(
        "--catalog",
        default="catalog.json",
        help="Path to catalog.json (default: catalog.json)",
    )
    parser.add_argument(
        "--schema",
        default="catalog.schema.json",
        help="Path to catalog.schema.json (default: catalog.schema.json)",
    )
    args = parser.parse_args(argv)

    catalog_path = Path(args.catalog)
    schema_path = Path(args.schema)

    print(f"Loading catalog: {catalog_path}")
    catalog = load_json(catalog_path, "catalog.json")
    print(f"Loading schema: {schema_path}")
    schema = load_json(schema_path, "catalog.schema.json")

    if validate_schema(catalog, schema, schema_path):
        return 1

    apps = catalog.get("apps", [])
    if not isinstance(apps, list):
        print('ERROR: Catalog property "$.apps" must be an array.')
        return 1

    if not apps:
        print("No apps to verify.")
        print("Validation: OK")
        return 0

    print(f"Verifying {len(apps)} app package(s)...")
    failures = 0
    for index, app in enumerate(apps):
        if not isinstance(app, dict):
            path = format_json_path(["apps", index])
            print(f"ERROR: {path} must be an object.")
            failures += 1
            continue
        if not verify_app(app, index):
            failures += 1

    if failures:
        print(f"Validation: FAILED ({failures} app(s) with errors)")
        return 1

    print("Validation: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
