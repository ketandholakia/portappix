#!/usr/bin/env python3
"""Validate Portappix catalog.json.

Checks performed:
1. JSON Schema validation against catalog.schema.json.
2. Duplicate app ids.
3. For each app entry: stream the package download, compute SHA-256 and byte size.
4. Inspect each package zip: entry count/size limits, zip-slip entries, app.json at
   the archive root, manifest id matching the catalog id, and the same registry /
   junction / environment policy rules as Portappix.Policy (Delphi side).

Exits with code 1 on any failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import requests
from jsonschema import Draft202012Validator, FormatChecker


CHUNK_SIZE = 1024 * 1024
REQUEST_TIMEOUT = (30, 300)
USER_AGENT = "Portappix-Catalog-Validator/2.0"
MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 20000

ALLOWED_ENV = {
    "APPDATA", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP", "HOME", "PATH",
    "PATHEXT", "COMSPEC", "PROGRAMDATA", "PUBLIC", "XDG_CONFIG_HOME",
    "XDG_DATA_HOME", "XDG_CACHE_HOME", "USERNAME",
}
PATH_LIKE_ENV = {"PATH", "PATHEXT"}
DENIED_REGISTRY_VENDORS = {
    "microsoft", "classes", "policies", "windows", "windows nt", "currentversion",
}
DENIED_PATH_COMPONENTS = {
    "documents", "desktop", "downloads", "onedrive", "windows", "system32",
    "program files", "program files (x86)",
}
ALLOWED_JUNCTION_PATTERNS = [
    re.compile(r"^%APPDATA%\\[^\\]+", re.IGNORECASE),
    re.compile(r"^%LOCALAPPDATA%\\[^\\]+", re.IGNORECASE),
    re.compile(r"^%PROGRAMDATA%\\[^\\]+", re.IGNORECASE),
    re.compile(r"^%USERPROFILE%\\\.[^\\]+", re.IGNORECASE),
    re.compile(r"^[A-Za-z]:\\ProgramData\\[^\\]+", re.IGNORECASE),
    re.compile(
        r"^[A-Za-z]:\\Users\\[^\\]+\\AppData\\(Roaming|Local)\\[^\\]+", re.IGNORECASE
    ),
    re.compile(r"^[A-Za-z]:\\Users\\[^\\]+\\\.[^\\]+", re.IGNORECASE),
]


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


def normalize_windows_path(value: str) -> str:
    return ntpath.normpath(value.replace("/", "\\"))


def stream_download_and_hash(url: str, destination: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total_size = 0
    headers = {"User-Agent": USER_AGENT}

    with requests.get(url, stream=True, timeout=REQUEST_TIMEOUT, headers=headers) as response:
        response.raise_for_status()
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                if not chunk:
                    continue
                digest.update(chunk)
                total_size += len(chunk)
                handle.write(chunk)

    return digest.hexdigest(), total_size


def validate_registry_path(key: str) -> list[str]:
    errors: list[str] = []
    if "\\" not in key:
        return [f"registry path {key!r} is invalid"]
    root, subkey = key.split("\\", 1)
    if root.upper() not in {"HKCU", "HKEY_CURRENT_USER"}:
        return [f"registry path {key!r} must be under HKCU\\Software"]
    parts = [part for part in subkey.split("\\") if part]
    if len(parts) < 3 or parts[0].lower() != "software":
        return [
            f"registry path {key!r} must be HKCU\\Software\\<vendor>\\<app> "
            "(at least two levels below HKCU\\Software)"
        ]
    if parts[1].lower() in DENIED_REGISTRY_VENDORS:
        errors.append(f"registry path {key!r} uses a reserved vendor {parts[1]!r}")
    return errors


def validate_junction_host(host: str) -> list[str]:
    if not host.strip():
        return ["junction host path must not be empty"]
    if "{" in host:
        return [f"junction host {host!r} must not contain manifest tokens"]

    normalized = normalize_windows_path(host.strip())
    if ".." in normalized.split("\\"):
        return [f"junction host {host!r} must not contain path traversal"]

    for component in normalized.split("\\"):
        if component.lower() in DENIED_PATH_COMPONENTS:
            return [f"junction host {host!r} is in a protected system or user folder"]

    for pattern in ALLOWED_JUNCTION_PATTERNS:
        if pattern.match(normalized):
            return []
    return [
        f"junction host {host!r} must be inside %APPDATA%, %LOCALAPPDATA%, "
        "%PROGRAMDATA%, or %USERPROFILE%\\.<name>"
    ]


def validate_junction_target(target: str) -> list[str]:
    if not target.strip():
        return ["junction target must not be empty"]
    if ".." in normalize_windows_path(target).split("\\"):
        return [f"junction target {target!r} must not contain path traversal"]
    if "{data}" in target.lower() or "{app}" in target.lower() or "{root}" in target.lower():
        return []
    if not ntpath.isabs(target):
        return []
    return [f"junction target {target!r} must live inside the portable {{data}} directory"]


def validate_environment(env: Any) -> list[str]:
    errors: list[str] = []
    if env is None:
        return errors
    if not isinstance(env, dict):
        return ["manifest env must be an object"]

    for name, value in env.items():
        if not isinstance(name, str) or not name:
            errors.append("manifest env contains an invalid variable name")
            continue
        if name.upper() not in ALLOWED_ENV:
            errors.append(
                f"environment variable {name!r} is not in the allow-list"
            )
            continue
        if name.upper() in PATH_LIKE_ENV:
            text = str(value)
            if "{app}" not in text.lower() and "{data}" not in text.lower():
                errors.append(
                    f"path-like environment variable {name!r} must reference {{app}} or {{data}}"
                )
    return errors


def validate_manifest_policy(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    registry = manifest.get("registry", [])
    if registry is not None and not isinstance(registry, list):
        errors.append("manifest registry must be an array")
    elif isinstance(registry, list):
        for key in registry:
            if not isinstance(key, str):
                errors.append("manifest registry entries must be strings")
                continue
            errors.extend(validate_registry_path(key))

    junctions = manifest.get("junctions", {})
    if junctions is not None and not isinstance(junctions, dict):
        errors.append("manifest junctions must be an object")
    elif isinstance(junctions, dict):
        for host, target in junctions.items():
            errors.extend(validate_junction_host(str(host)))
            errors.extend(validate_junction_target(str(target)))

    errors.extend(validate_environment(manifest.get("env")))
    return errors


def validate_zip_entry_name(name: str) -> list[str]:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return [f"zip entry {name!r} is an absolute path"]
    parts = normalized.split("/")
    if ".." in parts:
        return [f"zip entry {name!r} escapes the archive root"]
    return []


def inspect_package(path: Path, app: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                return [f"package has {len(entries)} entries; the limit is {MAX_ENTRIES}"]

            total = sum(max(0, entry.file_size) for entry in entries)
            if total > MAX_UNCOMPRESSED_BYTES:
                return [
                    f"package expands to {total} bytes; the limit is "
                    f"{MAX_UNCOMPRESSED_BYTES}"
                ]

            for entry in entries:
                errors.extend(validate_zip_entry_name(entry.filename))

            if "__MACOSX/" in archive.namelist():
                errors.append("package contains macOS metadata (__MACOSX)")

            if "app.json" not in archive.namelist():
                errors.append("package does not contain app.json at the archive root")
                return errors

            try:
                manifest = json.loads(archive.read("app.json").decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                return errors + [f"app.json is not valid UTF-8 JSON: {exc}"]

            if not isinstance(manifest, dict):
                return errors + ["app.json must contain a JSON object"]

            expected_id = str(app.get("id", ""))
            manifest_id = manifest.get("id")
            if not isinstance(manifest_id, str) or manifest_id != expected_id:
                errors.append(
                    f"manifest id {manifest_id!r} does not match catalog id {expected_id!r}"
                )

            for key in ("exe", "id"):
                if not isinstance(manifest.get(key), str) or not manifest.get(key):
                    errors.append(f"manifest is missing a valid {key!r}")

            errors.extend(validate_manifest_policy(manifest))
    except zipfile.BadZipFile:
        errors.append("package is not a valid zip archive")
    return errors


def verify_app(app: dict[str, Any], index: int, workdir: Path) -> bool:
    label = app_label(app, index)
    url = str(app.get("url", ""))
    expected_hash = str(app.get("sha256", "")).lower()
    expected_size = app.get("size", 0)

    print(f"Validating {label}...")
    print(f"  URL: {url}")

    if not url.lower().startswith("https://"):
        print("  URL: FAILED (https:// is required)")
        return False

    package_path = workdir / f"package-{index}.zip"
    try:
        actual_hash, actual_size = stream_download_and_hash(url, package_path)
    except requests.exceptions.RequestException as exc:
        print("  Download: FAILED")
        print(f"  ERROR: Unable to download {label}: {exc}")
        return False

    ok = True
    if actual_hash.lower() == expected_hash:
        print(f"  Hash Match: OK ({actual_hash})")
    else:
        print("  Hash Match: FAILED")
        print(f"    expected: {expected_hash}")
        print(f"    actual:   {actual_hash}")
        ok = False

    if actual_size == expected_size:
        print(f"  Size Match: OK ({actual_size} bytes)")
    else:
        print("  Size Match: FAILED")
        print(f"    expected: {expected_size} bytes")
        print(f"    actual:   {actual_size} bytes")
        ok = False

    if not ok:
        return False

    package_errors = inspect_package(package_path, app)
    if package_errors:
        print("  Manifest/Policy: FAILED")
        for error in package_errors:
            print(f"    - {error}")
        return False

    print("  Manifest/Policy: OK")
    return True


def validate_recipe_provenance(apps: list[Any], recipe_schema_path: Path) -> int:
    """Cross-check catalog entries that reference recipes (kind: "recipe")."""
    from jsonschema import Draft202012Validator, FormatChecker

    if not recipe_schema_path.exists():
        print(f"ERROR: recipe schema not found: {recipe_schema_path}")
        return 1

    schema = load_json(recipe_schema_path, "recipe.schema.json")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    failures = 0

    for index, app in enumerate(apps):
        if not isinstance(app, dict):
            continue
        kind = app.get("kind", "package")
        recipe_ref = app.get("recipe", "")
        label = app_label(app, index)

        if kind not in ("package", "recipe"):
            print(f"ERROR: {label} has unknown kind '{kind}'.")
            failures += 1
            continue
        if kind == "recipe" and not recipe_ref:
            print(f"ERROR: {label} has kind 'recipe' but no recipe path.")
            failures += 1
            continue
        if kind == "package" and recipe_ref:
            print(f"ERROR: {label} references a recipe but kind is 'package'.")
            failures += 1
            continue
        if kind != "recipe":
            continue

        recipe_path = Path(recipe_ref)
        if not recipe_path.exists():
            print(f"ERROR: {label} references missing recipe file: {recipe_path}")
            failures += 1
            continue

        recipe = load_json(recipe_path, f"recipe for {label}")
        errors = sorted(
            validator.iter_errors(recipe), key=lambda error: list(error.absolute_path)
        )
        if errors:
            print(f"ERROR: recipe for {label} fails {recipe_schema_path.name}:")
            for error in errors:
                location = "/".join(str(part) for part in error.absolute_path)
                print(f"  - {location}: {error.message}" if location else f"  - {error.message}")
            failures += 1
            continue

        if recipe.get("id") != app.get("id"):
            print(f"ERROR: recipe id {recipe.get('id')} != catalog id {app.get('id')} for {label}.")
            failures += 1
        if recipe.get("version") != app.get("version"):
            print(
                f"ERROR: recipe version {recipe.get('version')} != catalog version "
                f"{app.get('version')} for {label}; rebuild the package."
            )
            failures += 1

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Portappix catalog.json")
    parser.add_argument("--catalog", default="catalog.json")
    parser.add_argument("--schema", default="catalog.schema.json")
    parser.add_argument("--recipe-schema", default="recipe.schema.json")
    parser.add_argument("--skip-provenance", action="store_true",
                        help="Skip recipe cross-checks (recipe files not present)")
    args = parser.parse_args(argv)

    catalog_path = Path(args.catalog)
    schema_path = Path(args.schema)

    print(f"Loading catalog: {catalog_path}")
    catalog = load_json(catalog_path, "catalog.json")
    print(f"Loading schema: {schema_path}")
    schema = load_json(schema_path, "catalog.schema.json")

    if validate_schema(catalog, schema, schema_path):
        return 1

    if not isinstance(catalog, dict):
        print("ERROR: catalog.json must contain an object.")
        return 1

    apps = catalog.get("apps", [])
    if not isinstance(apps, list):
        print('ERROR: Catalog property "$.apps" must be an array.')
        return 1

    seen: dict[str, int] = {}
    duplicate = False
    for index, app in enumerate(apps):
        if not isinstance(app, dict):
            print(f"ERROR: {format_json_path(['apps', index])} must be an object.")
            duplicate = True
            continue
        app_id = str(app.get("id", "")).lower()
        if app_id:
            if app_id in seen:
                print(
                    f"ERROR: duplicate app id '{app_id}' at "
                    f"{format_json_path(['apps', index])} "
                    f"(first seen at {format_json_path(['apps', seen[app_id]])})"
                )
                duplicate = True
            else:
                seen[app_id] = index
    if duplicate:
        print("Validation: FAILED (invalid app entries)")
        return 1

    if not apps:
        print("No apps to verify.")
        print("Validation: OK")
        return 0

    if not args.skip_provenance:
        recipe_failures = validate_recipe_provenance(apps, Path(args.recipe_schema))
        if recipe_failures:
            print(f"Recipe provenance: FAILED ({recipe_failures} error(s))")
            return 1
        print("Recipe provenance: OK")

    print(f"Verifying {len(apps)} app package(s)...")
    failures = 0
    with tempfile.TemporaryDirectory(prefix="portappix-catalog-") as temporary:
        workdir = Path(temporary)
        for index, app in enumerate(apps):
            if not verify_app(app, index, workdir):
                failures += 1

    if failures:
        print(f"Validation: FAILED ({failures} app(s) with errors)")
        return 1

    print("Validation: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
