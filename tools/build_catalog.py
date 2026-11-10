#!/usr/bin/env python3
"""Build catalog.json from built recipes.

Reads recipes/*.json plus the build manifests that tools/build_recipe.py
produced (dist/<id>.build.json), verifies each built package on disk (sha256 +
size recomputed, app.json policy re-checked), and writes catalog.json with
provenance fields (kind: "recipe", recipe: "recipes/<id>.json"). Optionally
signs the result with the same ECDSA P-256 scheme as sign_catalog.py.
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

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR.parent / "scripts"))

from validate_catalog import load_json, inspect_package  # noqa: E402

CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sign_file(path: Path, key_path: Path) -> Path:
    sys.path.insert(0, str(TOOLS_DIR.parent / "scripts"))
    from sign_catalog import load_private_key, sign_bytes  # noqa: E402

    signature = sign_bytes(path.read_bytes(), load_private_key(key_path))
    signature_path = path.with_name(path.name + ".sig")
    signature_path.write_bytes(signature)
    print(f"Signature written: {signature_path}")
    return signature_path


def verify_built_package(recipe: dict[str, Any], build: dict[str, Any],
                         package_path: Path) -> None:
    if build["id"] != recipe["id"]:
        raise SystemExit(f"ERROR: build manifest id {build['id']} != recipe id {recipe['id']}")
    if build["version"] != recipe["version"]:
        raise SystemExit(
            f"ERROR: package for {recipe['id']} was built from version "
            f"{build['version']} but the recipe pins {recipe['version']}; rebuild it."
        )

    actual_sha256 = sha256_file(package_path)
    if actual_sha256 != build["sha256"].lower():
        raise SystemExit(
            f"ERROR: built package {package_path.name} does not match its build "
            f"manifest (sha256 {actual_sha256} != {build['sha256']}); rebuild it."
        )
    actual_size = package_path.stat().st_size
    if actual_size != build["size"]:
        raise SystemExit(f"ERROR: built package size mismatch for {recipe['id']}.")

    # The built package must pass the same zip + policy inspection as any
    # other catalog package (app.json at root, policy rules, zip-slip, ...).
    app_entry = {
        "id": recipe["id"],
        "name": recipe["name"],
        "version": recipe["version"],
    }
    problems = inspect_package(package_path, app_entry)
    if problems:
        print(f"Built package inspection: FAILED ({recipe['id']})")
        for problem in problems:
            print(f"  - {problem}")
        raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build catalog.json from recipes")
    parser.add_argument("--recipes", type=Path, default=Path("recipes"),
                        help="Folder containing <id>.json recipe files")
    parser.add_argument("--packages", type=Path, default=Path("dist"),
                        help="Folder with <id>.package.zip + <id>.build.json files "
                             "produced by build_recipe.py")
    parser.add_argument("--url-base", required=True,
                        help="https:// base URL under which the built packages "
                             "are hosted")
    parser.add_argument("--out", type=Path, default=Path("catalog.json"))
    parser.add_argument("--schema", type=Path, default=Path("catalog.schema.json"))
    parser.add_argument("--recipe-schema", type=Path, default=Path("recipe.schema.json"))
    parser.add_argument("--key", type=Path, default=None,
                        help="Optional P-256 private key to sign catalog.json")
    parser.add_argument("--include", default=None,
                        help="Optional comma-separated list of recipe IDs to include (e.g. everything,fastfetch,...)")
    args = parser.parse_args(argv)

    if not args.url_base.startswith("https://"):
        raise SystemExit("ERROR: --url-base must be an https:// URL")

    from jsonschema import Draft202012Validator, FormatChecker

    recipe_schema = load_json(args.recipe_schema, "recipe schema")
    recipe_validator = Draft202012Validator(recipe_schema, format_checker=FormatChecker())

    recipe_paths = sorted(args.recipes.glob("*.json"))
    if not recipe_paths:
        raise SystemExit(f"ERROR: no recipe files found in {args.recipes}")

    include_ids = set(x.strip() for x in args.include.split(",")) if args.include else None

    apps: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for recipe_path in recipe_paths:
        recipe = load_json(recipe_path, "recipe")
        recipe_id = recipe["id"]
        if include_ids and recipe_id not in include_ids:
            continue

        for error in recipe_validator.iter_errors(recipe):
            raise SystemExit(
                f"ERROR: {recipe_path.name} does not match {args.recipe_schema.name}: "
                f"{error.message}"
            )

        if recipe_id in seen_ids:
            raise SystemExit(f"ERROR: duplicate recipe id {recipe_id}")
        seen_ids.add(recipe_id)

        redistribution = recipe.get("redistribution", "allowed")
        if redistribution == "vendor-link-only":
            entry = {
                "id": recipe_id,
                "name": recipe["name"],
                "publisher": recipe.get("publisher", ""),
                "version": recipe["version"],
                "category": recipe["category"],
                "url": recipe["source"]["url"],
                "sha256": recipe["source"]["sha256"].lower(),
                "size": recipe["source"]["size"],
                "kind": "vendor-link",
                "recipe": f"recipes/{recipe_path.name}",
            }
            if "license" in recipe:
                entry["license"] = recipe["license"]
            entry["redistribution"] = "vendor-link-only"
            if "stripPrefix" in recipe:
                entry["stripPrefix"] = recipe["stripPrefix"]
            exe_path = recipe.get("exePath") or recipe.get("manifest", {}).get("exe")
            if exe_path:
                entry["exePath"] = exe_path
            if "manifest" in recipe:
                entry["manifest"] = recipe["manifest"]
            apps.append(entry)
            print(f"Vendor-link recipe OK: {recipe_id} {recipe['version']} (vendor URL)")
            continue

        build_file = args.packages / f"{recipe_id}.build.json"
        if not build_file.exists():
            if include_ids and recipe_id in include_ids:
                raise SystemExit(
                    f"ERROR: no build manifest for '{recipe_id}' ({build_file}); "
                    "run tools/build_recipe.py first."
                )
            continue
        build = load_json(build_file, f"build manifest for {recipe_id}")

        package_path = args.packages / build["package"]
        if not package_path.exists():
            raise SystemExit(f"ERROR: built package missing: {package_path}")
        verify_built_package(recipe, build, package_path)

        entry = {
            "id": recipe_id,
            "name": recipe["name"],
            "publisher": recipe.get("publisher", ""),
            "version": recipe["version"],
            "category": recipe["category"],
            "url": f"{args.url_base.rstrip('/')}/{build['package']}",
            "sha256": build["sha256"].lower(),
            "size": build["size"],
            "kind": "recipe",
            "recipe": f"recipes/{recipe_path.name}",
        }
        if "license" in recipe:
            entry["license"] = recipe["license"]
        if "redistribution" in recipe:
            entry["redistribution"] = recipe["redistribution"]
        apps.append(entry)
        print(f"Recipe OK: {recipe_id} {recipe['version']} "
              f"({build['size']} bytes, sha256 {build['sha256'][:16]}...)")

    apps.sort(key=lambda app: app["id"])
    catalog = {"apps": apps}

    args.out.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Catalog written: {args.out} ({len(apps)} app(s))")

    if args.key:
        sign_file(args.out, args.key)

    return 0


if __name__ == "__main__":
    sys.exit(main())
