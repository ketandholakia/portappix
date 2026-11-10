#!/usr/bin/env python3
"""Distribution package security guard for Portappix archives.

Verifies that a distribution archive (release zip, app package zip) contains
no forbidden material:

- Git metadata (any ``.git`` path component).
- Private-key directories (``keys/``, ``.ssh/`` components).
- Private-key files (``.pem``, ``.pfx``, ``.p12``, ``.key``, ``.pvk``
  extensions; bare ``id_rsa``-style names).
- Known secret-bearing configuration files (``.env*``, ``secrets.*``,
  ``credentials.json``).
- PEM private-key markers inside file contents (``-----BEGIN ... PRIVATE
  KEY-----``), scanned for every entry up to a size cap.

Checks are case-insensitive and both ``\\`` and ``/`` separators are
normalized before matching. Violations are reported as paths plus rule
names only — file contents are never printed.

Library use:
    from package_guard import check_archive
    findings = check_archive(Path("portappix-1.0.0-stable.zip"))

CLI use (exit 0 = clean, 1 = violation or unreadable archive):
    python scripts/package_guard.py <archive.zip> [<more.zips>...]
"""

from __future__ import annotations

import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SCAN_SIZE_LIMIT = 10 * 1024 * 1024  # per-entry content-scan cap

PEM_PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----")

FORBIDDEN_DIR_COMPONENTS = {"keys", ".ssh"}
FORBIDDEN_FILE_EXTENSIONS = {".pem", ".pfx", ".p12", ".key", ".pvk"}
FORBIDDEN_FILE_BASENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
FORBIDDEN_SECRET_BASENAMES = {"secrets.json", "secrets.yaml", "secrets.yml",
                              "credentials.json"}


@dataclass(frozen=True)
class Finding:
    archive: str
    entry: str
    rule: str
    detail: str


def normalize_archive_path(name: str) -> str:
    """Normalize an archive entry name for security checks.

    Backslashes become forward slashes, drive letters are stripped, and
    leading ``/`` or ``./`` prefixes are removed so nested Windows-style
    entries cannot dodge component matching.
    """
    normalized = name.replace("\\", "/")
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized[2:]
    return normalized.lstrip("/").removeprefix("./")


def path_findings(entry: str) -> list[tuple[str, str]]:
    """Return (rule, detail) findings for an entry name, or an empty list."""
    normalized = normalize_archive_path(entry)
    lowered = normalized.lower()
    if not lowered:
        return []

    components = lowered.split("/")
    if ".git" in components:
        return [("GIT_METADATA", f"'.git' path component in '{normalized}'")]
    if any(component in FORBIDDEN_DIR_COMPONENTS for component in components):
        offending = next(c for c in components if c in FORBIDDEN_DIR_COMPONENTS)
        return [("PRIVATE_KEY_DIR", f"'{offending}/' directory component in '{normalized}'")]

    basename = components[-1]
    stem, dot, extension = basename.rpartition(".")
    if dot and ("." + extension) in FORBIDDEN_FILE_EXTENSIONS:
        return [("PRIVATE_KEY_FILE", f"'*.{extension}' private-key file '{normalized}'")]
    if basename in FORBIDDEN_FILE_BASENAMES:
        return [("PRIVATE_KEY_FILE", f"private-key file '{normalized}'")]
    if basename == ".env" or basename.startswith(".env."):
        return [("SECRET_CONFIG", f"secret-bearing environment file '{normalized}'")]
    if basename in FORBIDDEN_SECRET_BASENAMES:
        return [("SECRET_CONFIG", f"secret-bearing configuration file '{normalized}'")]
    return []


def content_findings(entry: str, data: bytes) -> list[tuple[str, str]]:
    """Return (rule, detail) findings for an entry's bytes, or an empty list."""
    if PEM_PRIVATE_KEY_MARKER.search(data):
        return [("PEM_MARKER",
                 f"PEM private-key marker inside '{normalize_archive_path(entry)}'")]
    return []


def check_archive(archive: Path) -> list[Finding]:
    """Check one archive. Returns a list of findings; empty means clean.

    Archives or entries that cannot be read fail closed with an UNREADABLE
    finding rather than being silently skipped.
    """
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                entry = info.filename
                for rule, detail in path_findings(entry):
                    findings.append(Finding(str(archive), entry, rule, detail))
                    continue
                if info.is_dir() or info.file_size > SCAN_SIZE_LIMIT:
                    continue
                try:
                    data = zf.read(info)
                except Exception as exc:
                    findings.append(Finding(
                        str(archive), entry, "UNREADABLE",
                        f"entry could not be read for content scan: "
                        f"{exc.__class__.__name__}"))
                    continue
                for rule, detail in content_findings(entry, data):
                    findings.append(Finding(str(archive), entry, rule, detail))
    except zipfile.BadZipFile:
        findings.append(Finding(str(archive), "", "UNREADABLE",
                                "not a readable zip archive"))
    return findings


def format_findings(findings: Iterable[Finding]) -> str:
    lines = []
    for finding in findings:
        entry = finding.entry if finding.entry else "(archive)"
        lines.append(f"  FORBIDDEN [{finding.rule}] {entry}: {finding.detail}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print("Usage: package_guard.py <archive.zip> [<more.zips>...]")
        return 1

    all_findings: list[Finding] = []
    for argument in argv:
        archive = Path(argument)
        if not archive.exists():
            print(f"ERROR: archive not found: {archive}")
            all_findings.append(Finding(str(archive), "", "UNREADABLE",
                                        "archive not found"))
            continue
        findings = check_archive(archive)
        all_findings.extend(findings)
        if findings:
            print(f"FAILED: {archive} ({len(findings)} violation(s))")
            print(format_findings(findings))
        else:
            print(f"OK: {archive} contains no forbidden material")

    if all_findings:
        total = len(all_findings)
        print(f"Package guard: FAILED ({total} violation(s) across "
              f"{len(argv)} archive(s)); contents were NOT printed.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
