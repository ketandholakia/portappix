#!/usr/bin/env python3
"""Phase 1 regression tests: signing workflow + distribution package guard.

Hand-rolled assertion harness in the same spirit as tests/PortappixTests.dpr
(no test framework). Runs scripts/sign_catalog.py as a subprocess to verify
CLI/exit-code behaviour and imports scripts/package_guard.py for archive
checks. Every key used here is a synthetic test key generated inside a
temporary directory and deleted afterwards — real signing keys are never
read, copied, or referenced.

Exit code 0 = all checks passed, 1 = any failure.

Requires: pip install cryptography
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
sys.path.insert(0, str(SCRIPTS))

from package_guard import check_archive  # noqa: E402

PYTHON = sys.executable or "python"
SIGN_SCRIPT = SCRIPTS / "sign_catalog.py"
GUARD_SCRIPT = SCRIPTS / "package_guard.py"

Passed = 0
Failed = 0


def check(condition: bool, name: str) -> None:
    global Passed, Failed
    if condition:
        Passed += 1
        print(f"PASS: {name}")
    else:
        Failed += 1
        print(f"FAIL: {name}")


def run_sign(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PYTHON, str(SIGN_SCRIPT), *args],
        capture_output=True, text=True, cwd=str(REPO),
    )


def run_guard_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PYTHON, str(GUARD_SCRIPT), *args],
        capture_output=True, text=True, cwd=str(REPO),
    )


def write_pem(path: Path, pem: bytes) -> Path:
    path.write_bytes(pem)
    return path


def make_key_pair(directory: Path, curve=ec.SECP256R1):
    """Generate a synthetic key pair for testing; private material never leaves the temp dir."""
    directory.mkdir(parents=True, exist_ok=True)
    curve_instance = curve() if isinstance(curve, type) else curve
    private = ec.generate_private_key(curve_instance)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return write_pem(directory / "test_signing_key.pem", private_pem), \
        write_pem(directory / "test_public_key.pem", public_pem)


def make_rsa_pair(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return write_pem(directory / "test_rsa_key.pem", private_pem)


def add_entry(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    zf.writestr(name, data)


CLEAN_PACKAGE = [
    ("app.json", b'{"schema":1,"id":"demo","exe":"demo.exe"}'),
    ("demo.exe", b"MZ\x90\x00 fake executable"),
    ("docs/readme.txt", b"readme"),
    ("data/settings.ini", b"[main]\nvalue=1\n"),
]


def build_zip(path: Path, entries) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            add_entry(zf, name, data)
    return path


FAKE_PEM_TEXT = (
    b"not a real key, synthetic test marker only\n"
    b"-----BEGIN " + b"RSA " + b"PRIVATE KEY-----\n"
    b"c2ltdWxhdGVkIHRlc3QgZml4dHVyZTogbmV2ZXIgYSB2YWxpZCBrZXk=\n"
    b"-----END " + b"RSA " + b"PRIVATE KEY-----\n"
)


def main() -> int:
    print("Portappix signing workflow + package guard tests")
    print("------------------------------------------------")

    with tempfile.TemporaryDirectory(prefix="portappix-p1-tests-") as td:
        work = Path(td)

        # --- Signing workflow ------------------------------------------------
        catalog = work / "catalog.json"
        catalog.write_bytes(b'{"apps": []}\n')
        sig_path = Path(str(catalog) + ".sig")
        signer_priv, signer_pub = make_key_pair(work / "good")

        proc = run_sign("--catalog", str(catalog), "--key", str(work / "missing.pem"))
        check(proc.returncode != 0,
              "signing: missing private key fails with a non-zero exit code")
        check(not sig_path.exists(),
              "signing: missing private key writes no signature")

        bad_pem = write_pem(work / "garbage.pem", b"this is not a pem file\n")
        proc = run_sign("--catalog", str(catalog), "--key", str(bad_pem))
        check(proc.returncode != 0, "signing: invalid private key fails")

        p384_priv, _ = make_key_pair(work / "p384", curve=ec.SECP384R1())
        proc = run_sign("--catalog", str(catalog), "--key", str(p384_priv))
        check(proc.returncode != 0, "signing: wrong curve (P-384) private key fails")

        rsa_pem = make_rsa_pair(work / "rsa")
        proc = run_sign("--catalog", str(catalog), "--key", str(rsa_pem))
        check(proc.returncode != 0, "signing: wrong key type (RSA) private key fails")

        proc = run_sign("--catalog", str(catalog))
        check(proc.returncode != 0,
              "signing: signing without --key fails (no automatic key generation)")

        proc = run_sign("--catalog", str(catalog), "--key", str(signer_priv),
                        "--public-key", str(signer_pub))
        check(proc.returncode == 0,
              "signing: valid signing succeeds and exits zero")
        check(sig_path.exists() and len(sig_path.read_bytes()) == 64,
              "signing: valid signing produces a 64-byte raw r||s signature")
        verify = run_sign("--catalog", str(catalog), "--public-key",
                          str(signer_pub), "--verify")
        check(verify.returncode == 0,
              "signing: the fresh signature verifies against the signer's public key")
        check(not list(work.glob("*.tmp")) and not list(sig_path.parent.glob("*.tmp")),
              "signing: temporary signing files are cleaned up")
        check("SHA-256 of signed bytes:" in proc.stdout,
              "signing: prints SHA-256 of the signed bytes")
        check("SHA-256 of verified bytes:" in verify.stdout,
              "signing: prints SHA-256 of the verified bytes")

        # CRLF rejection by default, allowed with --allow-crlf
        crlf_catalog = work / "crlf.json"
        crlf_catalog.write_bytes(b'{"apps": []}\r\n')
        crlf_sig = work / "crlf.json.sig"
        proc = run_sign("--catalog", str(crlf_catalog), "--key", str(signer_priv),
                        "--public-key", str(signer_pub))
        check(proc.returncode != 0 and "contains CR bytes" in proc.stdout,
              "signing: refuses to sign file containing CR bytes by default")
        check(not crlf_sig.exists(),
              "signing: CR file produces no signature")

        proc = run_sign("--catalog", str(crlf_catalog), "--key", str(signer_priv),
                        "--public-key", str(signer_pub), "--allow-crlf")
        check(proc.returncode == 0,
              "signing: signs file containing CR bytes when --allow-crlf is passed")
        check(crlf_sig.exists(),
              "signing: --allow-crlf produces signature")

        # A subsequent signing failure must not touch the valid signature.
        valid_sig_bytes = sig_path.read_bytes()
        other_catalog = work / "other.json"
        other_catalog.write_bytes(b'{"apps": ["different"]}\n')
        proc = run_sign("--catalog", str(other_catalog), "--key", str(work / "missing.pem"),
                        "--signature", str(sig_path))
        check(proc.returncode != 0,
              "signing: failed signing returns a non-zero exit code")
        check(sig_path.read_bytes() == valid_sig_bytes,
              "signing: verification failure does not replace an existing valid signature")

        # --- Package guard ----------------------------------------------------
        findings = check_archive(build_zip(work / "git.zip", [
            (".git/config", b"[core]\n"), ("app.json", b"{}")]))
        check(any(f.rule == "GIT_METADATA" for f in findings),
              "guard: .git/config entry is rejected")

        findings = check_archive(build_zip(work / "keys.zip", [
            ("keys/catalog_signing_key.pem", b"synthetic, not a real key"),
            ("app.json", b"{}")]))
        check(any(f.rule in ("PRIVATE_KEY_DIR", "PRIVATE_KEY_FILE") for f in findings),
              "guard: keys/*.pem entry is rejected")

        findings = check_archive(build_zip(work / "case.zip", [
            (".GIT/HEAD", b"ref: refs/heads/main\n"), ("app.json", b"{}")]))
        check(any(f.rule == "GIT_METADATA" for f in findings),
              "guard: detection is case-insensitive (.GIT)")

        findings = check_archive(build_zip(work / "slash.zip", [
            (".git\\config", b"[core]\n"), ("app.json", b"{}")]))
        check(any(f.rule == "GIT_METADATA" for f in findings),
              "guard: backslash archive entry style is handled")

        findings = check_archive(build_zip(work / "nested.zip", [
            ("a/b/keys/vendor.key", b"synthetic"), ("app.json", b"{}")]))
        check(any(f.rule in ("PRIVATE_KEY_DIR", "PRIVATE_KEY_FILE") for f in findings),
              "guard: nested forbidden paths are rejected")

        findings = check_archive(build_zip(work / "pemtext.zip", [
            ("tools/legacy.txt", FAKE_PEM_TEXT), ("app.json", b"{}")]))
        check(any(f.rule == "PEM_MARKER" for f in findings),
              "guard: PEM private-key marker in a text file is rejected")

        findings = check_archive(build_zip(work / "env.zip", [
            (".env", b"SECRET=not-really\n"), ("app.json", b"{}")]))
        check(any(f.rule == "SECRET_CONFIG" for f in findings),
              "guard: secret-bearing .env file is rejected")

        findings = check_archive(build_zip(work / "pfx.zip", [
            ("certs/server.pfx", b"synthetic binary"), ("app.json", b"{}")]))
        check(any(f.rule == "PRIVATE_KEY_FILE" for f in findings),
              "guard: .pfx private-key file is rejected")

        clean = build_zip(work / "clean.zip", CLEAN_PACKAGE)
        check(check_archive(clean) == [], "guard: a clean package passes")

        # --- Public key allowance and strict keys/ isolation -----------------
        pub_pem_data = (
            b"-----BEGIN PUBLIC KEY-----\n"
            b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3opfkvp3mqlV17cDlLmPA/PouJA9\n"
            b"QDhMmjoAPTr+wncrQYeWw4VGTkSSE1TUVSB1TKaIwdDIm23CVADUCk1sVg==\n"
            b"-----END PUBLIC KEY-----\n"
        )

        # 1. The public PEM is accepted
        findings = check_archive(build_zip(work / "public_key.zip", [
            ("keys/catalog_public.pem", pub_pem_data), ("app.json", b"{}")]))
        check(findings == [], "guard: keys/catalog_public.pem is accepted")

        # 2. Any other file under keys/ is rejected
        findings = check_archive(build_zip(work / "keys_other_pem.zip", [
            ("keys/other_key.pem", pub_pem_data), ("app.json", b"{}")]))
        check(any(f.rule == "PRIVATE_KEY_DIR" for f in findings),
              "guard: any other file under keys/ is rejected (other_key.pem)")

        findings = check_archive(build_zip(work / "keys_other_txt.zip", [
            ("keys/notes.txt", b"plain text"), ("app.json", b"{}")]))
        check(any(f.rule == "PRIVATE_KEY_DIR" for f in findings),
              "guard: any other file under keys/ is rejected (notes.txt)")

        findings = check_archive(build_zip(work / "keys_other_key.zip", [
            ("keys/vendor.key", b"key data"), ("app.json", b"{}")]))
        check(any(f.rule == "PRIVATE_KEY_DIR" for f in findings),
              "guard: any other file under keys/ is rejected (vendor.key)")

        # 3. A public-named file containing a private marker is rejected
        findings = check_archive(build_zip(work / "public_fake_private.zip", [
            ("keys/catalog_public.pem", FAKE_PEM_TEXT), ("app.json", b"{}")]))
        check(any(f.rule == "PEM_MARKER" for f in findings),
              "guard: public-named file containing private marker is rejected")

        # Public-named file without valid public key marker is rejected
        findings = check_archive(build_zip(work / "public_not_pem.zip", [
            ("keys/catalog_public.pem", b"not a public key pem\n"), ("app.json", b"{}")]))
        check(any(f.rule == "INVALID_PUBLIC_KEY" for f in findings),
              "guard: public-named file without public key marker is rejected")

        # 4. A *.pem private key anywhere else is rejected
        findings = check_archive(build_zip(work / "pem_root.zip", [
            ("catalog_public.pem", pub_pem_data), ("app.json", b"{}")]))
        check(any(f.rule == "PRIVATE_KEY_FILE" for f in findings),
              "guard: *.pem file at root is rejected")

        findings = check_archive(build_zip(work / "pem_certs.zip", [
            ("certs/client.pem", pub_pem_data), ("app.json", b"{}")]))
        check(any(f.rule == "PRIVATE_KEY_FILE" for f in findings),
              "guard: *.pem file anywhere else is rejected")

        # --- Live git archive verification -----------------------------------
        archive_out = work / "git_archive_source.zip"
        treeish = "HEAD"
        # If uncommitted changes exist (e.g. before committing .gitattributes),
        # create a temporary tree snapshot for git archive.
        status_proc = subprocess.run(["git", "status", "--porcelain"],
                                     cwd=str(REPO), capture_output=True, text=True)
        if status_proc.stdout.strip():
            # Update index with working tree changes for the test snapshot
            subprocess.run(["git", "add", "-A"], cwd=str(REPO), check=True)
            tree_proc = subprocess.run(["git", "write-tree"], cwd=str(REPO),
                                       capture_output=True, text=True)
            if tree_proc.returncode == 0 and tree_proc.stdout.strip():
                treeish = tree_proc.stdout.strip()

        archive_proc = subprocess.run(
            ["git", "archive", "--format=zip", f"--output={archive_out}", treeish],
            cwd=str(REPO),
            capture_output=True,
            text=True,
        )
        check(archive_proc.returncode == 0, "live archive: git archive succeeds")
        guard_findings = check_archive(archive_out)
        check(guard_findings == [], f"live archive: package_guard reports clean (findings: {guard_findings})")
        with zipfile.ZipFile(archive_out) as zf:
            names = zf.namelist()
            check("keys/catalog_public.pem" in names,
                  "live archive: contains keys/catalog_public.pem")
            check(not any(".git" in n.lower().split("/") for n in names),
                  "live archive: contains no .git metadata")
            check(not any(n.lower().endswith(".dcu") for n in names),
                  "live archive: contains no .dcu files")
            check(not any("__history" in n.lower() for n in names),
                  "live archive: contains no __history")
            check(any(n.startswith("tests/suite/") for n in names),
                  "live archive: contains tests/suite")
            check(any(n.startswith("tests/fakeapps/") for n in names),
                  "live archive: contains tests/fakeapps")

        proc = run_guard_cli(str(build_zip(work / "cli_bad.zip", [
            (".git/config", b"[core]\n")])))
        check(proc.returncode != 0,
              "guard: CLI exits non-zero when a forbidden file is found")
        check(".git/config" in proc.stdout and "GIT_METADATA" in proc.stdout,
              "guard: CLI reports the offending path and rule name")
        proc = run_guard_cli(str(clean))
        check(proc.returncode == 0,
              "guard: CLI exits zero for a clean archive")

    print()
    print(f"Result: {Passed} passed, {Failed} failed")
    return 0 if Failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
