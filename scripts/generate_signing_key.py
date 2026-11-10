#!/usr/bin/env python3
"""Generate a new Portappix catalog signing key pair (ECDSA P-256).

The private key is written to an operator-supplied path that MUST be outside
a Git repository (enforced) and is ACL-restricted to the current user on
Windows (chmod 600 elsewhere). The public key may live in the repository
(normally keys/catalog_public.pem, which .gitignore whitelists).

Only public information is printed: the public-key fingerprint, the raw
point coordinates, and the CNG ECCPUBLICBLOB hex for Portappix.Signature.pas.
Private-key material is never printed, logged, or copied.

This tool is for explicit rotation events only; normal signing never
generates keys (see sign_catalog.py).

Requires: pip install cryptography
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

P256_MAGIC = "45435331"      # BCRYPT_ECDSA_PUBLIC_P256_MAGIC, little-endian
P256_KEY_LENGTH = "20000000"  # 32-byte key length field, little-endian


def is_inside_git_repo(directory: Path) -> bool:
    directory = directory.resolve()
    if not directory.exists():
        directory = directory.parent
    while True:
        if (directory / ".git").exists():
            return True
        if directory.parent == directory:
            return False
        directory = directory.parent


def fingerprint(public_pem: bytes) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Re-parse so the fingerprint is over the canonical DER encoding.
    key = serialization.load_pem_public_key(public_pem)
    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2)).upper()


def restrict_private_key_acl(path: Path) -> None:
    if os.name == "nt":
        # Remove inherited ACEs, keep only the current user with full control.
        subprocess.run(
            ["icacls", str(path), "/inheritance:r",
             "/grant:r", f"{os.environ.get('USERNAME', '')}:F"],
            check=True, capture_output=True, text=True,
        )
    else:
        os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a Portappix ECDSA P-256 signing key pair")
    parser.add_argument("--out", required=True,
                        help="Output path for the private key PEM (must be outside any Git repository)")
    parser.add_argument("--public-out", required=True,
                        help="Output path for the public key PEM (may be inside the repository)")
    parser.add_argument("--force-public", action="store_true",
                        help="Allow overwriting an existing public key file")
    args = parser.parse_args(argv)

    private_path = Path(args.out).expanduser()
    public_path = Path(args.public_out).expanduser()

    if private_path.exists():
        print(f"ERROR: {private_path} already exists; refusing to overwrite an existing private key.")
        return 1
    if is_inside_git_repo(private_path.parent):
        print(f"ERROR: {private_path} is inside a Git repository. "
              "Private signing keys must be stored outside the repository.")
        return 1
    if public_path.exists() and not args.force_public:
        print(f"ERROR: {public_path} already exists (use --force-public to replace it).")
        return 1

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = ec.generate_private_key(ec.SECP256R1())

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    restrict_private_key_acl(private_path)
    public_path.write_bytes(public_pem)

    numbers = private_key.public_key().public_numbers()
    x_hex = numbers.x.to_bytes(32, "big").hex().upper()
    y_hex = numbers.y.to_bytes(32, "big").hex().upper()
    blob_hex = P256_MAGIC + P256_KEY_LENGTH + x_hex + y_hex

    print("ECDSA P-256 signing key pair generated.")
    print(f"  Private key : {private_path} (ACL restricted to the current user)")
    print(f"  Public key  : {public_path}")
    print(f"  Fingerprint (SHA-256 of SPKI DER): {fingerprint(public_pem)}")
    print("  CNG ECCPUBLICBLOB hex for Portappix.Signature.pas (wrap as needed):")
    for offset in range(0, len(blob_hex), 72):
        print(f"    '{blob_hex[offset:offset + 72]}'")
    print("The private key was NOT printed and must never be committed or packaged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
