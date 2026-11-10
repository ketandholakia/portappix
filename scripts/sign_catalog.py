#!/usr/bin/env python3
"""Create or verify a Portappix catalog signature.

The signature is ECDSA P-256 over the SHA-256 digest of the exact catalog bytes,
stored as the raw 64-byte r||s value expected by Windows CNG (BCrypt*).

Signing safety rules:
- The private key path must be supplied explicitly (--key); it is never
  inferred and never generated here. Key generation is a separate, explicit
  rotation step (scripts/generate_signing_key.py).
- The private key must exist, parse as PEM, and be an ECDSA P-256 key; any
  other condition is a clean failure with exit code 1. Private-key material
  is never printed or logged.
- Every signature is written to a temporary file first, verified immediately
  against the trusted public key (--public-key, default: keys/catalog_public.pem),
  and only then moved into place. A failed or unverifiable signature never
  replaces an existing valid signature file.
- Temporary files are always cleaned up, including on failure paths.

Requires: pip install cryptography
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

SIGNATURE_SIZE = 64

DEFAULT_PUBLIC_KEY = Path(__file__).resolve().parent.parent / "keys" / "catalog_public.pem"


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"ERROR: cannot read private key {path}: {exc.__class__.__name__}")
    if not raw.strip():
        raise SystemExit(f"ERROR: private key file {path} is empty")
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except Exception:
        raise SystemExit(f"ERROR: {path} is not a readable PEM private key")
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise SystemExit(f"ERROR: {path} is not a P-256 (SECP256R1) private key")
    return key


def load_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"ERROR: cannot read public key {path}: {exc.__class__.__name__}")
    try:
        key = serialization.load_pem_public_key(raw)
    except Exception:
        raise SystemExit(f"ERROR: {path} is not a readable PEM public key")
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise SystemExit(f"ERROR: {path} is not a P-256 (SECP256R1) public key")
    return key


def sign_bytes(data: bytes, key: ec.EllipticCurvePrivateKey) -> bytes:
    digest = hashlib.sha256(data).digest()
    der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_bytes(data: bytes, signature: bytes, key: ec.EllipticCurvePublicKey) -> bool:
    if len(signature) != SIGNATURE_SIZE:
        return False
    digest = hashlib.sha256(data).digest()
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der = utils.encode_dss_signature(r, s)
    try:
        key.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False


def sign_and_swap(catalog_path: Path, key_path: Path, signature_path: Path,
                  verify_key: ec.EllipticCurvePublicKey, allow_crlf: bool = False) -> int:
    """Sign to a temporary file, verify it, then atomically move it into place.

    On any failure the existing signature file (if any) is left untouched and
    a non-zero exit code is returned.
    """
    data = catalog_path.read_bytes()
    if b"\r" in data and not allow_crlf:
        print(f"ERROR: {catalog_path} contains CR bytes (\\r). Signed files must use LF line endings for byte-stability. Pass --allow-crlf to override.")
        return 1

    digest_hex = hashlib.sha256(data).hexdigest()
    print(f"SHA-256 of signed bytes: {digest_hex}")
    key = load_private_key(key_path)

    signature = sign_bytes(data, key)
    if not verify_bytes(data, signature, verify_key):
        # Signing and verification use the same bytes, so this indicates a
        # broken toolchain or a non-P-256 trust key; refuse to publish.
        print("ERROR: the freshly generated signature failed verification "
              "against the trusted public key; nothing was written.")
        return 1

    temp_path: Path | None = None
    try:
        # tempfile guarantees a unique name that cannot collide with another
        # concurrent signing run targeting the same signature path.
        handle, temp_name = tempfile.mkstemp(
            prefix=signature_path.name + ".", suffix=".tmp",
            dir=str(signature_path.parent) if signature_path.parent.exists() else None,
        )
        temp_path = Path(temp_name)
        with os.fdopen(handle, "wb") as stream:
            stream.write(signature)
        os.replace(temp_path, signature_path)
        temp_path = None
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass

    print(f"Signature written and verified: {signature_path} ({len(signature)} bytes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign or verify a Portappix catalog")
    parser.add_argument("--catalog", default="catalog.json")
    parser.add_argument("--key", help="P-256 private key (PEM) for signing; "
                                      "must be outside the repository. Never generated here.")
    parser.add_argument("--public-key", help="P-256 public key (PEM) used to verify the "
                                             "signature (default: keys/catalog_public.pem)")
    parser.add_argument("--allow-crlf", action="store_true",
                        help="Allow signing files containing CR bytes (\\r)")
    parser.add_argument("--signature", help="Signature file (default: <catalog>.sig)")
    parser.add_argument("--verify", action="store_true", help="Verify instead of signing")
    args = parser.parse_args(argv)

    catalog_path = Path(args.catalog)
    if not catalog_path.exists():
        print(f"ERROR: catalog not found: {catalog_path}")
        return 1

    signature_path = Path(args.signature) if args.signature else Path(
        str(catalog_path) + ".sig"
    )
    data = catalog_path.read_bytes()

    public_key_path = Path(args.public_key) if args.public_key else DEFAULT_PUBLIC_KEY

    if args.verify:
        if not public_key_path.exists():
            print(f"ERROR: public key not found: {public_key_path}")
            return 1
        if not signature_path.exists():
            print(f"ERROR: signature not found: {signature_path}")
            return 1
        digest_hex = hashlib.sha256(data).hexdigest()
        print(f"SHA-256 of verified bytes: {digest_hex}")
        ok = verify_bytes(data, signature_path.read_bytes(), load_public_key(public_key_path))
        print(f"Signature: {'OK' if ok else 'FAILED'} ({catalog_path})")
        return 0 if ok else 1

    if not args.key:
        print("ERROR: --key is required when signing")
        return 1

    verify_key_path = public_key_path
    if not verify_key_path.exists():
        print(f"ERROR: trusted public key for post-sign verification not found: {verify_key_path} "
              "(pass --public-key explicitly)")
        return 1
    verify_key = load_public_key(verify_key_path)

    signature_path.parent.mkdir(parents=True, exist_ok=True)
    return sign_and_swap(catalog_path, Path(args.key), signature_path, verify_key,
                         allow_crlf=args.allow_crlf)


if __name__ == "__main__":
    sys.exit(main())
