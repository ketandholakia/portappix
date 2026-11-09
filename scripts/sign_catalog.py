#!/usr/bin/env python3
"""Create or verify a Portappix catalog signature.

The signature is ECDSA P-256 over the SHA-256 digest of the exact catalog bytes,
stored as the raw 64-byte r||s value expected by Windows CNG (BCrypt*).

Requires: pip install cryptography
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

SIGNATURE_SIZE = 64


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise SystemExit(f"ERROR: {path} is not a P-256 (SECP256R1) private key")
    return key


def load_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign or verify a Portappix catalog")
    parser.add_argument("--catalog", default="catalog.json")
    parser.add_argument("--key", help="P-256 private key (PEM) for signing")
    parser.add_argument("--public-key", help="P-256 public key (PEM) for verification")
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

    if args.verify:
        if not args.public_key:
            print("ERROR: --public-key is required with --verify")
            return 1
        if not signature_path.exists():
            print(f"ERROR: signature not found: {signature_path}")
            return 1
        ok = verify_bytes(data, signature_path.read_bytes(), load_public_key(Path(args.public_key)))
        print(f"Signature: {'OK' if ok else 'FAILED'} ({catalog_path})")
        return 0 if ok else 1

    if not args.key:
        print("ERROR: --key is required when signing")
        return 1

    signature = sign_bytes(data, load_private_key(Path(args.key)))
    signature_path.write_bytes(signature)
    print(f"Signature written: {signature_path} ({len(signature)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
