# Portappix Signing Key Management

Applies to: the ECDSA P-256 key pair that signs `catalog.json`, `releases.json`,
and recipe-built catalogs. Verified with Windows CNG by the embedded public key
in `src/Portappix.Signature.pas` (`CatalogPublicKeyHex`).

## 1. Why the previous key is considered compromised

During the Phase 0 audit (2026-11-09) the repository-local archive
`portappix.zip` was found to contain `keys/catalog_signing_key.pem` — the
then-current private signing key — together with the full `.git/` directory.
Any copy of that archive that has ever left the build machine (or any backup
of the repository tree that included `keys/`) exposes the key.

Per the Phase 1 decision, the old key is therefore **treated as compromised
regardless of whether the ZIP is known to have been shared**. The key was
rotated on 2026-11-09; the old private key file was removed from the working
tree and must never be used for signing again.

**Removing the old key from a ZIP does not erase historical copies.** The
archive exists in backups, download caches, and possibly third-party hands;
deleting a file from the current working tree changes nothing about copies
that were already made. This is why the response is rotation, not deletion.

## 2. Current key facts (public information only)

| Item | Value |
| --- | --- |
| Algorithm | ECDSA P-256 (SECP256R1), signature = raw 64-byte `r‖s` over SHA-256 of the exact bytes |
| Public key (committed) | `keys/catalog_public.pem` |
| Public-key fingerprint (SHA-256 of SPKI DER) | `85:97:78:2E:83:04:1E:1E:60:E8:2F:B8:22:66:78:81:10:A9:0B:EA:3B:CD:4A:77:75:4E:3D:FA:48:9D:AF:E7` |
| Trust anchor (launcher) | `CatalogPublicKeyHex` constant in `src/Portappix.Signature.pas` (CNG ECCPUBLICBLOB format) |
| Private key location | **Outside the repository**, at an operator-chosen path — the current deployment uses `%USERPROFILE%\.portappix\signing\catalog_signing_key.pem`, ACL-restricted to the owning user |
| Git protection | `.gitignore` excludes `keys/*`, `*.pem`, `*.pfx`, `*.p12`, `*.pvk`, `*.key`, `*.sig.tmp`, and common secret files; only `keys/catalog_public.pem` is whitelisted |

## 3. New key-generation procedure

Never generate keys as a side effect of signing. Use the dedicated tool:

```bash
python scripts/generate_signing_key.py \
    --out "$USERPROFILE/.portappix/signing/catalog_signing_key.pem" \
    --public-out keys/catalog_public.pem
```

The tool:

- refuses output paths inside any Git repository,
- refuses to overwrite an existing private key,
- writes the private key with user-only ACLs on Windows (`icacls
  /inheritance:r /grant:r <user>:F`) or `0600` elsewhere,
- prints only public information (fingerprint, CNG `ECCPUBLICBLOB` hex for
  the launcher constant) and never private-key material.

After generating, update `CatalogPublicKeyHex` in `src/Portappix.Signature.pas`
with the printed blob and commit the new `keys/catalog_public.pem`.

## 4. Secure private-key storage requirements

- The private key lives **outside the repository**, on a build/signing
  machine controlled by the maintainer.
- File ACLs allow only the operator account (and no network-visible shares).
- It must never be committed, packaged, uploaded, pasted into chat/email, or
  copied into a staging folder. `scripts/package_guard.py` fails any release
  archive that contains it.
- The recommended location follows the pattern
  `%USERPROFILE%\.portappix\signing\<name>.pem` on Windows.
- Backups, if any, must be encrypted (e.g. age/BitLocker-to-go) and stored
  with the same care as production credentials.

No hardware-backed protection (TPM/HSM) is used or claimed; the key is a
software PEM file protected by file-system ACLs.

## 5. Signing procedure

```bash
python scripts/sign_catalog.py --catalog catalog.json \
    --key "$USERPROFILE/.portappix/signing/catalog_signing_key.pem"
```

Behaviour (implemented in `scripts/sign_catalog.py`):

- The private key must be passed explicitly (`--key`); signing never
  generates or falls back to a key.
- The key must parse as PEM and be an ECDSA P-256 key; anything else is a
  clean failure with exit code 1 (no tracebacks, no key material printed).
- The signature is written to a temporary file, **verified immediately**
  against the trusted public key (`--public-key` or the committed
  `keys/catalog_public.pem`), and only then moved into place.
- A failed or unverifiable signing never replaces an existing valid
  signature; temporary files are always cleaned up.
- `scripts/make_release.py` and `tools/build_catalog.py` reuse the same
  primitives and require the same explicit `--key`.

## 6. Signature verification procedure

- **Application:** the launcher verifies every catalog and `releases.json`
  with the embedded public key via CNG (`Portappix.Signature.VerifySignature` /
  `VerifySignatureForCatalog`). Specifically:
  - **`releases.json` (self-update):** `DownloadReleases` in `Portappix.Update.pas`
    unconditionally requires and verifies the release signature (`<url>.sig`)
    against the embedded public key. There is no developer flag, command-line
    switch, or bypass for `releases.json` signature verification under any build
    configuration; an unsigned or invalid release manifest is always refused.
  - **`catalog.json` (app store):** `LoadFromFile` and `LoadFromUrl` in
    `Portappix.Catalog.pas` check for `<catalog>.sig` (or `<url>.sig`) and
    verify it against the embedded key (`SignatureVerified := True`). In release
    builds, signature verification is mandatory: any catalog without a `.sig`
    or with an invalid signature raises `EPortappixCatalogError`, and the dev
    flag does not exist in the compiled code. Under `PORTAPPIX_TESTUPDATE` test
    builds only, an internal variable `AllowUnsignedCatalogs: Boolean = False`
    is compiled in to permit unsigned catalogs for local test harnesses when
    explicitly set. Furthermore, `ApplyPendingUpdates` in
    `Portappix.PackageManager.pas` verifies `Catalog.SignatureVerified` before
    processing any queued update, ensuring unsigned catalogs cannot be used to
    apply updates.
- **Tooling:** `python scripts/sign_catalog.py --catalog catalog.json
  --public-key keys/catalog_public.pem --verify` (exit 0 = OK).
- **Independent check:** the fingerprint in §2 can be compared against the
  committed PEM: `openssl pkey -pubin -in keys/catalog_public.pem -outform DER
  | openssl dgst -sha256`.

## 7. Key backup and recovery

- Back up the private key **encrypted** (the PEM is protected only by file
  ACLs at rest) to a second location the operator controls.
- Record the fingerprint of the backed-up key and verify the restore by
  re-computing it.
- If the private key is lost and no backup exists: generate a new key pair
  (§3) and follow the rotation sequence (§9). Signatures from the lost key
  remain verifiable by launchers that still embed it — so never lose track of
  which trust pin a distributed launcher carries.

## 8. Key rotation procedure (future releases)

1. Generate a new key pair (§3). Do not touch the old private key file.
2. Update `CatalogPublicKeyHex` in `src/Portappix.Signature.pas` and commit
   the new `keys/catalog_public.pem` (replacing the old one).
3. Re-sign every signed artifact with the new key: `catalog.json`,
   `dist/releases.json` (+ `.sig` files), and any recipe-built catalogs.
4. Run `python tests/scripts/test_signing_workflow.py` and the Delphi test
   suite; update the self-test vectors in `tests/PortappixTests.dpr`
   (`TestSignatureVerification`) the same way the Phase 1 rotation did.
5. Follow the release sequence in §10.
6. Destroy the retired private key (shred the file; it must never sign again)
   and remove it from every signing machine.

## 9. Incident response — private key exposed

1. **Assume the key is compromised.** Delete a file from a ZIP or the repo
   does not un-leak it.
2. Rotate immediately (§8): new key, new embedded pin, re-sign everything.
3. Publish the new launcher/catalog and document the rotation date and
   fingerprint (like §2).
4. Hunt for the exposure path and fix the packaging hole (in the 2026-11-09
   incident: `portappix.zip` contained `keys/` and `.git/`; the fix is the
   automated `scripts/package_guard.py` check now built into every packaging
   path, plus the `.gitignore` rules).
5. Never attempt to "reuse carefully" a known-exposed key.

## 10. Catalog migration / coordinated release sequence

Launchers pin the trust key at compile time, so trust changes are not
backwards-compatible in the other direction:

1. Build and publish the **new launcher** whose embedded pin is the new
   public key (this launcher rejects all old-key signatures).
2. Re-sign `catalog.json` / `releases.json` with the **new** key and publish
   them.
3. Launchers from before this transition accept only old-key signatures:
   they must not be pointed at new-key catalogs. Distribute the new launcher
   through the normal self-update flow **before** switching the hosted
   catalog to new-key signatures.
4. Old-key signatures are rejected by every launcher built after the
   transition (covered by regression tests: the old-key catalog signature is
   verified rejected in `TestSignatureVerification`).

Verification is never weakened to keep old signatures working.

## 11. Release packaging protection (summary)

- `scripts/package_guard.py` inspects every distribution archive for `.git/`
  paths, private-key directories/files, secret-bearing config files, and PEM
  markers; it is wired into `scripts/make_release.py`,
  `tools/build_recipe.py`, and `scripts/validate_catalog.py`, and can be run
  standalone: `python scripts/package_guard.py <archive>`.
- `scripts/make_release.py` additionally excludes Git metadata, developer/IDE
  files, and the repository-only `tests/`/`docs/` trees while zipping.
- The historical `portappix.zip` snapshot at the repository root predates
  these guards and **does** contain forbidden material; it is preserved as an
  existing artifact and must not be distributed (see
  `docs/audit/phase-1/PHASE_1_REPORT.md`).
