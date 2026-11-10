# Portappix — Phase 1 Report: Signing Key Rotation & Distribution Security

Date: 2026-11-09/10. Branch `main`, HEAD at start and end `c4bce225d55c1b13ff9a88a9b8bc0d1fef1df180`
(the 7 unpushed commits vs `origin/main` are intact; no commit, push, reset, stash, or branch
change was made). No private-key material appears anywhere in this report or in the repository.

## 1. Initial repository state

- Pre-flight matched the Phase 0 baseline exactly: branch `main`, HEAD `c4bce22`, 7 commits
  ahead of `origin/main`, working tree clean except the untracked `docs/` audit directory from
  Phase 0 (expected — it was never committed).
- `Portappix.Signature.pas` embedded the pre-rotation public key; the private key existed at
  `keys/catalog_signing_key.pem` (git-ignored, 241 bytes); root `catalog.json.sig` carried a
  signature made with that old key.
- Python tooling available: `cryptography` 50.0.2. Delphi 12 Athens (BDS 23.0, compiler 36.0)
  with `dcc32`/`dcc64`.

## 2. Files changed

Modified (tracked):

| File | Change |
| --- | --- |
| `src/Portappix.Signature.pas` | Trust pin replaced with the new public key (`CatalogPublicKeyHex`); `VerifySignature` refactored into `VerifySignatureWithKey(content, signature, publicKey)` + trust-pinned wrapper; fail-closed 72-byte public-blob length check; BCrypt implementation otherwise unchanged. |
| `scripts/sign_catalog.py` | Hardened: explicit `--key` (never generated/fallback), clean non-zero failures for missing/empty/unparseable/non-P-256 keys, sign→temp→verify-against-trusted-public-key→atomic swap, existing valid signature never replaced, temp files always cleaned, no key material logged. `load_private_key`/`sign_bytes` API preserved for `make_release.py`/`build_catalog.py`. |
| `scripts/make_release.py` | Zip-creation exclusions (Git metadata, `keys/`/`.ssh`, key-file extensions, secret configs, `__pycache__`/IDE files, top-level `tests/`+`docs/` with `--include-dev-dirs` override) + automated `package_guard` verification of the built zip with non-zero exit on violations. |
| `scripts/validate_catalog.py` | `inspect_package` now runs `package_guard.check_archive` on every downloaded package zip. |
| `tools/build_recipe.py` | Built package zip is guard-checked before the `.build.json` manifest is produced. |
| `.gitignore` | `keys/*` + `!keys/catalog_public.pem` exception, `*.pem`, `*.pfx`, `*.p12`, `*.pvk`, `*.key`, `*.sig.tmp`, `.env*`, `secrets.*`, `credentials.json`. |
| `catalog.json.sig` | Re-signed with the new key (64-byte raw `r‖s`; verified with `keys/catalog_public.pem`). |
| `tests/PortappixTests.dpr` | New `TestSignatureVerification` (14 checks) + `Portappix.Signature` in uses. |
| `README.md`, `RELEASE_CHECKLIST.md`, `recipes/README.md` | Signing commands now reference the operator key path and `keys/catalog_public.pem`; package-guard step added to the release checklist. |

Added (untracked until committed):

| File | Purpose |
| --- | --- |
| `scripts/generate_signing_key.py` | Rotation-only key generation; refuses repo paths and overwrites; ACL-hardens the private key; prints only public data. |
| `scripts/package_guard.py` | Distribution-archive guard (also a standalone CLI). |
| `keys/catalog_public.pem` | The new trusted public key (the one whitelisted key file). |
| `tests/scripts/test_signing_workflow.py` | 24-check hand-rolled harness for the signing workflow + package guard (synthetic keys only). |
| `docs/security/SIGNING_KEY_MANAGEMENT.md` | Key management, rotation, incident response, release sequence. |
| `docs/audit/phase-1/PHASE_1_REPORT.md` | This report. |

## 3. New public-key fingerprint

**`85:97:78:2E:83:04:1E:1E:60:E8:2F:B8:22:66:78:81:10:A9:0B:EA:3B:CD:4A:77:75:4E:3D:FA:48:9D:AF:E7`**
(SHA-256 over the SubjectPublicKeyInfo DER of `keys/catalog_public.pem`; re-verified after
placement). The embedded `CatalogPublicKeyHex` blob was regenerated from the same key and the
committed PEM, the `.dpr` test constants, and the PEM were cross-verified programmatically.

## 4. Key generation and storage outcome

- Generated with the new `scripts/generate_signing_key.py`: ECDSA P-256, PKCS#8 PEM.
- Private key stored **outside the repository** at
  `%USERPROFILE%\.portappix\signing\catalog_signing_key.pem`; ACL verified via `icacls` — the
  file carries exactly one ACE (`<user>:(F)`), inheritance removed.
- The old compromised key file `keys/catalog_signing_key.pem` was **deleted from the working
  tree** (operator-approved). A historical copy remains preserved inside the legacy
  `portappix.zip`, which is kept as an existing artifact. The old key was never read, printed,
  or used after the rotation decision (the old signature used in tests was captured from
  `catalog.json.sig` before re-signing — a public artifact).
- No private key was ever committed, staged, or packaged. `git diff` was scanned for
  `PRIVATE KEY`/password/secret markers: only code identifiers match.

## 5. Old-key rejection and new-key acceptance evidence

All vectors were validated cryptographically (Python, `cryptography`) **before** being embedded
in tests, and the Delphi tests were then executed on both targets:

| Evidence | Result |
| --- | --- |
| New-key signature over fixed self-test content accepted by the embedded new pin (`VerifySignatureForCatalog`) | PASS (Win32 + Win64) |
| The genuine old-key signature over the pre-rotation `catalog.json` rejected by the new pin | PASS (Win32 + Win64) |
| The same old-key signature still verifies under the old public blob when supplied explicitly (`VerifySignatureWithKey`) — proving rejection is caused by the trust-pin change, not a bad vector | PASS |
| A different (synthetic) key's signature rejected by the embedded pin, and self-verifies under its own blob | PASS |
| The embedded pin differs from the pre-rotation pin constant | PASS |
| Tampered content, 63-byte/empty/all-zero signatures, truncated and wrong-magic public blobs, empty content — all fail closed | PASS |

The 14 signature checks appear as `PASS: Signature: …` lines in both test runs
(167 pre-existing checks unchanged → **181 passed / 0 failed on Win32 and Win64**).

## 6. Packaging guard results

- `python scripts/package_guard.py portappix.zip` → **FAILED, 461 violations** (`.git/*` under
  GIT_METADATA; `keys/catalog_signing_key.pem` under PRIVATE_KEY_DIR and PEM_MARKER), exit code 1.
  The legacy artifact is preserved on disk and flagged as not-for-distribution.
- `tests/scripts/test_signing_workflow.py` → **24 passed / 0 failed**: `.git/config`, `keys/*.pem`,
  nested `a/b/keys/*.key`, `.GIT` (case-insensitive), backslash-style entries, PEM-marker text
  files, `.env`, `.pfx` all rejected; a clean package and clean CLI run pass; signing workflow
  failures (missing/invalid/wrong-curve/RSA/absent `--key`) exit non-zero without touching an
  existing valid signature; temp files are cleaned up.
- During test development the guard's file-extension rule was found not to fire (dotted-set
  comparison bug) — fixed in `package_guard.py` and re-verified by the suite.

## 7. Build and test results

Command-line builds (documented path; output redirected to
`%LOCALAPPDATA%\Temp\portappix-phase1-build\` so no existing artifact was touched; `-E`/`-N0`
are output-location flags only):

| Target | Result | Warnings |
| --- | --- | --- |
| Launcher Win32 (`dcc32 -B -E. -N0. -U<repo>\src <repo>\src\Launcher.dpr`) | Success, 10,430 lines | 1 (known W1002) |
| Launcher Win64 (`dcc64`, same flags) | Success | 1 (known W1002) |
| Tests Win32 (`tests\PortappixTests.dpr`) | Success, 8,845 lines | 1 (known W1002) |
| Tests Win64 | Success | 1 (known W1002) |

| Test run | Result | Exit code |
| --- | --- | --- |
| `PortappixTests.exe` Win32 | **181 passed, 0 failed** (167 baseline + 14 new) | 0 |
| `PortappixTests.exe` Win64 | **181 passed, 0 failed** | 0 |
| `python tests/scripts/test_signing_workflow.py` | **24 passed, 0 failed** | 0 |
| `tests/suite/run_suite.ps1` | **NOT-RUN** — deliberately hijacks `HKCU\Software\PortappixTest`, `%PROGRAMDATA%\PortappixTest` and `%APPDATA%\FakeApps`; VM/Windows-Sandbox-only by its own header, and Phase 1 instructions prohibit destructive compatibility tests on the development machine. |

## 8. Remaining risks and limitations

1. **Legacy `portappix.zip` still contains the old private key and `.git/`** — preserved per
   instructions; the operator must delete/quarantine it manually. It must never be distributed.
2. **Any launcher built before this phase embeds the old pin** and will reject new-key catalogs —
   follow the coordinated release sequence in `docs/security/SIGNING_KEY_MANAGEMENT.md` §10
   (publish the new launcher before pointing hosted URLs at new-key signatures).
3. **Git history** still contains pre-rotation commits (including the old `keys/` handling in
   earlier working trees — the key file itself was never tracked). History was deliberately not
   rewritten; the old key is treated as compromised, which is why rotation (not deletion) was the
   remedy.
4. **run_suite.ps1, validate_catalog.py full run, and recipe builds were not executed** (VM
   requirement / network downloads); their code paths were exercised via the new unit tests
   instead. The `validate_catalog.py` guard wiring compiles and imports, but has not run against
   a live catalog.
5. The private key is protected by file ACLs only — no TPM/HSM backing is implemented or claimed.
6. `Portappix.Consent` policy-consent hashes are unrelated to signing keys; no migration needed.

## 9. Exact commands used

```
# pre-flight
git rev-parse --abbrev-ref HEAD; git rev-parse HEAD; git status --short
git log origin/main..HEAD --oneline | wc -l

# key generation (tool written, then executed)
python scripts/generate_signing_key.py \
    --out "$USERPROFILE/.portappix/signing/catalog_signing_key.pem" \
    --public-out keys/catalog_public.pem
icacls "$USERPROFILE/.portappix/signing/catalog_signing_key.pem"   # ACL verification

# rotation
python scripts/sign_catalog.py --catalog catalog.json \
    --key "$USERPROFILE/.portappix/signing/catalog_signing_key.pem"
python scripts/sign_catalog.py --catalog catalog.json \
    --public-key keys/catalog_public.pem --verify
rm keys/catalog_signing_key.pem

# builds (from %LOCALAPPDATA%\Temp\portappix-phase1-build\<dir>)
dcc32 -B -E. -N0. -UC:/Users/Admin/Documents/github/portappix/src \
    C:/Users/Admin/Documents/github/portappix/src/Launcher.dpr          # + dcc64
dcc32 -B -E. -N0. -UC:/Users/Admin/Documents/github/portappix/src \
    C:/Users/Admin/Documents/github/portappix/tests/PortappixTests.dpr  # + dcc64

# tests
PortappixTests.exe                                          # per target dir
python tests/scripts/test_signing_workflow.py
python scripts/package_guard.py portappix.zip

# final review
git status --short; git diff --stat; git diff | grep -iE "PRIVATE KEY|PASSWORD|API_KEY|SECRET="
```

## 10. Operator actions still required

1. Delete or securely archive the legacy `portappix.zip` (contains the compromised key and
   `.git/`); it is preserved untouched for this decision.
2. Make an **encrypted** backup of `%USERPROFILE%\.portappix\signing\catalog_signing_key.pem`
   and record the fingerprint from §3 with it.
3. When next publishing: build the release with
   `python scripts/make_release.py … --key <operator key path>` and follow the §10 release
   sequence (new launcher before new-key catalog at the hosted location).
