# Phase 2C — Final Sandbox Release Qualification

**Date:** 2026-11-12
**Qualification lead:** automated validation run (ZCode agent) under operator
approval, per `RELEASE_CHECKLIST.md` and the Phase 2C task definition.

---

## A. Executive Summary

- **Tested HEAD (product source):** `ce686d64da82a78757be1e05a5be82182944f8d9`
  (`docs: record R21 and the Phase 2B gate results`), branch `main`, working
  tree clean at the start of qualification; all Phase 2B commits (R15–R21)
  verified present.
- **Overall result:** all mandatory release gates passed on a disposable
  Windows Sandbox against binaries built from the exact tested HEAD.
- **Finding during qualification:** one mandatory gate (Gate 4) failed on the
  first Sandbox run. Investigation (§B.2, finding PH2C-01) showed the failure
  was a **stale gate expectation**, not a product defect: Gate 4 Case 6
  encoded pre-R9 rollback semantics and can never pass on any binary built
  after commit `81e61aa`. With operator approval, the gate case was reworked
  (test infrastructure only — **no product source changed**), and the full
  gate set was re-executed in a fresh Sandbox.
- **Release recommendation: GO** (§G).

### Qualification-event timeline

| Time (IST) | Event |
|---|---|
| 21:41 | Baseline verified: HEAD `ce686d6`, tree clean, Phase 2B commits present |
| 21:45–22:15 | Source audit R15–R21 (5 verified, 1 doc-only discrepancy); all artifacts rebuilt from HEAD; security scans, packaging guard, catalog/signing integrity — all clean |
| 22:17 | Sandbox run 1 (`20261112-221757`): Gates 1/2/3 pass; **Gate 4 FAIL at Case 6**; Gate 5 not reached (sandbox closed) |
| 22:30 | Qualification **stopped** per the §9 defect protocol; finding PH2C-01 documented and reproduced by code-path analysis; operator approval obtained for (a) the minimal gate fix and (b) two doc corrections |
| 23:07 | Sandbox run 2 (`20261112-230724`): **all gates green** (Gate 5 = platform-limited honest report) |

---

## B. Gate Results

Primary evidence: Sandbox run 2, `docs/audit/phase2c-evidence/sandbox-20261112-230724/`
(results dir `C:\Users\Public\PortappixSuiteResults`, started
`2026-11-12T23:07:17+05:30`, completed `2026-11-12T23:17:10+05:30`).
Run 1 (`20261112-221757/`) is retained as PH2C-01 evidence.

| Gate | Assertions passed | Failed | Status |
|---|---:|---:|---|
| Gate 1 — Crash recovery (real process termination at every journal checkpoint) | 13 | 0 | **PASS** |
| Gate 2 — Compatibility suite | 31 checks | 0 | **PASS** |
| Gate 3 — Self-update & watchdog rollback (R21 cross-check) | 23 | 0 | **PASS** |
| Gate 4 — Production rollback (release binary) | 46 | 0 | **PASS** (after approved Case 6 rework; run 1: 42 passed / 1 failed, aborted) |
| Gate 5 — Standard-user elevation check | — | — | **NOT RUN** — Windows Sandbox prohibits secondary logon (`seclogon`) by container policy; the script emits its designed honest environment-limitation report (byte-identical to all previous rounds). Full-VM procedure documented in the log. |

Gate 1 validated: real process termination at every checkpoint, recovery after
abrupt termination, journal consistency, fake-app survival, junction
restoration, host-clean guarantees (0 failures; raw log retained).

Gate 2 validated: 31 compatibility checks including 18 host-clean assertions
(no host leaks).

Gate 3 validated (§6 cross-check for R21): fresh update installation,
consecutive updates, `Launcher.exe.old` rotation, successful finalization
(`update_ok`), watchdog rollback, failed-build (1.3.0-fail) rollback — all
against the real staged-update flow that R21 repaired. Recovery after
interrupted finalization and no-self-replacement-of-the-executing-helper are
covered by the unit suites (R20/R21 checkpoint matrix, 944/0) rather than by
distinct Gate 3 cases, matching previous rounds.

Gate 4 validated (release `bin\Launcher.exe`): authentic authenticated
rollback (Cases 1, 2, 6), size- and content-tampered `.old` rejection (3a/3b),
missing-record rejection (4), mismatched-record rejection (5), schema-2 HMAC
record verification (Case 3), schema-1 migration behaviour (Case 6, fresh
un-established installation), preservation and correct consumption of
`Launcher.exe.old` throughout. Foreign-authentication-key rejection and
reparse-point refusal are covered by the unit suites
(`TestInstallationKeyIsolation`, junction/refusal tests) rather than by
distinct Gate 4 cases — unchanged from previous rounds.

### B.2 Finding PH2C-01 (Gate 4 Case 6) — resolved

- **Symptom (run 1):** `Case 6: Production launcher --accept-rollback
  succeeded with matching record` → FAIL; gate aborted at 42 passed / 1 failed.
- **Root cause:** the previous Gate 4 execution (2026-11-12 01:36) ran
  binaries built at 01:19 — before commit `81e61aa` (R9) existed. R9
  deliberately introduced the fail-closed rule
  (`src/Portappix.Update.pas:1010-1022`): *schema-1 rollback records are
  refused once authenticated schema-2 operation is established* (key blob or
  `Cache\rollback_migration.flag` present), preventing record laundering
  through the migration path. Gate 4's Cases 1–3 establish authentication for
  the test installation; Case 6 then hand-writes a schema-1 record and expects
  rollback to succeed — pre-R9 semantics. Cases 5 and 6 trigger the **same**
  refusal; Case 5 passes only because it expects refusal. As written, Gate 4
  was unsatisfiable on any post-`81e61aa` binary.
- **Product behaviour is correct:** the refusal is the documented, unit-tested
  R9 security policy (`VerifyOldLauncher refuses schema-1 records once
  schema-2 is established (R9)`; `R9: legitimate schema-1 record verifies
  pre-establishment`). No product source was implicated.
- **Reproduction:** deterministic; the decision path is unambiguous
  (established installation + schema-1 record → refusal → non-zero exit),
  confirmed by the run-1 log and the unit tests above.
- **Approved minimal fix (test infrastructure only):** `Case 6` in
  `tests/suite/run_rollback_validation.ps1` now exercises the legitimate
  schema-1 migration success path on a **fresh sub-installation** (no key
  blob, no migration flag) with an authentic `.old` and a matching schema-1
  record; the established-state refusal assertions (Case 5) are unchanged and
  no assertion was weakened. The migration success path previously had no
  Sandbox-level E2E coverage; it now does.
- **Result:** run 2 Gate 4 = 46 passed / 0 failed.

---

## C. Build Results

All artifacts built from the exact tested HEAD (`ce686d6`, clean tree).

| Configuration | Tool | Result | Warnings |
|---|---|---|---|
| Launcher Win32 Release (`bin\Launcher.exe`) | dcc32 36.0 | OK — 5,205,504 B | 0 (build output clean) |
| Launcher Win64 Release (`bin\Launcher64.exe`) | dcc64 36.0 | OK — 7,657,984 B | 0 |
| Launcher Win32 TESTCRASH (`bin\LauncherTestCrash.exe`) | dcc32 | OK | H2077 hints only (pre-existing) |
| Tests Win32 test-config (TESTCRASH+TESTUPDATE+TESTINJECT) | dcc32 | OK — **944 passed / 0 failed** | 5 warnings: 3× W1002 (known, accepted per checklist), W1012 + W1036 (pre-existing, test code only) |
| Tests Win64 test-config | dcc64 | OK — **944 passed / 0 failed** | same |
| Tests Win32 release-config (TESTCRASH) | dcc32 | OK — **791 passed / 0 failed** | 4 warnings (3× W1002 + pre-existing test-code warning) |
| Tests Win64 release-config | dcc64 | OK — **791 passed / 0 failed** | same |
| Fake apps (Win32 + Win64) | `tests\fakeapps\build.cmd all` | OK | — |
| Self-update fixtures (1.0.0 / 1.1.0 / 1.2.0 / 1.3.0-fail, throwaway keys outside the repo) | `scripts\build_selfupdate_fixture.ps1` | OK, feeds signed + verified | — |

Full compiler logs: `docs/audit/phase2c-evidence/build_tests_*.log`,
`build_fakeapps.log`, `build_selfupdate_fixture.log`.

**Flaky-test note (host only):** in 1 of 6 Win32 release-config runs, the
timing-sensitive concurrency test `Tx journal: concurrent journal access fails
with a busy error (no exception raised)` failed; the identical binary passed
5/6 runs and passed in every other configuration (including both test-config
runs where the same test appears). Treated as host-timing sensitivity, not a
regression; both the failing and clean logs are retained.

---

## D. Security Results

- **Production binary isolation:** `launcher_forbidden_material`
  (`scripts/make_release.py`) accepts `bin\Launcher.exe` and
  `bin\Launcher64.exe` (CLEAN) and **flags every test-mode binary**
  (`LauncherTestCrash.exe`, `PortappixTests_Test.exe`,
  `PortappixTests_Release.exe`) — accept/reject behaviour verified. A broad
  independent byte-scan of both production binaries (UTF-16LE and UTF-8) found
  **no** occurrence of `PORTAPPIX_TESTCRASH`, `PORTAPPIX_TESTUPDATE`,
  `PORTAPPIX_TESTINJECT`, `PORTAPPIX_CRASH_AT`, the failure-injection hook
  identifiers (`PortappixFileMoveHook`, `PortappixFileDeleteHook`,
  `PortappixDirectoryDeleteHook`), build markers, or PEM private-key markers.
- **Packaging guard:** `scripts/package_guard.py` accepts a zip of the
  production binaries (no forbidden material); the launcher-level
  test-isolation guard provides the test-binary rejection above.
- **Isolation suites:** `test_failure_injection_isolation.py` **53 passed /
  0 failed**; `test_crash_hook_isolation.py` **51 passed / 0 failed**.
- **Rollback authentication:** Gate 4 Cases 1–6 (schema-2 HMAC verification,
  schema-1 establishment-gated migration, tamper/missing/mismatch refusal) all
  pass on the release binary; per-installation key isolation is unit-verified
  (`TestInstallationKeyIsolation`).
- **Companion backup integrity:** R15/R16 invariants re-verified by source
  audit at HEAD; exercised end-to-end by Gate 3; unit suites 944/0.
- **Signing integrity:** `catalog.json`
  (`6a11325a9f434f9ef432cfe0befd217977f758a3bb27428e13f632e43e52123d`),
  `catalog.json.sig`
  (`7070019795d135902a9e7e9e044557fe2cdf8cee33fc95dd4b9efb17862f07c6`) and
  `keys/catalog_public.pem`
  (`4267990f7387888be42b6e573f0495bcaa1c87fa9cd9f33585c72cd611a9d7eb`) are
  byte-identical to the approved baseline (tracked in git, working tree clean;
  last touched by commit `3082123`, before Phase 1).
  `scripts/validate_catalog.py` passes, including signature verification.
- **No private signing keys** were created, modified, copied or committed:
  `keys/` contains only `keys/catalog_public.pem`; the self-update fixture
  builder generates its throwaway ECDSA keypair under the git-ignored
  `tests/suite/fixtures/` staging tree only.

### Documentation corrections applied during qualification (operator-approved)

1. `docs/security/UPDATE_ROLLBACK_INTEGRITY.md` — R19 key location corrected
   (`<user-profile>` via `TPath.GetHomePath`, not `%LOCALAPPDATA%`), and §2.1
   now documents the R9 establishment gate (schema-1 accepted only before
   authenticated operation is established; inconsistent flag-without-key state
   refuses rollback entirely).
2. `docs/audit/REMEDIATION_REPORT.md` — R19 fix column corrected to the real
   key path.

---

## E. Evidence

All under `docs/audit/phase2c-evidence/`:

- `sandbox-20261112-230724/` — **primary Sandbox run 2**: `gate1_crash.log`
  (13/0), `gate2_suite.log` (31/0), `gate3_selfupdate.log` (23/0),
  `gate4_rollback.log` (46/0), `gate5_standard_user.log` (honest
  environment-limitation report), `results.json`, suite summary
  `20261112-230724.{json,md}`, `sandbox_started.txt`, `all_gates_complete.txt`.
- `sandbox-20261112-221757/` — run 1 (PH2C-01 evidence: Gate 4 abort at
  Case 6; Gates 1–3 already passing).
- `binary-sha256.txt` — SHA-256 of every built binary:

| Binary | SHA-256 |
|---|---|
| `bin/Launcher.exe` (Win32 Release) | `8f3590e65f6f9859db8c510f71a5cf5ff80ec85f93604fe040b4d44efbb83851` |
| `bin/Launcher64.exe` (Win64 Release) | `b5b8263abc6311634282bfd04aecb95fece95f7d47fa88d580ac4426267b87ef` |
| `bin/LauncherTestCrash.exe` (Win32 TESTCRASH) | `40161fb84b24f096e5c5bf878f85c250c1c1133cdd9b318fc2058b6c11486f8f` |
| `bin/PortappixTests_Test.exe` | `76b23b6cf20285b5754aec39107571793b8025960bb1c666a8d9c41278765452` |
| `bin/PortappixTests_Test64.exe` | `519e0fbef80e0fcb078fdd02f4b8fe1250b049191508449d3983afe758508cff` |
| `bin/PortappixTests_Release.exe` | `87a6a63acdb2eebaa3d470653a3f37b9874f0acd220ad51193f18e9b3137fe50` |
| `bin/PortappixTests_Release64.exe` | `1128bed7a72d3e0ac35321d7c058333dd4671b5cd463bfb00e34ed3f0205f82d` |

- Build logs: `build_tests_win{32,64}_{test,release}config.log`,
  `build_fakeapps.log`, `build_selfupdate_fixture.log`.
- Unit-test run logs: `unit-tests-win{32,64}-testconfig.log` (944/0 each),
  `unit-tests-win32-releaseconfig.log` (flaky-host run, 790/1),
  `unit-tests-win32-releaseconfig-rerun.log` (791/0).
- Isolation/security scans: `failure-injection-isolation.log` (53/0),
  `crash-hook-isolation.log` (51/0), `validate_catalog.log` (OK).
- The Sandbox host results dir was reset between runs by **relocating** the
  previous contents (`C:\Users\Public\PortappixSuiteResults_run1_failed_case6`,
  `..._prev_20261112_0137`) — nothing was deleted.

---

## F. Remaining Risks

Inherited from Phase 2B §9.3 (unchanged):

1. **Legacy key adoption** links installations created before R19 on the same
   machine (each copies the same historic key). New installations are fully
   independent.
2. **Long-path support is per-component bounded** — a single path component
   over 255 characters is rejected by NTFS (clean failure, no data loss).
3. **`RootDirectory`-relative handle renames** unsupported on the tested
   Windows build; absolute names are used (sufficient for the rollback path).
4. **Power-loss validation** of durable writes remains a VM-class open item
   (unit simulation and real process termination are different evidence
   classes).
5. **Orphaned staging/companion directories** after an unrecoverable
   interruption are preserved deliberately and need operator cleanup after
   inspection.

Specific to this round:

6. **Gate 5 is not executable inside Windows Sandbox** (container policy
   blocks secondary logon). The gate emits its designed honest
   environment-limitation report; the ERROR_ELEVATION_REQUIRED path remains
   unit-verified. A full-VM run (Hyper-V/VirtualBox with `seclogon` enabled)
   is the documented path to exercise the real standard-user scenarios.
7. **Flaky host-timing unit test** (`Tx journal: concurrent journal access
   fails with a busy error`, 1 failure in 6 Win32 release-config host runs) —
   timing-sensitive concurrency assertion; passed in all other runs and
   configurations.
8. **Gate-4 foreign-key and reparse refusal coverage** lives in the unit
   suites, not as distinct Gate 4 cases (unchanged from previous rounds).

---

## G. Final Recommendation

**GO.**

All mandatory release gates for this phase passed on a disposable Windows
Sandbox against binaries built from the exact tested HEAD `ce686d6`:
Gate 1 (13/0), Gate 4 (46/0), with Gate 2 (31/0) and the R21 cross-check
Gate 3 (23/0) also green; production builds are clean, release security scans
and the packaging guard accept the production binaries and reject test-mode
binaries, and catalog/signing material is byte-identical to the approved
baseline. The single gate failure encountered was proven to be a stale gate
expectation (PH2C-01), fixed with operator approval as test-infrastructure
only, and the full gate set re-executed green.

Gate 5 remains a platform limitation of Windows Sandbox (not a failure); if
the release operator treats a real standard-user elevation run as mandatory,
execute `tests\suite\run_standard_user_validation.ps1 -IConfirmThisIsAVM` in a
full VM per the documented procedure before publishing.
