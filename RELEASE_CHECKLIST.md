# Release checklist

Do every step **in order**. Steps 1–4 happen on a build machine; steps 5–7
must happen in a clean Windows VM / Windows Sandbox — never on a daily-driver
machine.

## 1. Build

- [ ] `git status` is clean and `git pull` done; you are on the release commit.
- [ ] Win32 build of the launcher: `cd src && dcc32 -B Launcher.dpr`
- [ ] Win64 build of the launcher: `dcc64 -B Launcher.dpr`
- [ ] Win32 tests build and run green: `cd tests && dcc32 -B -U..\src PortappixTests.dpr && PortappixTests.exe`
- [ ] Win64 tests build and run green: `dcc64 -B -U..\src PortappixTests.dpr && PortappixTests.exe`
- [ ] No new compiler hints/errors introduced (`-Q` output clean except the known W1002).

## 2. Catalog and recipes

- [ ] `python scripts/validate_catalog.py` passes (schema, hashes, sizes, zip
      inspection, policy lint, URL reachability).
- [ ] Every recipe in `recipes\` passes the policy lint
      (`python tools/build_recipe.py --lint-only` or the CI recipe job).
- [ ] `catalog.json` was re-signed after any change:
      `python scripts/sign_catalog.py --catalog catalog.json --key "<operator signing key outside the repo>"`
      and verified: `... --public-key keys/catalog_public.pem --verify`.
- [ ] The embedded `Portappix.Signature.CatalogPublicKeyHex` still matches the
      public key of the signing key actually used
      (`keys/catalog_public.pem`; fingerprint comparison in
      `docs/security/SIGNING_KEY_MANAGEMENT.md`).

## 3. Documentation

- [ ] README tables (units, manifest fields, CLI switches) match the code.
- [ ] `tests\suite\real_apps.md` table has been reset (Pass/Fail/Notes cleared)
      for this release round.
- [ ] Version references updated where the version is shown (about line).

## 4. Release artifact

- [ ] `python scripts/make_release.py --source <staging-folder> --out dist\ --version x.y.z --channel stable --key <operator signing key outside the repo> --url-base https://<host>/downloads`
      builds the release zip, writes `releases.json` and signs it. The script
      excludes Git metadata, private keys, developer/IDE files and the
      `tests/`/`docs/` trees, and runs `scripts/package_guard.py` on the
      finished zip — if the guard fails, the artifact must not be uploaded.
- [ ] Package guard re-check (optional, standalone):
      `python scripts/package_guard.py dist\portappix-x.y.z-stable.zip`.
- [ ] `dist\releases.json` + `dist\releases.json.sig` verified with the
      verifier used by the launcher (`--check-updates` / the update check).
- [ ] Upload the release zip to the release URL from `releases.json`; the
      sha256/size in `releases.json` must match the uploaded asset.

## 5. Compatibility suite (clean VM / Windows Sandbox ONLY)

- [ ] `tests\fakeapps\build.cmd` builds all fake apps.
- [ ] `tests\suite\run_suite.ps1` — all cases pass; results JSON shows
      `failed: 0`.
- [ ] Every `*/host-clean` assertion passed (no host leaks).
- [ ] Crash-recovery case passed (kill the launcher mid-run, then recover).

## 6. Real apps (clean VM / Windows Sandbox ONLY)

- [ ] `tests\suite\real_apps.md` walked start to finish in this VM; Pass/Fail
      and Notes filled in.
- [ ] Trace mode was run at least once on an unknown app to confirm the
      warning dialog and `Trace\<id>_<timestamp>\report.md` output.
- [ ] The trace report's `suggested_app.json` loaded and passed
      `--check-manifest`.

## 7. Update flows (clean VM ONLY)

- [ ] App update: install an app, request a catalog update while it runs, and
      confirm the entry lands in `Cache\pending_updates.json` (Store tab shows
      "Update pending"); close the app, restart the launcher, confirm the
      update applied and `Data\<id>` was untouched; verify the "Roll back"
      offer (`Apps\<id>.prev`) restores the previous version.
- [ ] Self-update: install release N-1, point it at `releases.json` for N
      (`--check-updates` / `--self-update`), apply, and confirm the new
      version starts: `--post-update` writes `Cache\update_ok`, records the
      version in `Cache\launcher_version.json`, and keeps `Launcher.exe.old`
      as the rollback copy.
- [ ] Rollback watchdog: delete the `update_ok` marker (simulating a new
      version that never booted), relaunch, and confirm the offer to restore
      `Launcher.exe.old` (UI dialog; headless runs log a warning instead).
- [ ] Downgrade blocked: point at `releases.json` with a lower version and
      confirm refusal (exit code 7).
- [ ] Manifest downgrade protection: a package whose `version` or
      `dataVersion` is older than the installed app / recorded data version
      is refused.

## 8. Tag and publish

- [ ] Commit the release (`RELEASE: x.y.z`), tag `vX.Y.Z`, push tag.
- [ ] GitHub release with the zip + `releases.json` + `releases.json.sig`.
- [ ] Update the hosted catalog (and `releases.json`) URLs to the new assets.
