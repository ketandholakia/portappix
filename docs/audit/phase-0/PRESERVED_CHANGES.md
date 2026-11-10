# Portappix — Phase 0 Preserved Changes

This document records every developer change / local artifact that existed **before** Phase 0
began, and why each was preserved. Nothing on this list was modified, deleted, overwritten,
stashed, reset, or checked out during Phase 0.

## 1. Git working tree

`git status` at Phase 0 start (and end): **clean** — no unstaged modifications, nothing staged,
no untracked files. Therefore there were **no uncommitted developer modifications to classify**
(existing-developer-modification / untracked-developer-file / generated / unknown: all four
categories are empty for the working tree).

## 2. Unpushed commits (the real "existing developer changes")

Local `main` is **7 commits ahead of `origin/main`** (origin at `52fabc9`). These commits are
the current developer state and were preserved exactly:

| Commit (oldest→newest) | Subject | Content |
| --- | --- | --- |
| `e1d1192` | Fix remaining compile issues and persist the catalog URL setting | source fixes + `Cache\catalog_url.txt` persistence |
| `16f2886` | Document how to run the unit tests (both bitnesses) and ignore local zips | README + .gitignore |
| `b403334` | Add the compatibility suite: fake apps, manifests, runner script, sandbox config | `tests/fakeapps/**`, `tests/suite/**` (incl. `run_suite.ps1`, +538 lines) |
| `f108a43` | Part 2: trace reports - what did this app touch | `Portappix.Trace.pas`, CLI/UI/README integration |
| `bb0e8bc` | Part 3a: safe app updates - semver, downgrade protection, pending queue, rollback | `Portappix.Version.pas`, package-manager changes |
| `c71851e` | Part 3b: launcher self-update - signed releases.json, swap, watchdog | `Portappix.Update.pas`, `make_release.py` |
| `c4bce22` | Part 4: known-app recipes - 25 pinned recipes, recipe tooling, catalog provenance | `recipes/**`, `recipe.schema.json`, `tools/**`, provenance fields |

Cumulative vs `origin/main`: 74 files, +8,937/−122. **No push, commit, reset, rebase, or
stash was performed** — pushing remains the maintainer's decision.

## 3. The `tests/suite/run_suite.ps1` instruction

The Phase 0 brief said "Do not overwrite the existing `tests/suite/run_suite.ps1` modification."
Verified state:

- `git log --follow -- tests/suite/run_suite.ps1` → exactly one commit (`b403334`, the +538-line add).
- `git status` shows no working-tree modification of the file.
- Conclusion: the referenced "modification" is the file's **committed** state; it was opened for
  reading only and is byte-for-byte unchanged after Phase 0.

## 4. Git-ignored local artifacts (preserved on disk, untouched)

All of these are excluded by `.gitignore` and were left exactly as found:

| Artifact | Why preserved |
| --- | --- |
| `keys/catalog_signing_key.pem` | The production signing key. Never read, printed, moved, rotated, or regenerated (Phase 0 constraints 6–7, 8). Its presence inside `portappix.zip` is reported as finding PH0-SEC-01 — handling it is a Phase 1 decision. |
| `dist/` (6 files, ~5.1 MB) | Recipe build outputs (`everything/fastfetch/tcpview` packages + `.build.json`). Deleting generated artifacts is prohibited (Step 7). |
| `portappix.zip` (10.8 MB) | Local full-repo snapshot; flagged as a security finding, but deletion/rotation is out of Phase 0 scope. |
| `bin/`, `src/Win32/**`, `src/*.dcu`, `src/Launcher.exe`, `src/Portappix.res`, `tests/Win32/**`, `tests/fakeapps/out*/` | Existing build outputs. Phase 0 builds were redirected to a temp dir specifically so these would not be overwritten; the first (redirected) attempt was captured in BUILD_TEST_BASELINE.md. |
| `scripts/__pycache__/` | Python bytecode cache. |
| `Portappix.dproj.local`, `Portappix.identcache`, `Portappix.res` (root), `__history/` | IDE leftovers from a root-level project open; harmless, git-ignored, untouched. |
| `catalog.json` / `catalog.json.sig` (root, tracked) | The **production catalog** — not regenerated, not re-signed (Phase 0 constraint 8). |

## 5. Documentation set read (not modified)

`README.md` (451 lines) and `RELEASE_CHECKLIST.md` (86 lines) were read in full.
`AGENTS.md` and `TESTING.md` do **not exist** in the repository (recorded). No documentation
outside `docs/audit/phase-0/` was changed.

## 6. What Phase 0 itself added

Exactly one addition to the repository, all of it new audit documentation:

```
docs/audit/phase-0/BASELINE_REPORT.md
docs/audit/phase-0/ARCHITECTURE_INVENTORY.md
docs/audit/phase-0/SECURITY_INVENTORY.md
docs/audit/phase-0/BUILD_TEST_BASELINE.md
docs/audit/phase-0/PRESERVED_CHANGES.md        (this file)
docs/audit/phase-0/PHASE_0_EXIT_CHECKLIST.md
```

`docs/` did not exist before Phase 0, so nothing was overwritten to create these. The files are
untracked until the maintainer chooses to commit them (no automatic commit per constraints).
Temporary build outputs from the Phase 0 baseline builds live outside the repository in
`%LOCALAPPDATA%\Temp\portappix-phase0-build\` and can be deleted freely.
