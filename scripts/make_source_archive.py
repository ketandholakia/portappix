#!/usr/bin/env python3
"""Produce a clean, reviewable source archive from git.

The second-pass source audit reviewed a manually produced src.zip that
contained compiled executables, DCUs and PortappixTestKey.inc alongside the
sources. Review archives must be source-only: binaries hide review coverage
and build/test material does not belong in a hand-off. This script produces
a reproducible archive directly from git HEAD (never the working tree, so
untracked build debris cannot leak in), optionally restricts it to specific
paths, and runs scripts/package_guard.py over the result.

Usage:
  python scripts/make_source_archive.py --out src-review.zip
  python scripts/make_source_archive.py --out src-review.zip --paths src tests docs scripts
Exit code 0 = archive written and guard-clean; 1 = refused.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"REFUSED: {message}", file=sys.stderr)
    sys.exit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True,
                        help="Output zip path (must be outside the repo)")
    parser.add_argument("--paths", nargs="*", default=["src", "tests", "docs", "scripts"],
                        help="Repo-relative paths to include (default: src tests docs scripts)")
    args = parser.parse_args(argv)

    out = Path(args.out).resolve()
    repo = REPO.resolve()
    if out.is_relative_to(repo):
        fail("the output path is inside the repository; archives must be "
             "written outside so they can never be committed")
    if out.exists():
        fail(f"the output path already exists: {out}")
    for included in args.paths:
        if included.startswith("/") or included.startswith("\\") or ".." in Path(included).parts:
            fail(f"invalid include path: {included}")

    # Fail closed on a dirty tree: an archive labeled with HEAD's commit must
    # really contain HEAD's content (staged-but-uncommitted edits would not).
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo,
                            capture_output=True, text=True, timeout=60)
    if status.returncode != 0:
        fail("git status failed; refusing to archive an unverifiable tree")
    if status.stdout.strip():
        fail("the working tree is dirty; commit or stash first so the "
             "archive provably matches a commit")

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                          capture_output=True, text=True, timeout=60)
    if head.returncode != 0:
        fail("unable to resolve HEAD")
    commit = head.stdout.strip()

    git_args = ["git", "archive", "--format=zip", "-o", str(out), commit, "--"] + list(args.paths)
    run = subprocess.run(git_args, cwd=repo, capture_output=True, text=True, timeout=300)
    if run.returncode != 0:
        fail(f"git archive failed: {run.stderr.strip()}")

    guard = subprocess.run([sys.executable, str(REPO / "scripts" / "package_guard.py"),
                            str(out)], cwd=repo, capture_output=True, text=True, timeout=300)
    if guard.returncode != 0:
        out.unlink(missing_ok=True)
        print(guard.stdout, file=sys.stderr)
        fail("package_guard rejected the archive; it was deleted")

    print(f"Archive: {out}")
    print(f"Commit:  {commit}")
    print(f"Paths:   {', '.join(args.paths)}")
    print("package_guard: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
