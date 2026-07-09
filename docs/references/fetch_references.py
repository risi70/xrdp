#!/usr/bin/env python3
"""Fetch external reference documents into ignored originals directories.

This script intentionally requires an explicit license acknowledgement. It does
not make third-party documents redistributable; it only helps an operator create
local offline copies when permitted by the relevant vendor terms.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAIN_REPO_ROOT = ROOT.parents[1]
MANIFEST = ROOT / "manifest.yaml"


def parse_manifest() -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if line.startswith("  - id:"):
            if current:
                refs.append(current)
            current = {"id": line.split(":", 1)[1].strip().strip('"')}
        elif current is not None and re.match(r"    [a-zA-Z_]+:", line):
            key, value = line.strip().split(":", 1)
            current[key] = value.strip().strip('"')
    if current:
        refs.append(current)
    return refs


def git_root(path: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        return None
    return Path(result.stdout.strip()).resolve()


def run_git(path: Path, args: list[str]) -> None:
    subprocess.run(["git", "-C", str(path), *args], check=True)


def prepare_commit_target(output_root: Path, allow_main_repo_commit: bool) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    repo_root = git_root(output_root)
    if repo_root is None:
        raise SystemExit(f"{output_root} is not inside a git repository")
    if repo_root == MAIN_REPO_ROOT.resolve() and not allow_main_repo_commit:
        raise SystemExit(
            "refusing to commit downloaded third-party documents to the main xrdp repo; "
            "use a separate private checkout such as docs/references/private or pass "
            "--allow-main-repo-commit only after confirming redistribution is permitted"
        )
    return repo_root


def safe_name(ref: dict[str, str]) -> str:
    suffix = ".html"
    url = ref.get("url", "")
    if url.lower().endswith(".pdf"):
        suffix = ".pdf"
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", ref["id"]) + suffix


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--accept-third-party-licenses", action="store_true")
    parser.add_argument("--supplier", action="append")
    parser.add_argument("--include-fetch-false", action="store_true")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=ROOT,
        help="directory receiving supplier/originals files; use a separate private git checkout to commit downloads",
    )
    parser.add_argument("--commit", action="store_true", help="git add and commit fetched files in the output git repository")
    parser.add_argument("--push", action="store_true", help="push the output git repository after committing")
    parser.add_argument("--commit-message", default="docs: update offline external references")
    parser.add_argument(
        "--allow-main-repo-commit",
        action="store_true",
        help="allow committing downloads to this repository; avoid unless redistribution is explicitly permitted",
    )
    args = parser.parse_args(argv)

    if not args.accept_third_party_licenses:
        parser.error("refusing to download until --accept-third-party-licenses is supplied")

    output_root = args.output_root.resolve()
    commit_repo = None
    if args.push and not args.commit:
        parser.error("--push requires --commit")
    if args.commit:
        commit_repo = prepare_commit_target(output_root, args.allow_main_repo_commit)

    refs = parse_manifest()
    suppliers = set(args.supplier or [])
    fetched: list[Path] = []
    failures: list[str] = []
    for ref in refs:
        if suppliers and ref.get("supplier") not in suppliers:
            continue
        if ref.get("fetch", "false").lower() != "true" and not args.include_fetch_false:
            print(f"skip {ref['id']}: fetch=false")
            continue
        supplier = ref.get("supplier", "misc")
        outdir = output_root / supplier / "originals"
        outdir.mkdir(parents=True, exist_ok=True)
        out = outdir / safe_name(ref)
        print(f"fetch {ref['id']} -> {out}")
        req = urllib.request.Request(ref["url"], headers={"User-Agent": "xrdp-baf-reference-fetch/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                out.write_bytes(response.read())
            fetched.append(out)
        except urllib.error.HTTPError as ex:
            message = f"{ref['id']}: HTTP {ex.code} {ex.reason} ({ref['url']})"
            print(f"warn: {message}", file=sys.stderr)
            failures.append(message)
        except urllib.error.URLError as ex:
            message = f"{ref['id']}: URL error {ex.reason} ({ref['url']})"
            print(f"warn: {message}", file=sys.stderr)
            failures.append(message)
        except TimeoutError:
            message = f"{ref['id']}: timeout ({ref['url']})"
            print(f"warn: {message}", file=sys.stderr)
            failures.append(message)

    if commit_repo is not None:
        if not fetched:
            print("no fetched files to commit", file=sys.stderr)
        else:
            run_git(commit_repo, ["add", *[str(path) for path in fetched]])
            diff = subprocess.run(["git", "-C", str(commit_repo), "diff", "--cached", "--quiet"])
            if diff.returncode == 0:
                print("no downloaded reference changes to commit")
            else:
                run_git(commit_repo, ["commit", "-m", args.commit_message])
                if args.push:
                    run_git(commit_repo, ["push"])

    if failures:
        print(f"completed with {len(failures)} failed reference fetch(es)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
