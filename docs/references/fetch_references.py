#!/usr/bin/env python3
"""Fetch external reference documents into ignored originals directories.

This script intentionally requires an explicit license acknowledgement. It does
not make third-party documents redistributable; it only helps an operator create
local offline copies when permitted by the relevant vendor terms.
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
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
    args = parser.parse_args(argv)

    if not args.accept_third_party_licenses:
        parser.error("refusing to download until --accept-third-party-licenses is supplied")

    refs = parse_manifest()
    suppliers = set(args.supplier or [])
    failures: list[str] = []
    for ref in refs:
        if suppliers and ref.get("supplier") not in suppliers:
            continue
        if ref.get("fetch", "false").lower() != "true" and not args.include_fetch_false:
            print(f"skip {ref['id']}: fetch=false")
            continue
        supplier = ref.get("supplier", "misc")
        outdir = ROOT / supplier / "originals"
        outdir.mkdir(parents=True, exist_ok=True)
        out = outdir / safe_name(ref)
        print(f"fetch {ref['id']} -> {out}")
        req = urllib.request.Request(ref["url"], headers={"User-Agent": "xrdp-baf-reference-fetch/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                out.write_bytes(response.read())
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

    if failures:
        print(f"completed with {len(failures)} failed reference fetch(es)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
