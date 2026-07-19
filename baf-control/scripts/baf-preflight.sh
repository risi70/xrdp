#!/usr/bin/env bash
set -euo pipefail

git status --short
git branch --show-current
git log --oneline -15
git fetch origin
git rev-parse HEAD
git rev-parse origin/mvp-broker-assertion
git log --oneline origin/mvp-broker-assertion..HEAD
git log --oneline HEAD..origin/mvp-broker-assertion
