"""The vendored handle client must match broker-auth/tools exactly."""

from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]

VENDORED = PLUGIN_ROOT / "BAFRDP" / "core" / "handle_socket.py"
ORIGINAL = REPO_ROOT / "broker-auth" / "tools" / "baf_handle_client.py"
HEADER_LINES = 3


@pytest.mark.skipif(
    not ORIGINAL.exists(),
    reason="original absent (running from an extracted payload); "
           "build-plugin.sh verifies drift against the committed source",
)
def test_vendored_copy_matches_original():
    vendored_lines = VENDORED.read_text(encoding="utf-8").splitlines()
    header = vendored_lines[:HEADER_LINES]
    assert all(line.startswith("#") for line in header), \
        "vendored header must remain comment-only"
    body = "\n".join(vendored_lines[HEADER_LINES:]).strip()
    original = ORIGINAL.read_text(encoding="utf-8").strip()
    assert body == original, (
        "BAFRDP/core/handle_socket.py drifted from "
        "broker-auth/tools/baf_handle_client.py; re-vendor it"
    )
