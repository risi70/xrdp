"""Ephemeral self-signed certificates for the test suites."""

from __future__ import annotations

import subprocess
from pathlib import Path


def make_cert(directory: Path, name: str, common_name: str,
              san: str | None = None) -> tuple[Path, Path]:
    cert = directory / f"{name}.pem"
    key = directory / f"{name}.key"
    command = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "2", "-keyout", str(key), "-out", str(cert),
        "-subj", f"/CN={common_name}",
    ]
    if san:
        command += ["-addext", f"subjectAltName={san}"]
    subprocess.run(command, check=True, capture_output=True)
    return cert, key
