#!/usr/bin/env python3

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "broker-auth" / "tools"))


def load_command():
    loader = importlib.machinery.SourceFileLoader(
        "baf_uds_register", str(HERE / "baf-uds-register")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class RegisterCommandTests(unittest.TestCase):
    def setUp(self):
        self.command = load_command()

    def descriptor_with(self, value):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, value)
        os.close(write_fd)
        self.addCleanup(os.close, read_fd)
        return read_fd

    def test_registers_descriptor_assertion_and_prints_cookie(self):
        assertion = b"header.payload.signature"
        fd = self.descriptor_with(assertion)
        output = io.StringIO()
        handle = "a" * 64

        with mock.patch.object(
            self.command.baf_handle_client, "store", return_value=handle
        ) as store, contextlib.redirect_stdout(output):
            result = self.command.main(
                [
                    "--assertion-fd", str(fd), "--target", "desktop-01",
                    "--format", "cookie",
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), f"Cookie: msts={handle}\n")
        store.assert_called_once_with(
            "/run/xrdp/baf-handle.sock", assertion, "desktop-01", 90
        )

    def test_failure_does_not_print_assertion(self):
        assertion = b"credential-grade-assertion"
        fd = self.descriptor_with(assertion)
        error = io.StringIO()

        with mock.patch.object(
            self.command.baf_handle_client,
            "store",
            side_effect=self.command.baf_handle_client.HandleError("unavailable"),
        ), contextlib.redirect_stderr(error):
            result = self.command.main(
                ["--assertion-fd", str(fd), "--target", "desktop-01"]
            )

        self.assertEqual(result, 1)
        self.assertIn("unavailable", error.getvalue())
        self.assertNotIn(assertion.decode(), error.getvalue())

    def test_rejects_oversized_assertion_before_store(self):
        limit = self.command.baf_handle_client.MAX_ASSERTION
        fd = self.descriptor_with(b"x" * (limit + 1))

        with mock.patch.object(
            self.command.baf_handle_client, "store"
        ) as store, contextlib.redirect_stderr(io.StringIO()):
            result = self.command.main(
                ["--assertion-fd", str(fd), "--target", "desktop-01"]
            )

        self.assertEqual(result, 1)
        store.assert_not_called()


if __name__ == "__main__":
    unittest.main()
