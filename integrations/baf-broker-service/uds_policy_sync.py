#!/usr/bin/env python3
"""Synchronize the issuance-service policy from OpenUDS assignments.

Reads the assigned user services from the OpenUDS REST API (who owns
which machine) and rewrites the issuance service's ``policy.json``
accordingly, atomically. The running service picks the new file up
without a restart (mtime-based hot reload). Run periodically (systemd
timer/cron) or after assignment changes.

Design decisions:
- OpenUDS remains the source of truth for user↔machine assignment; the
  issuance service still enforces the result strictly per request.
- Entries with names that would fail the service's validation are
  skipped with a warning rather than aborting the sync (one odd machine
  name must not take down issuance for the fleet).
- An empty sync result refuses to overwrite a non-empty policy unless
  ``--allow-empty`` is given, so an API outage cannot silently wipe all
  grants.
- The REST paths are configurable to absorb OpenUDS version drift.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

log = logging.getLogger("uds-policy-sync")

_NAME_RE = re.compile(r"^[\x21-\x7e]{1,255}$")
MAX_RESPONSE = 4 * 1024 * 1024


class SyncError(RuntimeError):
    pass


class SyncConfig:
    _KEYS = {
        "uds_url", "auth_label", "username", "password_file", "ca_file",
        "policy_file", "audience_template", "roles", "groups", "timeout",
        "auth_path", "pools_path", "assigned_path_template",
        "allow_insecure_http",
    }
    _REQUIRED = {
        "uds_url", "auth_label", "username", "password_file",
        "policy_file",
    }

    def __init__(self, path: Path) -> None:
        values: dict[str, str] = {}
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if ":" not in line:
                raise SyncError(f"unsupported config line: {raw_line!r}")
            key, value = (part.strip() for part in line.split(":", 1))
            if key not in self._KEYS:
                raise SyncError(f"unknown config key: {key!r}")
            values[key] = value.strip('"').strip("'")
        missing = self._REQUIRED - set(values)
        if missing:
            raise SyncError(f"missing config keys: {sorted(missing)}")

        self.uds_url = values["uds_url"].rstrip("/")
        insecure = values.get("allow_insecure_http", "no") == "yes"
        if not self.uds_url.startswith("https://") and not insecure:
            raise SyncError("uds_url must use https")
        self.auth_label = values["auth_label"]
        self.username = values["username"]
        self.password = Path(
            values["password_file"]
        ).read_text(encoding="utf-8").strip()
        if not self.password:
            raise SyncError("password_file is empty")
        self.ca_file = values.get("ca_file") or None
        self.policy_file = Path(values["policy_file"])
        self.audience_template = values.get(
            "audience_template", "xrdp://{target}"
        )
        if "{target}" not in self.audience_template:
            raise SyncError("audience_template must contain {target}")
        self.roles = [
            item.strip()
            for item in values.get("roles", "desktop-user").split(",")
            if item.strip()
        ]
        self.groups = [
            item.strip()
            for item in values.get("groups", "").split(",")
            if item.strip()
        ]
        self.timeout = float(values.get("timeout", "10"))
        self.auth_path = values.get("auth_path", "/uds/rest/auth")
        self.pools_path = values.get(
            "pools_path", "/uds/rest/servicespools/overview"
        )
        self.assigned_path_template = values.get(
            "assigned_path_template",
            "/uds/rest/servicespools/{pool_id}/assignedservices/overview",
        )


class UdsClient:
    """Minimal OpenUDS admin REST client (stdlib only)."""

    def __init__(self, config: SyncConfig) -> None:
        self._config = config
        self._token: str | None = None
        if config.uds_url.startswith("https://"):
            self._context = ssl.create_default_context(
                cafile=config.ca_file
            )
        else:
            self._context = None

    def _request(self, path: str, payload: dict | None = None) -> Any:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["X-Auth-Token"] = self._token
        request = urllib.request.Request(
            self._config.uds_url + path,
            data=json.dumps(payload).encode() if payload else None,
            headers=headers,
            method="POST" if payload else "GET",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self._config.timeout,
                context=self._context,
            ) as response:
                body = response.read(MAX_RESPONSE + 1)
        except (urllib.error.URLError, OSError) as exc:
            raise SyncError(f"OpenUDS request {path} failed: {exc}") \
                from exc
        if len(body) > MAX_RESPONSE:
            raise SyncError(f"OpenUDS response for {path} too large")
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SyncError(f"OpenUDS response for {path} not JSON") \
                from exc

    def login(self) -> None:
        reply = self._request(self._config.auth_path, {
            "auth": self._config.auth_label,
            "username": self._config.username,
            "password": self._config.password,
        })
        token = reply.get("token") if isinstance(reply, dict) else None
        if not token:
            raise SyncError("OpenUDS login did not return a token")
        self._token = token

    def pools(self) -> list[dict]:
        reply = self._request(self._config.pools_path)
        if not isinstance(reply, list):
            raise SyncError("pools listing is not a list")
        return reply

    def assigned(self, pool_id: str) -> list[dict]:
        path = self._config.assigned_path_template.format(pool_id=pool_id)
        reply = self._request(path)
        if not isinstance(reply, list):
            raise SyncError(f"assigned listing for {pool_id} not a list")
        return reply


def _owner_login(entry: dict) -> str | None:
    owner = entry.get("owner") or entry.get("user") or ""
    if not isinstance(owner, str) or not owner:
        return None
    return owner.split("@", 1)[0]


def _machine_name(entry: dict) -> str | None:
    for key in ("friendly_name", "name"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def build_policy(config: SyncConfig, client: UdsClient) -> dict[str, Any]:
    users: dict[str, set[str]] = {}
    for pool in client.pools():
        pool_id = pool.get("id")
        if not isinstance(pool_id, str) or not pool_id:
            log.warning("skipping pool without id: %r", pool.get("name"))
            continue
        for entry in client.assigned(pool_id):
            login = _owner_login(entry)
            machine = _machine_name(entry)
            if not login or not machine:
                log.warning(
                    "skipping incomplete assignment in pool %s", pool_id
                )
                continue
            if not _NAME_RE.match(login) or not _NAME_RE.match(machine):
                log.warning(
                    "skipping assignment with invalid name: %r -> %r",
                    login, machine,
                )
                continue
            users.setdefault(login, set()).add(machine)

    targets = sorted({t for grants in users.values() for t in grants})
    return {
        "users": {
            login: {
                "targets": sorted(grants),
                "roles": config.roles,
                "groups": config.groups,
            }
            for login, grants in sorted(users.items())
        },
        "targets": {
            target: {
                "audience": config.audience_template.format(target=target)
            }
            for target in targets
        },
    }


def write_policy(config: SyncConfig, policy: dict[str, Any]) -> None:
    directory = config.policy_file.parent
    descriptor, temp_name = tempfile.mkstemp(
        dir=directory, prefix=".policy-sync-"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(policy, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temp_name, 0o640)
        os.replace(temp_name, config.policy_file)
    except BaseException:
        os.unlink(temp_name)
        raise


def _existing_policy_nonempty(path: Path) -> bool:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        return bool(document.get("users"))
    except (OSError, json.JSONDecodeError, AttributeError):
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the resulting policy instead of writing it",
    )
    parser.add_argument(
        "--allow-empty", action="store_true",
        help="permit overwriting a non-empty policy with zero users",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=args.log_level, format="%(name)s %(levelname)s %(message)s"
    )

    try:
        config = SyncConfig(args.config)
        client = UdsClient(config)
        client.login()
        policy = build_policy(config, client)
    except (SyncError, OSError) as exc:
        log.error("%s", exc)
        return 1

    if not policy["users"] and not args.allow_empty \
            and _existing_policy_nonempty(config.policy_file):
        log.error(
            "sync produced zero users but %s is non-empty; refusing "
            "to overwrite (use --allow-empty to force)",
            config.policy_file,
        )
        return 1

    if args.dry_run:
        json.dump(policy, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    write_policy(config, policy)
    log.info(
        "wrote %s: %d users, %d targets",
        config.policy_file, len(policy["users"]), len(policy["targets"]),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
