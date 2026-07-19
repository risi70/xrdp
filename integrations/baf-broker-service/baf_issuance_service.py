#!/usr/bin/env python3
"""BAF assertion issuance service — the broker-to-XRDP connector.

Serves the mutual-TLS HTTPS API consumed by the OpenUDS transport
plugin (``integrations/openuds-baf``) and any other authorized broker
front end:

    POST /v1/assertions   issue a signed BAF assertion (policy-gated)
    GET  /healthz         liveness (mTLS still required)

Trust model: the TLS client certificate authenticates the calling
front end (e.g. the OpenUDS server), which has already authenticated
the portal user against Keycloak. This service enforces the broker-side
policy — per-user target allowlists, per-target audiences, bounded
lifetimes — signs with the BAF issuer key, and returns the assertion.
The signing key never leaves this host; assertions are never logged.

Every anomaly fails closed: unknown client CN, unknown user or target,
malformed or oversized input, and rate-limit overruns all deny without
detail to the caller.
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REFERENCE_ISSUER = _HERE.parents[1] / "broker-auth" / "reference-issuer"
if str(_REFERENCE_ISSUER) not in sys.path:
    sys.path.insert(0, str(_REFERENCE_ISSUER))

from broker_issuer import build_claims, sign_claims  # noqa: E402

log = logging.getLogger("baf-issuanced")

MAX_BODY = 8192
_FIELD_RE = re.compile(r"^[\x21-\x7e]{1,255}$")


class PolicyDenied(Exception):
    """Request refused by broker policy; reason stays server-side."""


class ConfigError(Exception):
    pass


def _require_field(document: dict, name: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not _FIELD_RE.match(value):
        raise PolicyDenied(f"field {name} missing or malformed")
    return value


def _string_list(document: dict, name: str, default: list[str]) -> list[str]:
    value = document.get(name, default)
    if (not isinstance(value, list) or not value
            or not all(isinstance(item, str) and _FIELD_RE.match(item)
                       for item in value)):
        raise PolicyDenied(f"field {name} malformed")
    return value


class Policy:
    """Users, their target allowlists, and per-target audiences."""

    def __init__(self, document: dict[str, Any]) -> None:
        users = document.get("users")
        targets = document.get("targets")
        if not isinstance(users, dict) or not isinstance(targets, dict):
            raise ConfigError("policy needs 'users' and 'targets' objects")
        self.targets: dict[str, str] = {}
        for name, entry in targets.items():
            if (not _FIELD_RE.match(name) or not isinstance(entry, dict)
                    or not isinstance(entry.get("audience"), str)):
                raise ConfigError(f"policy target {name!r} malformed")
            self.targets[name] = entry["audience"]
        self.users: dict[str, dict[str, list[str]]] = {}
        for name, entry in users.items():
            if not _FIELD_RE.match(name) or not isinstance(entry, dict):
                raise ConfigError(f"policy user {name!r} malformed")
            allowed = entry.get("targets")
            if (not isinstance(allowed, list) or not allowed
                    or not all(target in self.targets
                               for target in allowed)):
                raise ConfigError(
                    f"policy user {name!r} has no valid target list"
                )
            roles = entry.get("roles", ["desktop-user"])
            groups = entry.get("groups", [])
            if not all(isinstance(item, str) for item in roles + groups):
                raise ConfigError(f"policy user {name!r} malformed")
            self.users[name] = {
                "targets": allowed, "roles": roles, "groups": groups,
            }

    @classmethod
    def load(cls, path: Path) -> "Policy":
        try:
            return cls(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot load policy {path}: {exc}") from exc

    def authorize(self, username: str, target: str) -> dict[str, Any]:
        user = self.users.get(username)
        if user is None:
            raise PolicyDenied(f"unknown user {username!r}")
        if target not in user["targets"]:
            raise PolicyDenied(
                f"user {username!r} not allowed target {target!r}"
            )
        return {
            "audience": self.targets[target],
            "roles": user["roles"],
            "groups": user["groups"],
        }


class PolicyStore:
    """Hot-reloading policy holder.

    The policy file is re-read when its mtime/size changes (e.g. after
    ``uds_policy_sync.py`` rewrites it), so grants apply without a
    service restart. A file that fails to parse keeps the last good
    policy in force — denying the whole fleet over a partial write
    would convert a sync bug into an outage. Startup with a bad policy
    still refuses to serve (ConfigError from the initial load).
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._policy = Policy.load(path)
        self._stamp = self._stat()
        self._lock = threading.Lock()

    def _stat(self) -> tuple[int, int]:
        status = self._path.stat()
        return (status.st_mtime_ns, status.st_size)

    def current(self) -> Policy:
        with self._lock:
            try:
                stamp = self._stat()
            except OSError:
                log.error("policy file unreadable; keeping last-good")
                return self._policy
            if stamp != self._stamp:
                try:
                    self._policy = Policy.load(self._path)
                    self._stamp = stamp
                    log.info(
                        "policy reloaded: %d users, %d targets",
                        len(self._policy.users), len(self._policy.targets),
                    )
                except ConfigError as exc:
                    self._stamp = stamp
                    log.error(
                        "policy reload rejected (%s); keeping last-good",
                        exc,
                    )
            return self._policy


class ServiceConfig:
    """Strict key:value configuration for the daemon."""

    _KEYS = {
        "listen_address", "listen_port", "tls_cert", "tls_key",
        "client_ca", "allowed_client_cn", "issuer", "kid",
        "private_key", "policy_file", "lifetime",
        "rate_limit_per_minute",
    }
    _REQUIRED = {
        "tls_cert", "tls_key", "client_ca", "allowed_client_cn",
        "issuer", "kid", "private_key", "policy_file",
    }

    def __init__(self, path: Path) -> None:
        values: dict[str, str] = {}
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if ":" not in line:
                raise ConfigError(f"unsupported config line: {raw_line!r}")
            key, value = (part.strip() for part in line.split(":", 1))
            if key not in self._KEYS:
                raise ConfigError(f"unknown config key: {key!r}")
            values[key] = value.strip('"').strip("'")
        missing = self._REQUIRED - set(values)
        if missing:
            raise ConfigError(f"missing config keys: {sorted(missing)}")

        self.listen_address = values.get("listen_address", "127.0.0.1")
        self.listen_port = int(values.get("listen_port", "8443"))
        self.tls_cert = values["tls_cert"]
        self.tls_key = values["tls_key"]
        self.client_ca = values["client_ca"]
        self.allowed_client_cn = tuple(
            item.strip()
            for item in values["allowed_client_cn"].split(",")
            if item.strip()
        )
        self.issuer = values["issuer"]
        self.kid = values["kid"]
        self.private_key = Path(values["private_key"]).read_bytes()
        self.policy_store = PolicyStore(Path(values["policy_file"]))
        self.lifetime = int(values.get("lifetime", "120"))
        self.rate_limit_per_minute = int(
            values.get("rate_limit_per_minute", "120")
        )
        if not self.issuer.startswith("https://"):
            raise ConfigError("issuer must be an https URL")
        if not 30 <= self.lifetime <= 300:
            raise ConfigError("lifetime must be between 30 and 300 seconds")
        if not self.allowed_client_cn:
            raise ConfigError("allowed_client_cn must not be empty")


class RateLimiter:
    """Small sliding-window limiter per client CN."""

    def __init__(self, per_minute: int) -> None:
        self._per_minute = per_minute
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        horizon = time.monotonic() - 60.0
        with self._lock:
            events = [
                stamp for stamp in self._events.get(key, ())
                if stamp > horizon
            ]
            if len(events) >= self._per_minute:
                self._events[key] = events
                return False
            events.append(time.monotonic())
            self._events[key] = events
            return True


def peer_common_name(tls_socket) -> str | None:
    certificate = tls_socket.getpeercert()
    for rdn in (certificate or {}).get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


class IssuanceHandler(BaseHTTPRequestHandler):
    server_version = "baf-issuanced"
    sys_version = ""
    timeout = 10

    # These are attached to the server object by serve().
    config: ServiceConfig
    limiter: RateLimiter

    def _reply(self, status: int, document: dict[str, Any]) -> None:
        body = json.dumps(document).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _client_cn(self) -> str | None:
        cn = peer_common_name(self.connection)
        if cn is None or cn not in self.server.config.allowed_client_cn:
            return None
        return cn

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self._client_cn() is None:
            self._reply(403, {"error": "denied"})
            return
        if self.path == "/healthz":
            self._reply(200, {"status": "ok"})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        client = self._client_cn()
        if client is None:
            log.warning("denied: unauthorized client certificate")
            self._reply(403, {"error": "denied"})
            return
        if self.path != "/v1/assertions":
            self._reply(404, {"error": "not found"})
            return
        if not self.server.limiter.allow(client):
            log.warning("denied: rate limit for client %r", client)
            self._reply(429, {"error": "rate limited"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        if not 2 <= length <= MAX_BODY:
            self._reply(400, {"error": "bad request"})
            return
        try:
            document = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(document, dict):
                raise ValueError("body must be an object")
        except (UnicodeDecodeError, ValueError):
            self._reply(400, {"error": "bad request"})
            return

        try:
            assertion, jti, username, target = self._issue(document)
        except PolicyDenied as exc:
            log.warning("denied for client %r: %s", client, exc)
            self._reply(403, {"error": "denied"})
            return
        except Exception:
            log.exception("issuance failed (internal)")
            self._reply(500, {"error": "internal"})
            return

        log.info(
            "issued: client=%r user=%r target=%r jti=%s",
            client, username, target, jti,
        )
        self._reply(200, {"assertion": assertion})

    def _issue(self, document: dict) -> tuple[str, str, str, str]:
        config = self.server.config
        username = _require_field(document, "preferred_username")
        target = _require_field(document, "target")
        subject = _require_field(document, "subject")
        session_id = _require_field(document, "broker_session_id")
        auth_method = _string_list(document, "auth_method", ["broker"])
        assurance = document.get("assurance_level", "mfa")
        device_trust = document.get("device_trust", "unknown")
        if not (isinstance(assurance, str) and _FIELD_RE.match(assurance)):
            raise PolicyDenied("assurance_level malformed")
        if not (isinstance(device_trust, str)
                and _FIELD_RE.match(device_trust)):
            raise PolicyDenied("device_trust malformed")

        grant = config.policy_store.current().authorize(username, target)
        jti = str(uuid.uuid4())
        claims = build_claims(
            issuer=config.issuer,
            audience=grant["audience"],
            subject=subject,
            preferred_username=username,
            groups=grant["groups"],
            roles=grant["roles"],
            target=target,
            session_id=session_id,
            auth_context={
                "amr": auth_method,
                "acr": assurance,
                "device_trust": device_trust,
            },
            lifetime=config.lifetime,
            jti=jti,
        )
        assertion = sign_claims(
            claims, config.private_key, key_id=config.kid
        )
        return assertion, jti, username, target

    def log_message(self, format: str, *args) -> None:
        # http.server's default access log goes to stderr with client
        # addresses; route through logging instead, no request bodies.
        log.debug("http: " + format, *args)


def build_server(config: ServiceConfig) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (config.listen_address, config.listen_port), IssuanceHandler
    )
    server.config = config
    server.limiter = RateLimiter(config.rate_limit_per_minute)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config.tls_cert, config.tls_key)
    context.load_verify_locations(config.client_ca)
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--log-level", default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    try:
        config = ServiceConfig(args.config)
    except (ConfigError, OSError, ValueError) as exc:
        log.error("configuration rejected: %s", exc)
        return 1
    server = build_server(config)
    log.info(
        "listening on %s:%d (issuer %s, %d users, %d targets)",
        config.listen_address, config.listen_port, config.issuer,
        len(config.policy_store.current().users),
        len(config.policy_store.current().targets),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
