"""Independent broker assertion conformance verifier."""

from __future__ import annotations

from typing import Any

import jwt


class ConformanceError(ValueError):
    """The assertion does not conform to the broker assertion profile."""


REQUIRED_CLAIMS = (
    "iss",
    "aud",
    "sub",
    "preferred_username",
    "groups",
    "roles",
    "target",
    "session_id",
    "auth_context",
    "iat",
    "nbf",
    "exp",
    "jti",
)


def verify_assertion(
    token: str,
    public_key: bytes | str,
    *,
    issuer: str,
    audience: str,
    target: str,
    leeway: int = 0,
) -> dict[str, Any]:
    """Verify an RS256 broker assertion and return its claims."""
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            leeway=leeway,
            options={"require": list(REQUIRED_CLAIMS)},
        )
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        raise ConformanceError("JWT validation failed") from exc

    if claims.get("target") != target:
        raise ConformanceError("target does not match")
    if not isinstance(claims.get("jti"), str) or not claims["jti"]:
        raise ConformanceError("jti must be a non-empty string")
    username = claims.get("preferred_username")
    if not isinstance(username, str) or not username:
        raise ConformanceError(
            "preferred_username must be a non-empty string"
        )

    return claims
