"""Verifying Cleat's webhook signature with the standard library only.

Cleat sends::

    cleat-signature: t=<unix seconds>,v1=<hex>

``v1`` is HMAC-SHA256, keyed with the endpoint's signing secret (it starts with
``whsec_``), over the ASCII string ``"<t>" + "." + "<raw request body>"``,
hex-encoded lowercase.

Two rules that matter more than the code itself:

1. Verify over the RAW BYTES of the request, before parsing JSON.
2. Compare with :func:`hmac.compare_digest`, never ``==``.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from dataclasses import dataclass

# Cleat's own documented example uses a 300 second tolerance.
DEFAULT_TOLERANCE_SECONDS = 300

_TIMESTAMP_RE = re.compile(r"\A[0-9]{1,15}\Z")
_SIGNATURE_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")  # SHA-256 is 32 bytes


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: str | None = None
    timestamp: int | None = None


@dataclass(frozen=True)
class _ParsedHeader:
    timestamp_raw: str
    timestamp: int
    signature: str


def _parse_signature_header(header: str | None) -> _ParsedHeader | None:
    """Parse ``t=...,v1=...``.

    Returns ``None`` for anything not fully understood, which the caller must
    treat as unsigned. Unknown fields are skipped rather than rejected, so an
    added ``v2=`` would not break this.
    """
    if not header:
        return None

    timestamp: str | None = None
    signature: str | None = None

    for part in header.split(","):
        key, sep, value = part.partition("=")
        if not sep:
            return None  # not a k=v pair: malformed
        key = key.strip()
        value = value.strip()
        if key == "t":
            if timestamp is not None:
                return None  # repeated field: malformed
            timestamp = value
        elif key == "v1":
            if signature is not None:
                return None
            signature = value

    if timestamp is None or signature is None:
        return None
    if not _TIMESTAMP_RE.match(timestamp) or not _SIGNATURE_RE.match(signature):
        return None

    # Keep the timestamp as the exact string that was sent: that string, not a
    # reformatted number, is what was signed.
    return _ParsedHeader(timestamp_raw=timestamp, timestamp=int(timestamp), signature=signature.lower())


def verify_cleat_signature(
    *,
    payload: bytes,
    header: str | None,
    secret: str | None,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now_seconds: int | None = None,
) -> VerificationResult:
    """Check a delivery's signature. ``payload`` must be the raw request body."""
    if not secret:
        return VerificationResult(ok=False, reason="missing_secret")

    parsed = _parse_signature_header(header)
    if parsed is None:
        return VerificationResult(ok=False, reason="malformed_header")

    # Replay guard. An attacker who captures one delivery can otherwise resend
    # it forever; the timestamp is inside the signed string, so it cannot be
    # edited, only replayed inside this window.
    now = int(time.time()) if now_seconds is None else now_seconds
    age = now - parsed.timestamp
    if age > tolerance_seconds:
        return VerificationResult(ok=False, reason="timestamp_too_old")
    if age < -tolerance_seconds:
        return VerificationResult(ok=False, reason="timestamp_in_future")

    signed_bytes = parsed.timestamp_raw.encode("ascii") + b"." + payload
    expected = hmac.new(secret.encode("utf-8"), signed_bytes, hashlib.sha256).digest()
    provided = bytes.fromhex(parsed.signature)

    if not hmac.compare_digest(expected, provided):
        return VerificationResult(ok=False, reason="signature_mismatch")

    return VerificationResult(ok=True, timestamp=parsed.timestamp)
