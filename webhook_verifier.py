#!/usr/bin/env python3
"""
Standalone HMAC-SHA256 Webhook Signature Verification Utility for AegisPay.
"""

from __future__ import annotations

import hashlib
import hmac


def verify_aegis_signature(raw_payload: str, signature_header: str, webhook_secret: str) -> bool:
    """
    Validates `X-Aegis-Signature` header (`t=<unix_ts>,v1=<hex_hmac>`).
    """
    parts = dict(item.split("=", 1) for item in signature_header.split(",") if "=" in item)
    provided_sig = parts.get("v1", "")
    if not provided_sig:
        return False
    expected_sig = hmac.new(
        webhook_secret.encode("utf-8"),
        raw_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(provided_sig, expected_sig)
