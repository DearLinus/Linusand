"""
Ported directly from v1's core.py `_state_hmac`. This was the single
most important security fix in v1 (signing ALL mutable timing fields,
not just the creation-time ones) -- the logic doesn't change here,
it just moves into its own class so LockEngine isn't also responsible
for knowing what HMAC canonicalization looks like.
"""
from __future__ import annotations

import hashlib
import hmac
import json

from .models import LockRecord

CLOCK_TAMPER_THRESHOLD_SECONDS = 15


class IntegrityEngine:
    def sign(self, master_key: bytes, record: LockRecord) -> str:
        payload = json.dumps(
            record.signed_payload(), sort_keys=True, separators=(",", ":")
        ).encode()
        return hmac.new(master_key, payload, hashlib.sha256).hexdigest()

    def verify(self, master_key: bytes, record: LockRecord) -> bool:
        if not record.state_hmac:
            return False
        expected = self.sign(master_key, record)
        return hmac.compare_digest(record.state_hmac, expected)

    def clock_tamper_detected(
        self, delta_wall: float, delta_mono: float
    ) -> bool:
        return abs(delta_wall - delta_mono) > CLOCK_TAMPER_THRESHOLD_SECONDS

    def sign_history(self, master_key: bytes, raw_json_str: str) -> str:
        return hmac.new(master_key, raw_json_str.encode(), hashlib.sha256).hexdigest()

    def verify_history(self, master_key: bytes, raw_json_str: str, sig: str | None) -> bool:
        if sig is None:
            return False
        expected = self.sign_history(master_key, raw_json_str)
        return hmac.compare_digest(sig, expected)
