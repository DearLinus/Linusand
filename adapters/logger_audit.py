"""
ILogger implementation: an append-only, hash-chained local audit log.
New in v2 -- v1 had no equivalent. Each line's hash includes the
previous line's hash, so editing or deleting a past entry breaks the
chain from that point forward and is detectable on next read, even
though the file itself is just plain JSON lines an attacker with disk
access could otherwise edit freely.

Deliberately simple (append a JSON line, no rotation/compaction) --
good enough for a personal desktop app's log volume.
"""
from __future__ import annotations

import hashlib
import json
import os
import time

from core.interfaces import ILogger

GENESIS_HASH = "0" * 64


class SignedAuditLog(ILogger):
    def __init__(self, data_dir: str):
        self.path = os.path.join(data_dir, "audit.log")

    def audit(self, event: str, metadata: dict | None = None) -> None:
        prev_hash = self._last_hash()
        entry = {
            "ts": time.time(),
            "event": event,
            "metadata": metadata or {},
            "prev_hash": prev_hash,
        }
        entry_hash = self._hash_entry(entry)
        entry["hash"] = entry_hash
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    def verify_chain(self) -> bool:
        """Returns True if the whole log is internally consistent.
        Exposed for a future 'Security Log' GUI screen / tests."""
        if not os.path.exists(self.path):
            return True
        prev_hash = GENESIS_HASH
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                claimed_hash = entry.pop("hash", None)
                if entry.get("prev_hash") != prev_hash:
                    return False
                if self._hash_entry(entry) != claimed_hash:
                    return False
                prev_hash = claimed_hash
        return True

    def _last_hash(self) -> str:
        if not os.path.exists(self.path):
            return GENESIS_HASH
        last = GENESIS_HASH
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                last = entry.get("hash", GENESIS_HASH)
        return last

    @staticmethod
    def _hash_entry(entry: dict) -> str:
        payload = json.dumps(entry, sort_keys=True).encode()
        return hashlib.sha256(payload).hexdigest()
