"""
Ported from v1's recovery-history / cooldown logic. Owns ONLY the
friction gating (cooldown math, required ack count, history
signing/verification) -- the actual decrypt-and-unlock call is
delegated back to LockEngine, which owns the lock record.
"""
from __future__ import annotations

import json
import time

from .integrity_engine import IntegrityEngine
from .interfaces import IKeyVault, IStorage, ILogger
from .lock_engine import LockEngine
from .models import RecoveryCooldownStatus

RECOVERY_COOLDOWN_BASE_SECONDS = 5 * 60
RECOVERY_COOLDOWN_CAP_SECONDS = 8 * 60 * 60
RECOVERY_ACK_PHRASE = "I am unlocking early and skipping the rest of this session"


class RecoveryEngine:
    def __init__(
        self,
        lock_engine: LockEngine,
        keyvault: IKeyVault,
        storage: IStorage,
        logger: ILogger,
        integrity: IntegrityEngine | None = None,
    ):
        self.lock_engine = lock_engine
        self.keyvault = keyvault
        self.storage = storage
        self.logger = logger
        self.integrity = integrity or IntegrityEngine()

    # ------------------------------------------------------------------
    def get_history(self) -> tuple[list, bool]:
        """Returns (history, tampered). Tampering must never make the
        next Force Recovery *easier* -- callers treat tampered=True as
        'assume the worst', same as v1."""
        state = self.storage.load_state()
        raw = state.get("recovery_history")
        sig = state.get("recovery_history_hmac")

        if not raw:
            return [], False

        master_key = self.keyvault.get_or_create_master_key()
        if not self.integrity.verify_history(master_key, raw, sig):
            return [], True

        try:
            return json.loads(raw), False
        except (json.JSONDecodeError, TypeError):
            return [], True

    def _save_history(self, history: list) -> None:
        raw = json.dumps(history, sort_keys=True)
        master_key = self.keyvault.get_or_create_master_key()
        sig = self.integrity.sign_history(master_key, raw)
        state = self.storage.load_state()
        state["recovery_history"] = raw
        state["recovery_history_hmac"] = sig
        self.storage.save_state(state)

    def record_use(self) -> None:
        history, tampered = self.get_history()
        if tampered:
            history = []
        history.append({"ts": time.time()})
        self._save_history(history)

    def get_cooldown_status(self) -> RecoveryCooldownStatus:
        history, tampered = self.get_history()

        if tampered:
            return RecoveryCooldownStatus(RECOVERY_COOLDOWN_CAP_SECONDS, 5, [])

        count = len(history)
        if count == 0:
            return RecoveryCooldownStatus(0.0, 1, history)

        last_ts = history[-1]["ts"]
        cooldown = min(
            RECOVERY_COOLDOWN_BASE_SECONDS * (2 ** (count - 1)),
            RECOVERY_COOLDOWN_CAP_SECONDS,
        )
        elapsed = time.time() - last_ts
        remaining = max(0.0, cooldown - elapsed)
        required_ack_count = min(1 + count, 5)
        return RecoveryCooldownStatus(remaining, required_ack_count, history)

    # ------------------------------------------------------------------
    def force_unlock(self, recovery_key_hex: str) -> tuple[str | None, str]:
        """Call only after the GUI has already gated on cooldown +
        acknowledgment phrase -- this method assumes those checks
        already passed, it just does the actual unlock + bookkeeping."""
        try:
            recovery_key = bytes.fromhex(recovery_key_hex)
        except Exception:
            return None, "Invalid recovery key"

        password, status = self.lock_engine.unlock_with_recovery_key(recovery_key)
        if password is None:
            return None, status

        self.record_use()
        self.logger.audit("recovery_used", {})
        return password, "success"
