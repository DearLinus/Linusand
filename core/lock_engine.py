"""
Ported from v1's TimeLockCore, but stripped down to ONLY lock
lifecycle logic: create, check remaining time, unlock. Recovery lives
in recovery_engine.py, integrity in integrity_engine.py, key/crypto/
storage are all injected interfaces.

This class has no idea whether it's running against real files and a
real TPM, or fakes in a unit test -- that's the point.
"""
from __future__ import annotations

import secrets

from .integrity_engine import IntegrityEngine, CLOCK_TAMPER_THRESHOLD_SECONDS
from .interfaces import ICrypto, IKeyVault, IStorage, IClock, ILogger
from .models import LockRecord, RemainingTimeResult

TAMPER_LOCKOUT_SECONDS = 10**9


class LockAlreadyActiveError(RuntimeError):
    pass


class LockEngine:
    def __init__(
        self,
        crypto: ICrypto,
        keyvault: IKeyVault,
        storage: IStorage,
        clock: IClock,
        logger: ILogger,
        integrity: IntegrityEngine | None = None,
    ):
        self.crypto = crypto
        self.keyvault = keyvault
        self.storage = storage
        self.clock = clock
        self.logger = logger
        self.integrity = integrity or IntegrityEngine()

    # ------------------------------------------------------------------
    def has_active_lock(self) -> bool:
        if not self.storage.lock_exists():
            return False
        data = self.storage.load_lock()
        if data is None:
            return True  # corrupt/unreadable -> treat as present, tamper path handles it
        return not data.get("consumed", False)

    def create_new_lock(self, duration_seconds: int, password: str | None = None) -> tuple[str, float]:
        if self.has_active_lock():
            remaining = self.get_remaining_time().remaining_seconds
            if remaining > 0:
                raise LockAlreadyActiveError(
                    "A lock is already active; refusing to overwrite it."
                )

        master_key = self.keyvault.get_or_create_master_key()
        recovery_key = self.keyvault.get_or_create_recovery_key()

        if password is None:
            password = self._generate_strong_password()

        created_wall = self.clock.now_wall()
        created_mono = self.clock.now_monotonic()
        unlock_time = created_wall + duration_seconds

        dek = self.crypto.generate_key()
        nonce, ciphertext = self.crypto.encrypt(dek, password.encode("utf-8"))
        m_nonce, m_wrapped = self.crypto.wrap_key(master_key, dek)
        r_nonce, r_wrapped = self.crypto.wrap_key(recovery_key, dek)

        record = LockRecord(
            duration_seconds=duration_seconds,
            created_wall=created_wall,
            created_mono=created_mono,
            checkpoint_wall=created_wall,
            checkpoint_mono=created_mono,
            trusted_elapsed=0.0,
            lock_token=secrets.token_hex(16),
            nonce=nonce.hex(),
            ciphertext=ciphertext.hex(),
            master_nonce=m_nonce.hex(),
            master_wrapped=m_wrapped.hex(),
            recovery_nonce=r_nonce.hex(),
            recovery_wrapped=r_wrapped.hex(),
        )
        record.state_hmac = self.integrity.sign(master_key, record)

        self.storage.save_lock(record.to_dict())
        self.keyvault.mark_lock_active(record.lock_token)
        self.logger.audit("lock_created", {"duration_seconds": duration_seconds})

        return password, unlock_time

    def check_tamper_evidence(self) -> bool:
        """True if the keyvault remembers an active lock but the lock
        file itself is gone -- i.e. someone deleted the data folder
        directly, outside the app, to silently cancel a countdown."""
        marker = self.keyvault.get_active_lock_marker()
        return bool(marker) and not self.storage.lock_exists()

    def clear_tamper_evidence(self) -> None:
        self.keyvault.clear_active_lock_marker()

    def generate_strong_password(self, length: int = 18) -> str:
        return self._generate_strong_password(length)

    def get_remaining_time(self) -> RemainingTimeResult:
        if not self.has_active_lock():
            return RemainingTimeResult(0.0, False)

        raw = self.storage.load_lock()
        if raw is None:
            return RemainingTimeResult(TAMPER_LOCKOUT_SECONDS, True)

        record = LockRecord.from_dict(raw)
        if record.duration_seconds is None or record.created_wall is None:
            return RemainingTimeResult(0.0, False)

        master_key = self.keyvault.get_or_create_master_key()

        if record.state_hmac:
            if not self.integrity.verify(master_key, record):
                self.logger.audit("tamper_detected", {"reason": "state_hmac_mismatch"})
                return RemainingTimeResult(TAMPER_LOCKOUT_SECONDS, True)
        else:
            self.logger.audit("tamper_detected", {"reason": "missing_state_hmac"})
            return RemainingTimeResult(TAMPER_LOCKOUT_SECONDS, True)

        now_wall = self.clock.now_wall()
        now_mono = self.clock.now_monotonic()

        tampered = False
        if record.checkpoint_mono is not None and now_mono >= record.checkpoint_mono:
            delta_wall = now_wall - record.checkpoint_wall
            delta_mono = now_mono - record.checkpoint_mono
            if self.integrity.clock_tamper_detected(delta_wall, delta_mono):
                tampered = True
                delta = delta_mono
            else:
                delta = delta_wall
        else:
            tampered = True
            delta = max(0.0, now_wall - record.checkpoint_wall)

        if tampered:
            self.logger.audit("tamper_detected", {"reason": "clock_skew"})

        total_elapsed = min(record.trusted_elapsed + max(0.0, delta), record.duration_seconds)
        remaining = max(0.0, record.duration_seconds - total_elapsed)

        record.checkpoint_wall = now_wall
        record.checkpoint_mono = now_mono
        record.trusted_elapsed = total_elapsed
        record.state_hmac = self.integrity.sign(master_key, record)
        self.storage.save_lock(record.to_dict())

        return RemainingTimeResult(remaining, tampered)

    def unlock(self) -> tuple[str | None, str]:
        """Normal (non-recovery) unlock path -- only succeeds once the
        timer has actually reached zero."""
        if not self.has_active_lock():
            return None, "No active lock"

        raw = self.storage.load_lock()
        if raw is None:
            return None, "Lock file is corrupted or unreadable - use Force Recovery"
        record = LockRecord.from_dict(raw)

        result = self.get_remaining_time()
        if result.remaining_seconds > 0:
            msg = "Lock is still active"
            if result.tampered:
                msg += " (clock/file tampering detected - use Force Recovery instead)"
            return None, msg

        master_key = self.keyvault.get_or_create_master_key()
        try:
            dek = self.crypto.unwrap_key(
                master_key, bytes.fromhex(record.master_nonce), bytes.fromhex(record.master_wrapped)
            )
            password = self.crypto.decrypt(
                dek, bytes.fromhex(record.nonce), bytes.fromhex(record.ciphertext)
            ).decode("utf-8")
        except Exception:
            return None, "Key decryption failed"

        self._mark_consumed()
        self.logger.audit("lock_unlocked", {"method": "normal"})
        return password, "success"

    def unlock_with_recovery_key(self, recovery_key: bytes) -> tuple[str | None, str]:
        """Used by RecoveryEngine once cooldown/ack checks have passed.
        LockEngine still owns the actual decrypt, since it owns the
        lock record -- RecoveryEngine owns the friction/gating."""
        if not self.has_active_lock():
            return None, "No active lock"

        raw = self.storage.load_lock()
        if raw is None:
            return None, "Lock file is corrupted or unreadable"
        record = LockRecord.from_dict(raw)

        if not self.keyvault.is_recovery_key_current(recovery_key):
            return None, "This recovery key has already been used and rotated"

        try:
            dek = self.crypto.unwrap_key(
                recovery_key, bytes.fromhex(record.recovery_nonce), bytes.fromhex(record.recovery_wrapped)
            )
            password = self.crypto.decrypt(
                dek, bytes.fromhex(record.nonce), bytes.fromhex(record.ciphertext)
            ).decode("utf-8")
        except Exception:
            return None, "Invalid recovery key"

        self._mark_consumed()
        self.keyvault.rotate_recovery_key()
        self.logger.audit("lock_unlocked", {"method": "force_recovery"})
        return password, "success"

    # ------------------------------------------------------------------
    def _mark_consumed(self) -> None:
        self.storage.save_lock({"consumed": True})
        self.keyvault.clear_active_lock_marker()

    def _generate_strong_password(self, length: int = 18) -> str:
        alphabet = (
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            "!@#$%^&*()_+-=[]{}|;:,.<>?"
        )
        return "".join(secrets.choice(alphabet) for _ in range(length))
