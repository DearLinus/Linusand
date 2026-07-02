"""
Plain data structures shared between the core engines and the adapters.
No I/O, no crypto, no OS calls here -- just shapes.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LockRecord:
    """Everything needed to describe one active (or consumed) lock.

    This mirrors the fields that used to live directly in lock.json in
    v1, but now it's a typed object the core passes to IStorage instead
    of the core reading/writing JSON itself.
    """
    duration_seconds: int
    created_wall: float
    created_mono: float
    checkpoint_wall: float
    checkpoint_mono: float
    trusted_elapsed: float
    lock_token: str
    nonce: str
    ciphertext: str
    master_nonce: str
    master_wrapped: str
    recovery_nonce: str
    recovery_wrapped: str
    state_hmac: str = ""
    consumed: bool = False

    # Fields covered by the integrity signature. Kept here, right next
    # to the model, so IntegrityEngine and this file can never silently
    # drift apart the way _SIGNED_FIELDS could in v1 if someone forgot
    # to update it in a second place.
    SIGNED_FIELDS = (
        "duration_seconds",
        "created_wall",
        "created_mono",
        "checkpoint_wall",
        "checkpoint_mono",
        "trusted_elapsed",
    )

    def signed_payload(self) -> dict:
        return {k: getattr(self, k) for k in self.SIGNED_FIELDS}

    def to_dict(self) -> dict:
        return {
            "duration_seconds": self.duration_seconds,
            "created_wall": self.created_wall,
            "created_mono": self.created_mono,
            "checkpoint_wall": self.checkpoint_wall,
            "checkpoint_mono": self.checkpoint_mono,
            "trusted_elapsed": self.trusted_elapsed,
            "lock_token": self.lock_token,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "master_nonce": self.master_nonce,
            "master_wrapped": self.master_wrapped,
            "recovery_nonce": self.recovery_nonce,
            "recovery_wrapped": self.recovery_wrapped,
            "state_hmac": self.state_hmac,
            "consumed": self.consumed,
        }

    @staticmethod
    def from_dict(d: dict) -> "LockRecord":
        return LockRecord(
            duration_seconds=d.get("duration_seconds"),
            created_wall=d.get("created_wall"),
            created_mono=d.get("created_mono"),
            checkpoint_wall=d.get("checkpoint_wall", d.get("created_wall")),
            checkpoint_mono=d.get("checkpoint_mono", d.get("created_mono")),
            trusted_elapsed=d.get("trusted_elapsed", 0.0),
            lock_token=d.get("lock_token", ""),
            nonce=d.get("nonce", ""),
            ciphertext=d.get("ciphertext", ""),
            master_nonce=d.get("master_nonce", ""),
            master_wrapped=d.get("master_wrapped", ""),
            recovery_nonce=d.get("recovery_nonce", ""),
            recovery_wrapped=d.get("recovery_wrapped", ""),
            state_hmac=d.get("state_hmac", ""),
            consumed=d.get("consumed", False),
        )


@dataclass
class RemainingTimeResult:
    remaining_seconds: float
    tampered: bool


@dataclass
class RecoveryCooldownStatus:
    seconds_remaining: float
    required_ack_count: int
    history: list = field(default_factory=list)
