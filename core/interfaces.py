"""
These Protocols are the ONLY thing core/ is allowed to depend on for
I/O, crypto, timing, or OS access. No file in core/ may import
`adapters` directly -- adapters are wired in once, at the composition
root (composition.py), and injected in.

This is what makes the core deployment-independent: today every
concrete implementation is local-only, but a future CloudCrypto /
CloudStorage adapter would implement these exact same interfaces and
nothing in core/ would need to change.
"""
from __future__ import annotations

from typing import Protocol, Callable, TypeVar

T = TypeVar("T")


class ICrypto(Protocol):
    """Symmetric encryption + key wrapping. Knows nothing about files,
    the OS, or where keys are stored -- only how to use key bytes it's
    handed."""

    def generate_key(self) -> bytes: ...

    def encrypt(self, key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        """Returns (nonce, ciphertext)."""
        ...

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes: ...

    def wrap_key(self, wrapping_key: bytes, key_to_wrap: bytes) -> tuple[bytes, bytes]:
        """Returns (nonce, wrapped)."""
        ...

    def unwrap_key(self, wrapping_key: bytes, nonce: bytes, wrapped: bytes) -> bytes: ...


class IKeyVault(Protocol):
    """Where the master key and recovery key actually live. This is the
    seam TPM/DPAPI implementations plug into later -- LockEngine never
    knows whether it's talking to keyring, a plain file, or a TPM."""

    def get_or_create_master_key(self) -> bytes: ...

    def get_or_create_recovery_key(self) -> bytes: ...

    def rotate_recovery_key(self) -> bytes: ...

    def is_recovery_key_current(self, candidate: bytes) -> bool: ...

    def security_warnings(self) -> list[str]:
        """Human-readable warnings (e.g. 'running in weaker fallback
        mode') the GUI can surface. Ported from v1's
        get_security_warnings()."""
        ...

    # -- external-deletion tamper evidence --------------------------------
    # A durable marker stored OUTSIDE the app's data folder (in the OS
    # credential store, when available) so that deleting the whole data
    # folder to silently cancel a countdown is still detectable on next
    # launch. Ported from v1's active_lock_token mechanism.
    def mark_lock_active(self, token: str) -> None: ...

    def get_active_lock_marker(self) -> str | None: ...

    def clear_active_lock_marker(self) -> None: ...


class IStorage(Protocol):
    """Durable local state: the lock record and small app state. Knows
    nothing about encryption -- just persists whatever bytes/dicts it's
    given, atomically."""

    def save_lock(self, data: dict) -> None: ...

    def load_lock(self) -> dict | None: ...

    def lock_exists(self) -> bool: ...

    def load_state(self) -> dict: ...

    def save_state(self, state: dict) -> None: ...


class IClock(Protocol):
    def now_wall(self) -> float: ...

    def now_monotonic(self) -> float: ...


class ILogger(Protocol):
    def audit(self, event: str, metadata: dict | None = None) -> None: ...
