"""
IKeyVault implementation using the OS credential store via `keyring`,
falling back to a plain file with a loud warning if keyring isn't
available -- this is exactly v1's load_master_key/get_recovery_key
logic, just moved behind the IKeyVault interface so LockEngine no
longer needs to know keyring exists.

This is deliberately named `SoftwareKeyVault` (not `LocalKeyVault`) to
leave room for `TPMKeyVault` / `DPAPIKeyVault` to be the *actual*
"local" story later -- this one is the fallback, not the target state.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.interfaces import IKeyVault

KEYRING_SERVICE = "TimeLockApp"

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False


class SoftwareKeyVault(IKeyVault):
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.master_key_file = os.path.join(data_dir, "master.key")
        self.recovery_key_file = os.path.join(data_dir, "recovery.key")

        self.keyring_degraded = False
        self._master_key_cache: bytes | None = None
        self._recovery_key_cache: bytes | None = None

    # -- keyring helpers, same fail-loud pattern as v1 -------------------
    def _keyring_get(self, key: str) -> str | None:
        if not KEYRING_AVAILABLE:
            return None
        try:
            return keyring.get_password(KEYRING_SERVICE, key)
        except Exception:
            self.keyring_degraded = True
            return None

    def _keyring_set(self, key: str, value: str) -> bool:
        if not KEYRING_AVAILABLE:
            return False
        try:
            keyring.set_password(KEYRING_SERVICE, key, value)
            return True
        except Exception:
            self.keyring_degraded = True
            return False

    # -- IKeyVault --------------------------------------------------------
    def get_or_create_master_key(self) -> bytes:
        if self._master_key_cache is not None:
            return self._master_key_cache

        if KEYRING_AVAILABLE:
            existing = self._keyring_get("master_key")
            if existing:
                self._master_key_cache = bytes.fromhex(existing)
                return self._master_key_cache
            key = AESGCM.generate_key(bit_length=256)
            self._keyring_set("master_key", key.hex())
            self._master_key_cache = key
            return key

        if os.path.exists(self.master_key_file):
            with open(self.master_key_file, "rb") as f:
                self._master_key_cache = f.read()
                return self._master_key_cache
        key = AESGCM.generate_key(bit_length=256)
        with open(self.master_key_file, "wb") as f:
            f.write(key)
        os.chmod(self.master_key_file, 0o600)
        self._master_key_cache = key
        return key

    def get_or_create_recovery_key(self) -> bytes:
        if self._recovery_key_cache is not None:
            return self._recovery_key_cache

        if KEYRING_AVAILABLE:
            existing = self._keyring_get("recovery_key")
            if existing:
                self._recovery_key_cache = bytes.fromhex(existing)
                return self._recovery_key_cache
            return self.rotate_recovery_key()

        if not os.path.exists(self.recovery_key_file):
            return self.rotate_recovery_key()
        with open(self.recovery_key_file, "rb") as f:
            key = f.read()
        self._recovery_key_cache = key
        return key

    def rotate_recovery_key(self) -> bytes:
        new_key = AESGCM.generate_key(bit_length=256)
        if KEYRING_AVAILABLE:
            self._keyring_set("recovery_key", new_key.hex())
        else:
            with open(self.recovery_key_file, "wb") as f:
                f.write(new_key)
            os.chmod(self.recovery_key_file, 0o600)
        self._keyring_set("recovery_key_hash", hashlib.sha256(new_key).hexdigest())
        self._recovery_key_cache = new_key
        return new_key

    def is_recovery_key_current(self, candidate: bytes) -> bool:
        expected_hash = self._keyring_get("recovery_key_hash")
        if expected_hash is None:
            return True  # no hash on record yet -- don't block, matches v1 behavior
        return hashlib.sha256(candidate).hexdigest() == expected_hash

    def mark_lock_active(self, token: str) -> None:
        self._keyring_set("active_lock_token", token)

    def get_active_lock_marker(self) -> str | None:
        return self._keyring_get("active_lock_token")

    def clear_active_lock_marker(self) -> None:
        if not KEYRING_AVAILABLE:
            return
        try:
            keyring.delete_password(KEYRING_SERVICE, "active_lock_token")
        except Exception:
            pass

    def security_warnings(self) -> list[str]:
        warnings = []
        if not KEYRING_AVAILABLE:
            warnings.append(
                "The 'keyring' package is not installed. Master key, "
                "recovery key, and tamper-history protections are all "
                "running in their weaker file-based fallback mode.\n"
                "Install it with: pip install keyring"
            )
        elif self.keyring_degraded:
            warnings.append(
                "keyring is installed but one or more calls to it failed "
                "on this system during this session. Some protections may "
                "not be working correctly -- check the console output for "
                "details."
            )
        return warnings
