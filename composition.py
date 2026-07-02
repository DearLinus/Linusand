"""
The composition root -- the ONLY file in this project allowed to
import both `core` and `adapters` and wire them together. Every other
file in `core/` depends only on interfaces; every adapter only
implements one interface. This file is where "which adapter runs
today" gets decided.

Today it always builds the local/software stack. A future
`composition_cloud.py` (or a flag in this same file) would build
RemoteCrypto/CloudStorage instead, with zero changes to anything in
`core/`.
"""
from __future__ import annotations

import os

from adapters.clock_system import SystemClock
from adapters.crypto_local import LocalAesGcmCrypto
from adapters.keyvault_software import SoftwareKeyVault
from adapters.logger_audit import SignedAuditLog
from adapters.storage_local import LocalFileStorage
from core.lock_engine import LockEngine
from core.recovery_engine import RecoveryEngine


def default_data_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "TimeLock")
    return os.path.join(os.path.expanduser("~"), ".timelock")


class TimeLockApp:
    """Small facade bundling the wired engines + a couple of pass-through
    helpers the GUI needs (security warnings, audit log). Kept
    intentionally thin -- it's wiring, not logic."""

    def __init__(self, data_dir: str | None = None):
        self.data_dir = data_dir or default_data_dir()

        # ---- adapters (swap these to change deployment target) --------
        self.crypto = LocalAesGcmCrypto()
        self.keyvault = SoftwareKeyVault(self.data_dir)
        self.storage = LocalFileStorage(self.data_dir)
        self.clock = SystemClock()
        self.logger = SignedAuditLog(self.data_dir)

        # ---- core engines (depend only on the interfaces above) --------
        self.lock_engine = LockEngine(
            crypto=self.crypto,
            keyvault=self.keyvault,
            storage=self.storage,
            clock=self.clock,
            logger=self.logger,
        )
        self.recovery_engine = RecoveryEngine(
            lock_engine=self.lock_engine,
            keyvault=self.keyvault,
            storage=self.storage,
            logger=self.logger,
        )

    def security_warnings(self) -> list[str]:
        return self.keyvault.security_warnings()

    # Thin passthroughs so the GUI layer never needs to know which
    # adapter/engine actually owns a given piece of state -- it just
    # talks to `self.app`. Kept here (not sprinkled across engines) so
    # it's obvious at a glance this is wiring convenience, not logic.
    def check_lock_tamper_evidence(self) -> bool:
        return self.lock_engine.check_tamper_evidence()

    def clear_lock_tamper_evidence(self) -> None:
        self.lock_engine.clear_tamper_evidence()

    def get_recovery_key(self):
        return self.keyvault.get_or_create_recovery_key()

    def load_state(self) -> dict:
        return self.storage.load_state()

    def save_state(self, state: dict) -> None:
        self.storage.save_state(state)


def build_app(data_dir: str | None = None) -> TimeLockApp:
    return TimeLockApp(data_dir)
