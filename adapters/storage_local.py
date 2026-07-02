"""
IStorage implementation over local JSON files, ported from v1's
_atomic_write_json / load_state / save_state, plus the "mark consumed
instead of delete" pattern from has_active_lock/_mark_lock_consumed
(kept because it's genuinely useful: it keeps working even under
restrictive ACLs that block delete but allow write).
"""
from __future__ import annotations

import json
import os
import secrets

from core.interfaces import IStorage


class LocalFileStorage(IStorage):
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.lock_file = os.path.join(data_dir, "lock.json")
        self.state_file = os.path.join(data_dir, "state.json")

    # -- lock -------------------------------------------------------------
    def save_lock(self, data: dict) -> None:
        self._atomic_write_json(self.lock_file, data)

    def load_lock(self) -> dict | None:
        try:
            with open(self.lock_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def lock_exists(self) -> bool:
        return os.path.exists(self.lock_file)

    # -- state --------------------------------------------------------------
    def load_state(self) -> dict:
        if not os.path.exists(self.state_file):
            return {}
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def save_state(self, state: dict) -> None:
        self._atomic_write_json(self.state_file, state)

    # -- internals ------------------------------------------------------------
    def _atomic_write_json(self, path: str, data: dict) -> None:
        """Crash-safe temp-file + os.replace() first; falls back to
        in-place truncate+rewrite if the rename itself fails (e.g. under
        a deny-delete ACL) -- identical strategy to v1."""
        payload = json.dumps(data, indent=4).encode()
        tmp_path = f"{path}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
        try:
            with open(tmp_path, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            return
        except OSError:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass

        if os.path.exists(path):
            with open(path, "r+b") as f:
                f.seek(0)
                f.write(payload)
                f.truncate()
                f.flush()
                os.fsync(f.fileno())
        else:
            with open(path, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
