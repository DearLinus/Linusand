# core.py
import os
import json
import time
import hmac
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CLOCK_TAMPER_THRESHOLD = 15
TAMPER_LOCKOUT_SECONDS = 10**9
KEYRING_SERVICE = "TimeLockApp"

# LAYER 4: escalating friction on Force Recovery. Each successful early
# unlock makes the NEXT one require a longer wait before the recovery
# dialog even opens. Grows fast at first, caps at 8 hours so it never
# becomes literally unusable in a real emergency.
RECOVERY_COOLDOWN_BASE_SECONDS = 5 * 60      # 5 min after the 1st use
RECOVERY_COOLDOWN_CAP_SECONDS = 8 * 60 * 60  # cap at 8 hours
RECOVERY_ACK_PHRASE_TEMPLATE = (
    "I am unlocking early and skipping the rest of this session"
)

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False
    print(
        "Warning: keyring not available (pip install keyring). "
        "Master-key protection and backup/restore tamper protection are "
        "both severely weakened without it."
    )

# Fields that determine how much time is left. ALL of them must be covered
# by the integrity HMAC, or an attacker can hand-edit lock.json and get a
# valid-looking file (this was the bug in the old version: only the
# creation-time fields were signed, not the live checkpoint/elapsed values
# that actually drive the countdown).
_SIGNED_FIELDS = (
    "duration_seconds",
    "created_wall",
    "created_mono",
    "checkpoint_wall",
    "checkpoint_mono",
    "trusted_elapsed",
)


class TimeLockCore:
    def __init__(self):
        self.DATA_DIR = self._get_data_dir()
        os.makedirs(self.DATA_DIR, exist_ok=True)
        self.STATE_FILE = os.path.join(self.DATA_DIR, "state.json")
        self.LOCK_FILE = os.path.join(self.DATA_DIR, "lock.json")
        self.MASTER_KEY_FILE = os.path.join(self.DATA_DIR, "master.key")
        self.RECOVERY_KEY_FILE = os.path.join(self.DATA_DIR, "recovery.key")
        # FIX (fresh pass, item A): True only once a keyring call actually
        # raises during this session (not simply "not installed").
        self.keyring_degraded = False
        # FIX (fresh pass, item B): in-memory cache so that if a keyring
        # *write* silently fails, this running process still keeps using
        # the SAME key for the rest of its life instead of minting a new
        # random one on every subsequent call (which would silently and
        # unpredictably break decryption of anything wrapped earlier in
        # this same run).
        self._master_key_cache = None
        self._recovery_key_cache = None

    @staticmethod
    def _get_data_dir():
        """
        Bug fix: the old version used bare relative filenames ("state.json"
        etc.), so behavior depended on whatever folder the app happened to
        be launched from. This pins everything to a fixed, predictable
        location so the Windows hardening script (icacls / Scheduled Task)
        always knows exactly where to point.
        """
        if os.name == "nt":
            base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
            return os.path.join(base, "TimeLock")
        return os.path.join(os.path.expanduser("~"), ".timelock")

    def _keyring_get(self, key):
        if not KEYRING_AVAILABLE:
            return None
        try:
            return keyring.get_password(KEYRING_SERVICE, key)
        except Exception as e:
            self.keyring_degraded = True
            print(f"Warning: keyring get failed for '{key}': {e}")
            return None

    def _keyring_set(self, key, value):
        if not KEYRING_AVAILABLE:
            return False
        try:
            keyring.set_password(KEYRING_SERVICE, key, value)
            return True
        except Exception as e:
            self.keyring_degraded = True
            print(f"Warning: keyring set failed for '{key}': {e}")
            return False

    def _keyring_delete(self, key):
        if not KEYRING_AVAILABLE:
            return
        try:
            keyring.delete_password(KEYRING_SERVICE, key)
        except Exception as e:
            self.keyring_degraded = True
            print(f"Warning: keyring delete failed for '{key}': {e}")

    def get_security_warnings(self):
        """
        FIX (fresh pass, item A): fail-loud instead of fail-silent.
        Returns human-readable warnings the GUI can surface directly,
        instead of keyring failures being invisible to the user.
        """
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

    # ------------------------------------------------------------------
    # LAYER 4: escalating friction on Force Recovery
    # ------------------------------------------------------------------
    # History of past early-unlocks is kept in the OS credential store
    # (not in state.json/lock.json) specifically so that deleting the
    # app's data folder does NOT reset the escalating cooldown or wipe
    # the history shown back to the user. If keyring is unavailable, we
    # fall back to state.json -- weaker (a file delete resets it), but
    # still better than nothing, and the user is warned at startup that
    # keyring is missing anyway.

    def _sign_history(self, master_key, raw_json_str):
        return hmac.new(master_key, raw_json_str.encode(), hashlib.sha256).hexdigest()

    def get_recovery_history(self):
        """
        FIX (item 4): the history is now HMAC-signed with master_key, the
        same pattern used for lock.json's state_hmac. Returns
        (history_list, tampered_bool).

        Design intent (matches the stated goal -- make cheating not worth
        the effort): if the stored history is missing its signature or the
        signature doesn't match, we do NOT fall back to an empty history.
        An attacker who deletes/edits the history to erase their past
        early-unlocks must never end up in a *better* position than if
        they'd left it alone. The caller (get_recovery_cooldown_status)
        treats tampered=True as "assume the worst" -- max cooldown, max
        required acknowledgments -- rather than "assume clean".
        """
        raw = self._keyring_get("recovery_history")
        sig = self._keyring_get("recovery_history_hmac")
        if raw is None:
            state = self.load_state()
            raw = state.get("recovery_history_fallback")
            sig = state.get("recovery_history_fallback_hmac")

        if not raw:
            return [], False

        master_key = self.load_master_key()
        expected_sig = self._sign_history(master_key, raw)
        if sig is None or not hmac.compare_digest(sig, expected_sig):
            return [], True

        try:
            return json.loads(raw), False
        except (json.JSONDecodeError, TypeError):
            return [], True

    def _save_recovery_history(self, history):
        raw = json.dumps(history, sort_keys=True)
        master_key = self.load_master_key()
        sig = self._sign_history(master_key, raw)
        if KEYRING_AVAILABLE:
            self._keyring_set("recovery_history", raw)
            self._keyring_set("recovery_history_hmac", sig)
        else:
            state = self.load_state()
            state["recovery_history_fallback"] = raw
            state["recovery_history_fallback_hmac"] = sig
            self.save_state(state)

    def record_recovery_use(self):
        """
        Call this exactly once, right after a Force Recovery succeeds.
        If the previous history was found tampered, we deliberately don't
        try to preserve/merge it (it can't be trusted) -- we start a
        fresh, properly signed history containing just this new entry.
        Any friction lost from the wiped tampered history was already
        paid for by get_recovery_cooldown_status forcing the worst case
        on this attempt.
        """
        history, tampered = self.get_recovery_history()
        if tampered:
            history = []
        history.append({"ts": time.time()})
        self._save_recovery_history(history)

    def get_recovery_cooldown_status(self):
        """
        Returns (seconds_remaining, required_ack_count, history).
        seconds_remaining > 0 means Force Recovery should stay locked out
        (show a countdown instead of the key-entry form).
        required_ack_count grows with how many times recovery has been
        used before, and drives how many times the acknowledgment phrase
        must be retyped correctly before the key-entry form unlocks.
        """
        history, tampered = self.get_recovery_history()

        if tampered:
            # FIX (item 4): tampering must never make this easier. Force
            # the worst case instead of resetting to "no history".
            return RECOVERY_COOLDOWN_CAP_SECONDS, 5, []

        count = len(history)
        if count == 0:
            return 0.0, 1, history

        last_ts = history[-1]["ts"]
        cooldown = min(
            RECOVERY_COOLDOWN_BASE_SECONDS * (2 ** (count - 1)),
            RECOVERY_COOLDOWN_CAP_SECONDS,
        )
        elapsed = time.time() - last_ts
        remaining = max(0.0, cooldown - elapsed)
        required_ack_count = min(1 + count, 5)  # cap at 5 retypes
        return remaining, required_ack_count, history

    def has_active_lock(self):
        """
        Use this instead of os.path.exists(self.LOCK_FILE) everywhere.
        Once the Windows deny-delete hardening is applied, the app can no
        longer actually delete lock.json (same restriction the user is
        subject to) -- so a "used up" lock is marked consumed via an
        in-place write instead of being removed. This treats both "file
        genuinely absent" and "file present but marked consumed" as "no
        active lock."
        """
        if not os.path.exists(self.LOCK_FILE):
            return False
        try:
            with open(self.LOCK_FILE) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return True  # corrupt file -> treat as still "there", tamper path handles it
        return not data.get("consumed", False)

    def _mark_lock_consumed(self):
        """
        Replaces the old os.remove(self.LOCK_FILE) call. Writes an
        in-place marker instead of deleting, so this keeps working even
        after icacls deny-delete is applied to the data folder (which
        blocks DELETE but not WRITE for the same account).
        """
        if os.path.exists(self.LOCK_FILE):
            try:
                self._atomic_write_json(self.LOCK_FILE, {"consumed": True})
            except Exception:
                pass

    def generate_strong_password(self, length=18):
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def load_master_key(self):
        """
        LAYER 2 HARDENING: master key lives ONLY in the OS credential
        store (Windows Credential Manager, etc.) when keyring is
        available -- never in a plain file. This means deleting the app
        folder does not reset it, and reading it requires going through
        the OS credential API instead of just opening a file.
        Falls back to a file (with a loud warning) only if keyring is
        unavailable.

        FIX (fresh pass, item B): checks the in-memory cache first. If a
        key was already generated this session, we NEVER mint a second
        one for the same process, even if persisting it to keyring
        silently failed -- that silent-failure case is exactly what used
        to cause locks to become undecryptable with no explanation.
        """
        if self._master_key_cache is not None:
            return self._master_key_cache

        if KEYRING_AVAILABLE:
            existing = self._keyring_get("master_key")
            if existing:
                self._master_key_cache = bytes.fromhex(existing)
                return self._master_key_cache
            key = AESGCM.generate_key(bit_length=256)
            if not self._keyring_set("master_key", key.hex()):
                print(
                    "Warning: could not persist a new master key to keyring. "
                    "It will only be valid for this running session -- "
                    "restarting the app before this lock finishes may make "
                    "it unrecoverable except via Force Recovery."
                )
            self._master_key_cache = key
            return key

        if os.path.exists(self.MASTER_KEY_FILE):
            with open(self.MASTER_KEY_FILE, "rb") as f:
                self._master_key_cache = f.read()
                return self._master_key_cache
        key = AESGCM.generate_key(bit_length=256)
        with open(self.MASTER_KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(self.MASTER_KEY_FILE, 0o600)
        self._master_key_cache = key
        return key

    def create_new_recovery_key(self):
        key = AESGCM.generate_key(bit_length=256)
        if KEYRING_AVAILABLE:
            if not self._keyring_set("recovery_key", key.hex()):
                print(
                    "Warning: could not persist the new recovery key to "
                    "keyring. It will only be valid for this running "
                    "session."
                )
        else:
            with open(self.RECOVERY_KEY_FILE, "wb") as f:
                f.write(key)
            os.chmod(self.RECOVERY_KEY_FILE, 0o600)
        self._keyring_set("recovery_key_hash", hashlib.sha256(key).hexdigest())
        self._recovery_key_cache = key
        return key

    def get_recovery_key(self):
        """
        FIX (item 3): applies the same pattern used for the master key --
        the recovery key itself (not just its hash) now lives in the OS
        credential store when keyring is available, instead of a plaintext
        file that a simple folder backup can copy wholesale. Falls back to
        the file if keyring is unavailable, and transparently migrates an
        existing plaintext file into keyring the first time it's found
        (the old file is left in place untouched, not deleted, to stay
        compatible with deny-delete hardening).

        FIX (fresh pass, item B): checks the in-memory cache first, for
        the same reason as load_master_key -- a silently-failed keyring
        write must never cause this process to mint a second, different
        recovery key later in the same run.
        """
        if self._recovery_key_cache is not None:
            return self._recovery_key_cache

        if KEYRING_AVAILABLE:
            existing = self._keyring_get("recovery_key")
            if existing:
                self._recovery_key_cache = bytes.fromhex(existing)
                return self._recovery_key_cache
            if os.path.exists(self.RECOVERY_KEY_FILE):
                with open(self.RECOVERY_KEY_FILE, "rb") as f:
                    key = f.read()
                self._keyring_set("recovery_key", key.hex())
                if self._keyring_get("recovery_key_hash") is None:
                    self._keyring_set("recovery_key_hash", hashlib.sha256(key).hexdigest())
                self._recovery_key_cache = key
                return key
            return self.create_new_recovery_key()

        if not os.path.exists(self.RECOVERY_KEY_FILE):
            return self.create_new_recovery_key()
        with open(self.RECOVERY_KEY_FILE, "rb") as f:
            key = f.read()
        if self._keyring_get("recovery_key_hash") is None:
            self._keyring_set("recovery_key_hash", hashlib.sha256(key).hexdigest())
        self._recovery_key_cache = key
        return key

    def rotate_recovery_key(self):
        new_key = AESGCM.generate_key(bit_length=256)
        if KEYRING_AVAILABLE:
            if not self._keyring_set("recovery_key", new_key.hex()):
                print(
                    "Warning: could not persist the rotated recovery key "
                    "to keyring. It will only be valid for this running "
                    "session."
                )
        else:
            with open(self.RECOVERY_KEY_FILE, "wb") as f:
                f.write(new_key)
            os.chmod(self.RECOVERY_KEY_FILE, 0o600)
        self._keyring_set("recovery_key_hash", hashlib.sha256(new_key).hexdigest())
        self._recovery_key_cache = new_key
        return new_key

    def load_state(self):
        if not os.path.exists(self.STATE_FILE):
            return {"last_seen": time.time()}
        with open(self.STATE_FILE, "r") as f:
            state = json.load(f)
        return state

    def save_state(self, state):
        # FIX (fresh pass, item D): was a plain non-atomic write before --
        # inconsistent with lock.json's crash-safe handling, and this file
        # now also holds the recovery-history fallback + its signature
        # when keyring is unavailable.
        self._atomic_write_json(self.STATE_FILE, state)

    def safe_time(self, state):
        now = time.time()
        if now < state.get("last_seen", 0) - CLOCK_TAMPER_THRESHOLD:
            print("Warning: system clock appears to have been tampered with!")
            return None
        state["last_seen"] = now
        self.save_state(state)
        return now

    def encrypt_password(self, dek, password):
        aes = AESGCM(dek)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, password.encode('utf-8'), None)
        return nonce, ct

    def decrypt_password(self, dek, nonce, ct):
        aes = AESGCM(dek)
        return aes.decrypt(nonce, ct, None).decode('utf-8')

    def wrap_key(self, wrapping_key, key_to_wrap):
        aes = AESGCM(wrapping_key)
        nonce = os.urandom(12)
        return nonce, aes.encrypt(nonce, key_to_wrap, None)

    def unwrap_key(self, wrapping_key, nonce, wrapped):
        aes = AESGCM(wrapping_key)
        return aes.decrypt(nonce, wrapped, None)

    def _state_hmac(self, master_key, data):
        """
        LAYER 1 FIX (the critical bug): the old _timing_hmac only signed
        duration_seconds/created_wall/created_mono. But the value that
        actually decides "how much time is left" each tick is
        trusted_elapsed / checkpoint_wall / checkpoint_mono -- none of
        which were covered. That meant a user could open lock.json in a
        text editor, set trusted_elapsed to a huge number, and the old
        HMAC would still verify fine because it never looked at that
        field. This computes one HMAC over ALL fields in _SIGNED_FIELDS,
        canonically serialized, and must be recomputed and re-stored
        every single time any of those fields changes on disk.
        """
        payload = json.dumps(
            {k: data[k] for k in _SIGNED_FIELDS},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hmac.new(master_key, payload, hashlib.sha256).hexdigest()

    def _atomic_write_json(self, path, data):
        """
        FIX (item 2): tries the crash-safe temp-file + os.replace()
        pattern FIRST (a crash mid-write can never leave a half-written
        file this way, unlike in-place truncate+rewrite). Only falls
        back to in-place truncate+rewrite if the rename itself fails --
        which is exactly what happens on Windows once the icacls
        deny-delete hardening (see windows_harden.ps1) is applied, since
        os.replace() needs DELETE permission on the destination and
        in-place writing only needs WRITE.

        This means: with no hardening applied (most installs today),
        writes are fully crash-safe. With deny-delete hardening applied,
        it degrades gracefully to the weaker-but-still-functional
        in-place mode automatically, instead of unconditionally taking
        the weaker path for everyone regardless of whether it's needed.
        """
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
            # رد شد -> احتمالاً deny-delete ACL فعاله؛ برو سراغ حالت جایگزین
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

    def create_new_lock(self, duration_seconds: int, password: str = None):
        # LOGIC FIX: never silently clobber a lock that's still counting
        # down. Without this, calling create_new_lock while one is active
        # would quietly reset the timer -- which is itself a cheat path.
        if self.has_active_lock():
            remaining, _ = self.get_remaining_time_safe()
            if remaining > 0:
                raise RuntimeError(
                    "A lock is already active; refusing to overwrite it."
                )

        master_key = self.load_master_key()
        recovery_key = self.get_recovery_key()

        if password is None:
            password = self.generate_strong_password()

        created_wall = time.time()
        created_mono = time.monotonic()
        unlock_time = created_wall + duration_seconds
        dek = AESGCM.generate_key(bit_length=256)

        nonce, ciphertext = self.encrypt_password(dek, password)
        m_nonce, m_wrapped = self.wrap_key(master_key, dek)
        r_nonce, r_wrapped = self.wrap_key(recovery_key, dek)

        lock_token = secrets.token_hex(16)

        lock_data = {
            "unlock_time": unlock_time,
            "duration_seconds": duration_seconds,
            "created_wall": created_wall,
            "created_mono": created_mono,
            "checkpoint_wall": created_wall,
            "checkpoint_mono": created_mono,
            "trusted_elapsed": 0.0,
            "lock_token": lock_token,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "master_nonce": m_nonce.hex(),
            "master_wrapped": m_wrapped.hex(),
            "recovery_nonce": r_nonce.hex(),
            "recovery_wrapped": r_wrapped.hex(),
        }
        lock_data["state_hmac"] = self._state_hmac(master_key, lock_data)

        self._atomic_write_json(self.LOCK_FILE, lock_data)

        self._keyring_set("active_lock_token", lock_token)

        return password, unlock_time

    def get_remaining_time_safe(self):
        if not self.has_active_lock():
            return 0, False

        try:
            with open(self.LOCK_FILE) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            # Corrupt/unreadable file -- treat exactly like a failed
            # integrity check rather than crashing the app.
            return TAMPER_LOCKOUT_SECONDS, True

        duration = data.get("duration_seconds")
        created_wall = data.get("created_wall")
        created_mono = data.get("created_mono")

        now_wall = time.time()
        now_mono = time.monotonic()

        if duration is None or created_wall is None:
            remaining = max(0, data.get("unlock_time", now_wall) - now_wall)
            return remaining, False

        master_key = self.load_master_key()

        # LAYER 1 FIX: verify the HMAC over ALL mutable fields, not just
        # the creation-time ones. If any of duration_seconds, created_*,
        # checkpoint_*, or trusted_elapsed was hand-edited since the last
        # time we wrote the file, this will not match and we treat the
        # lock as tampered -> lockout, rather than trusting whatever
        # numbers are sitting in the file.
        if "state_hmac" in data:
            try:
                expected = self._state_hmac(master_key, data)
            except KeyError:
                # a signed field is missing entirely -> definitely tampered
                return TAMPER_LOCKOUT_SECONDS, True
            if not hmac.compare_digest(data["state_hmac"], expected):
                return TAMPER_LOCKOUT_SECONDS, True
        elif "timing_hmac" in data:
            # Backward-compat with locks created by the old, weaker
            # scheme. Treat as tampered so it can't be used to bypass the
            # new checks -- forces a fresh lock under the new format.
            return TAMPER_LOCKOUT_SECONDS, True

        checkpoint_wall = data.get("checkpoint_wall", created_wall)
        checkpoint_mono = data.get("checkpoint_mono", created_mono)
        trusted_elapsed = data.get("trusted_elapsed", 0.0)

        tampered = False

        if checkpoint_mono is not None and now_mono >= checkpoint_mono:
            delta_wall = now_wall - checkpoint_wall
            delta_mono = now_mono - checkpoint_mono
            if abs(delta_wall - delta_mono) > CLOCK_TAMPER_THRESHOLD:
                tampered = True
                delta = delta_mono
            else:
                delta = delta_wall
        else:
            tampered = True
            delta = max(0, now_wall - checkpoint_wall)

        total_elapsed = min(trusted_elapsed + max(0, delta), duration)
        remaining = max(0, duration - total_elapsed)

        data["checkpoint_wall"] = now_wall
        data["checkpoint_mono"] = now_mono
        data["trusted_elapsed"] = total_elapsed
        # Re-sign after every mutation -- the on-disk HMAC must always
        # match the on-disk mutable fields, or the next read will (falsely)
        # flag tampering against our own legitimate update.
        data["state_hmac"] = self._state_hmac(master_key, data)
        try:
            self._atomic_write_json(self.LOCK_FILE, data)
        except Exception:
            pass

        return remaining, tampered

    def get_remaining_time(self):
        remaining, _ = self.get_remaining_time_safe()
        return remaining

    def is_time_up(self):
        return self.get_remaining_time() <= 0

    def check_lock_tamper_evidence(self):
        token = self._keyring_get("active_lock_token")
        return bool(token) and not os.path.exists(self.LOCK_FILE)

    def clear_lock_tamper_evidence(self):
        self._keyring_delete("active_lock_token")

    def unlock_password(self, force_recovery=False, recovery_key_input=None):
        if not self.has_active_lock():
            return None, "No active lock"

        master_key = self.load_master_key()
        state = self.load_state()

        # FIX (fresh pass, item C): get_remaining_time_safe() already
        # treats a corrupt lock.json as tampered instead of crashing, but
        # this direct read here didn't have the same protection -- a
        # corrupted file would raise an uncaught JSONDecodeError and
        # crash the whole app instead of failing gracefully.
        try:
            with open(self.LOCK_FILE) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None, "Lock file is corrupted or unreadable - use Force Recovery"

        if force_recovery and recovery_key_input:
            try:
                recovery_key = bytes.fromhex(recovery_key_input)
            except Exception:
                return None, "Invalid recovery key"

            # FIX (fresh pass, item E): check the key against the known-
            # current hash BEFORE doing any decryption work, not after.
            # Rejecting early means a stale/replayed key never gets its
            # bytes unwrapped or decrypted at all, which is both cleaner
            # and slightly more defensive than decrypting first and only
            # then deciding to discard the result.
            expected_hash = self._keyring_get("recovery_key_hash")
            if expected_hash is not None:
                actual_hash = hashlib.sha256(recovery_key).hexdigest()
                if actual_hash != expected_hash:
                    return None, "This recovery key has already been used and rotated"

            try:
                dek = self.unwrap_key(
                    recovery_key,
                    bytes.fromhex(data["recovery_nonce"]),
                    bytes.fromhex(data["recovery_wrapped"]),
                )
                password = self.decrypt_password(
                    dek, bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"])
                )
            except Exception:
                return None, "Invalid recovery key"

            if os.path.exists(self.LOCK_FILE):
                self._mark_lock_consumed()
            self._keyring_delete("active_lock_token")

            self.rotate_recovery_key()
            self.record_recovery_use()

            state["recovery_shown"] = False
            self.save_state(state)

            return password, "success"

        now = self.safe_time(state)
        if now is None:
            return None, "Warning: system clock was rolled back"

        remaining, tampered = self.get_remaining_time_safe()

        if remaining > 0:
            msg = "Lock is still active"
            if tampered:
                msg += " (clock/file tampering detected - use Force Recovery instead)"
            return None, msg

        try:
            dek = self.unwrap_key(
                master_key, bytes.fromhex(data["master_nonce"]), bytes.fromhex(data["master_wrapped"])
            )
        except Exception:
            return None, "Key decryption failed"

        password = self.decrypt_password(
            dek, bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"])
        )
        # FIX (item 1): this call was missing on the normal-unlock path,
        # so has_active_lock() kept returning True forever for a lock
        # that had already finished normally (only Force Recovery marked
        # it consumed). Harmless in practice because remaining still
        # correctly computed 0, but it made has_active_lock() lie.
        self._mark_lock_consumed()
        self._keyring_delete("active_lock_token")
        return password, "success"