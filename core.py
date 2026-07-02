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

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False
    print(
        "Warning: keyring not available (pip install keyring). "
        "Backup/restore tamper protection is disabled."
    )


class TimeLockCore:
    def __init__(self):
        self.STATE_FILE = "state.json"
        self.LOCK_FILE = "lock.json"
        self.MASTER_KEY_FILE = "master.key"
        self.RECOVERY_KEY_FILE = "recovery.key"

    def _keyring_get(self, key):
        if not KEYRING_AVAILABLE:
            return None
        try:
            return keyring.get_password(KEYRING_SERVICE, key)
        except Exception:
            return None

    def _keyring_set(self, key, value):
        if not KEYRING_AVAILABLE:
            return
        try:
            keyring.set_password(KEYRING_SERVICE, key, value)
        except Exception:
            pass

    def _keyring_delete(self, key):
        if not KEYRING_AVAILABLE:
            return
        try:
            keyring.delete_password(KEYRING_SERVICE, key)
        except Exception:
            pass

    def generate_strong_password(self, length=18):
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def load_master_key(self):
        if os.path.exists(self.MASTER_KEY_FILE):
            with open(self.MASTER_KEY_FILE, "rb") as f:
                return f.read()
        key = AESGCM.generate_key(bit_length=256)
        with open(self.MASTER_KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(self.MASTER_KEY_FILE, 0o600)
        return key

    def create_new_recovery_key(self):
        key = AESGCM.generate_key(bit_length=256)
        with open(self.RECOVERY_KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(self.RECOVERY_KEY_FILE, 0o600)
        self._keyring_set("recovery_key_hash", hashlib.sha256(key).hexdigest())
        return key

    def get_recovery_key(self):
        if not os.path.exists(self.RECOVERY_KEY_FILE):
            return self.create_new_recovery_key()
        with open(self.RECOVERY_KEY_FILE, "rb") as f:
            key = f.read()
        if self._keyring_get("recovery_key_hash") is None:
            self._keyring_set("recovery_key_hash", hashlib.sha256(key).hexdigest())
        return key

    def rotate_recovery_key(self):
        new_key = AESGCM.generate_key(bit_length=256)
        with open(self.RECOVERY_KEY_FILE, "wb") as f:
            f.write(new_key)
        os.chmod(self.RECOVERY_KEY_FILE, 0o600)
        self._keyring_set("recovery_key_hash", hashlib.sha256(new_key).hexdigest())
        return new_key

    def load_state(self):
        if not os.path.exists(self.STATE_FILE):
            return {"last_seen": time.time()}
        with open(self.STATE_FILE, "r") as f:
            state = json.load(f)
        return state

    def save_state(self, state):
        with open(self.STATE_FILE, "w") as f:
            json.dump(state, f, indent=4)

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

    def _timing_hmac(self, master_key, duration_seconds, created_wall, created_mono):
        msg = f"{duration_seconds}|{created_wall}|{created_mono}".encode()
        return hmac.new(master_key, msg, hashlib.sha256).hexdigest()

    def create_new_lock(self, duration_seconds: int, password: str = None):
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
            "timing_hmac": self._timing_hmac(master_key, duration_seconds, created_wall, created_mono),
            "lock_token": lock_token,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "master_nonce": m_nonce.hex(),
            "master_wrapped": m_wrapped.hex(),
            "recovery_nonce": r_nonce.hex(),
            "recovery_wrapped": r_wrapped.hex(),
        }

        with open(self.LOCK_FILE, "w") as f:
            json.dump(lock_data, f, indent=4)

        self._keyring_set("active_lock_token", lock_token)

        return password, unlock_time

    def get_remaining_time_safe(self):
        if not os.path.exists(self.LOCK_FILE):
            return 0, False

        with open(self.LOCK_FILE) as f:
            data = json.load(f)

        duration = data.get("duration_seconds")
        created_wall = data.get("created_wall")
        created_mono = data.get("created_mono")

        now_wall = time.time()
        now_mono = time.monotonic()

        if duration is None or created_wall is None:
            remaining = max(0, data.get("unlock_time", now_wall) - now_wall)
            return remaining, False

        if "timing_hmac" in data:
            master_key = self.load_master_key()
            expected = self._timing_hmac(master_key, duration, created_wall, created_mono)
            if data["timing_hmac"] != expected:
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
        try:
            with open(self.LOCK_FILE, "w") as f:
                json.dump(data, f, indent=4)
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
        if not os.path.exists(self.LOCK_FILE):
            return None, "No active lock"

        master_key = self.load_master_key()
        state = self.load_state()

        with open(self.LOCK_FILE) as f:
            data = json.load(f)

        if force_recovery and recovery_key_input:
            try:
                recovery_key = bytes.fromhex(recovery_key_input)
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

            expected_hash = self._keyring_get("recovery_key_hash")
            if expected_hash is not None:
                actual_hash = hashlib.sha256(recovery_key).hexdigest()
                if actual_hash != expected_hash:
                    return None, "This recovery key has already been used and rotated"

            if os.path.exists(self.LOCK_FILE):
                os.remove(self.LOCK_FILE)
            self._keyring_delete("active_lock_token")

            self.rotate_recovery_key()

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
        self._keyring_delete("active_lock_token")
        return password, "success"