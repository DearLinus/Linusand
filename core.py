# core.py
import os
import json
import time
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

class TimeLockCore:
    def __init__(self):
        self.STATE_FILE = "state.json"
        self.LOCK_FILE = "lock.json"
        self.MASTER_KEY_FILE = "master.key"
        self.RECOVERY_KEY_FILE = "recovery.key"

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
        return key

    def get_recovery_key(self):
        if not os.path.exists(self.RECOVERY_KEY_FILE):
            return self.create_new_recovery_key()
        with open(self.RECOVERY_KEY_FILE, "rb") as f:
            return f.read()

    def load_state(self):
        if not os.path.exists(self.STATE_FILE):
            return {"last_seen": time.time(), "temp_version": 0, "active_temp_key": None}
        with open(self.STATE_FILE, "r") as f:
            state = json.load(f)
        state.setdefault("temp_version", 0)
        state.setdefault("active_temp_key", None)
        return state

    def save_state(self, state):
        with open(self.STATE_FILE, "w") as f:
            json.dump(state, f, indent=4)

    def safe_time(self, state):
        now = time.time()
        if now < state.get("last_seen", 0) - 15:
            print("⚠️  هشدار: زمان سیستم دستکاری شده!")
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

    def create_new_lock(self, duration_seconds: int, password: str = None):
        master_key = self.load_master_key()
        recovery_key = self.get_recovery_key()
        state = self.load_state()

        state["temp_version"] = state.get("temp_version", 0) + 1
        temp_key = AESGCM.generate_key(bit_length=256)
        state["active_temp_key"] = temp_key.hex()
        self.save_state(state)

        if password is None:
            password = self.generate_strong_password()
            unlock_time = time.time() + duration_seconds
            dek = AESGCM.generate_key(bit_length=256)

        state["temp_version"] = state.get("temp_version", 0) + 1
        temp_key = AESGCM.generate_key(bit_length=256)
        state["active_temp_key"] = temp_key.hex()
        self.save_state(state)

        password = self.generate_strong_password()
        unlock_time = time.time() + duration_seconds
        dek = AESGCM.generate_key(bit_length=256)

        nonce, ciphertext = self.encrypt_password(dek, password)
        m_nonce, m_wrapped = self.wrap_key(master_key, dek)
        t_nonce, t_wrapped = self.wrap_key(temp_key, dek)
        r_nonce, r_wrapped = self.wrap_key(recovery_key, dek)

        lock_data = {
            "unlock_time": unlock_time,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "master_nonce": m_nonce.hex(),
            "master_wrapped": m_wrapped.hex(),
            "temp_nonce": t_nonce.hex(),
            "temp_wrapped": t_wrapped.hex(),
            "recovery_nonce": r_nonce.hex(),
            "recovery_wrapped": r_wrapped.hex(),
        }

        with open(self.LOCK_FILE, "w") as f:
            json.dump(lock_data, f, indent=4)

        return password, unlock_time

    def get_remaining_time(self):
        if not os.path.exists(self.LOCK_FILE):
            return 0
        with open(self.LOCK_FILE) as f:
            data = json.load(f)
        return max(0, data["unlock_time"] - time.time())

    def is_time_up(self):
        return self.get_remaining_time() <= 0

    def get_password(self):
        if not os.path.exists(self.LOCK_FILE):
            return None
        with open(self.LOCK_FILE) as f:
            data = json.load(f)
        return data.get("password")

    def unlock_password(self, force_recovery=False, recovery_key_input=None):
        if not os.path.exists(self.LOCK_FILE):
            return None, "لاک فعالی وجود ندارد"

        master_key = self.load_master_key()
        state = self.load_state()
        now = self.safe_time(state)
        if now is None:
            return None, "هشدار زمان"

        with open(self.LOCK_FILE) as f:
            data = json.load(f)

        if force_recovery and recovery_key_input:
            try:
                recovery_key = bytes.fromhex(recovery_key_input)
                dek = self.unwrap_key(recovery_key, bytes.fromhex(data["recovery_nonce"]), bytes.fromhex(data["recovery_wrapped"]))
                
                new_recovery_key = self.create_new_recovery_key()
                r_nonce, r_wrapped = self.wrap_key(new_recovery_key, dek)
                data["recovery_nonce"] = r_nonce.hex()
                data["recovery_wrapped"] = r_wrapped.hex()
                with open(self.LOCK_FILE, "w") as f:
                    json.dump(data, f, indent=4)
                
                password = self.decrypt_password(dek, bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"]))
                return password, "success"
            except:
                return None, "The recovery key is incorrect."
        elif data["unlock_time"] - now > 0:
            temp_key = bytes.fromhex(state["active_temp_key"])
            dek = self.unwrap_key(temp_key, bytes.fromhex(data["temp_nonce"]), bytes.fromhex(data["temp_wrapped"]))
        else:
            dek = self.unwrap_key(master_key, bytes.fromhex(data["master_nonce"]), bytes.fromhex(data["master_wrapped"]))

        password = self.decrypt_password(dek, bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"]))
        return password, "success"