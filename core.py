# core.py
import os
import json
import time
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

# حداکثر اختلاف مجاز (به ثانیه) بین wall-clock و monotonic clock
# قبل از این‌که دستکاری ساعت سیستم تشخیص داده بشه
CLOCK_TAMPER_THRESHOLD = 15


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
        """
        ساخت اولین recovery key، فقط وقتی که فایل recovery.key اصلاً
        وجود نداره (اولین اجرای برنامه). برای rotate کردن کلید بعد از
        مصرف، از rotate_recovery_key() استفاده می‌شه.
        """
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

    def rotate_recovery_key(self):
        """
        یک recovery key کاملاً جدید می‌سازه و جایگزین قدیمی می‌کنه.
        این تابع بعد از مصرف موفق یک recovery key (در unlock_password با
        force_recovery=True) صدا زده می‌شه تا کلید قدیمی دیگه برای هیچ
        قفلی (نه قفل فعلی که حذف شده، نه قفل‌های بعدی) معتبر نباشه.
        """
        new_key = AESGCM.generate_key(bit_length=256)
        with open(self.RECOVERY_KEY_FILE, "wb") as f:
            f.write(new_key)
        os.chmod(self.RECOVERY_KEY_FILE, 0o600)
        return new_key

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
        """
        تشخیص عقب رفتن ساعت سیستم (backward tampering).
        این تابع دست‌نخورده مونده، فقط کنارش get_remaining_time_safe
        برای تشخیص جلو رفتن ساعت اضافه شده.
        """
        now = time.time()
        if now < state.get("last_seen", 0) - CLOCK_TAMPER_THRESHOLD:
            print("⚠️  Warning: system clock appears to have been tampered with!")
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
        """
        FIX (مشکل شمارش زودهنگام): پارامتر اختیاری password اضافه شد تا
        بشه رمزی که از قبل تولید و به کاربر نمایش داده شده رو دوباره‌استفاده
        کرد، به‌جای تولید یک رمز تصادفی جدید.

        FIX (مشکل ۲): علاوه بر unlock_time (wall-clock)، duration_seconds
        و created_mono (ساعت monotonic) هم ذخیره می‌شن تا بعداً بشه دستکاری
        ساعت سیستم رو تشخیص داد.
        """
        master_key = self.load_master_key()
        recovery_key = self.get_recovery_key()
        state = self.load_state()

        state["temp_version"] = state.get("temp_version", 0) + 1
        temp_key = AESGCM.generate_key(bit_length=256)
        state["active_temp_key"] = temp_key.hex()
        self.save_state(state)

        if password is None:
            password = self.generate_strong_password()

        created_wall = time.time()
        created_mono = time.monotonic()
        unlock_time = created_wall + duration_seconds
        dek = AESGCM.generate_key(bit_length=256)

        nonce, ciphertext = self.encrypt_password(dek, password)
        m_nonce, m_wrapped = self.wrap_key(master_key, dek)
        t_nonce, t_wrapped = self.wrap_key(temp_key, dek)
        r_nonce, r_wrapped = self.wrap_key(recovery_key, dek)

        lock_data = {
            "unlock_time": unlock_time,
            "duration_seconds": duration_seconds,
            "created_wall": created_wall,
            "created_mono": created_mono,
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

    def get_remaining_time_safe(self):
        """
        FIX (مشکل ۲): محاسبه‌ی زمان باقی‌مانده با مقاومت در برابر دستکاری
        ساعت سیستم (system clock).

        از دو ساعت استفاده می‌کنه:
        - wall-clock (time.time): قابل تغییر توسط کاربر از تنظیمات سیستم
        - monotonic clock (time.monotonic): همیشه فقط جلو می‌ره و از تغییر
          ساعت سیستم اثر نمی‌گیره (فقط با ری‌استارت کامل سیستم ریست می‌شه)

        اگه اختلاف بین این دو زیاد بشه، یعنی ساعت سیستم دستکاری شده؛
        در این حالت مبنا رو ساعت monotonic قرار می‌دیم (قابل اعتمادتره).

        خروجی: (remaining_seconds, tampered_bool)
        """
        if not os.path.exists(self.LOCK_FILE):
            return 0, False

        with open(self.LOCK_FILE) as f:
            data = json.load(f)

        duration = data.get("duration_seconds")
        created_wall = data.get("created_wall")
        created_mono = data.get("created_mono")

        now_wall = time.time()
        now_mono = time.monotonic()

        # سازگاری با قفل‌های قدیمی که این فیلدهای جدید رو ندارن
        if duration is None or created_wall is None:
            remaining = max(0, data.get("unlock_time", now_wall) - now_wall)
            return remaining, False

        elapsed_wall = now_wall - created_wall
        tampered = False

        if created_mono is not None and now_mono >= created_mono:
            elapsed_mono = now_mono - created_mono
            if abs(elapsed_wall - elapsed_mono) > CLOCK_TAMPER_THRESHOLD:
                tampered = True
                elapsed = elapsed_mono
            else:
                elapsed = elapsed_wall
        else:
            # سیستم ری‌استارت شده و مقدار monotonic ریست شده؛
            # امکان مقایسه نیست، مجبوریم به wall-clock اعتماد کنیم
            elapsed = elapsed_wall

        remaining = max(0, duration - elapsed)
        return remaining, tampered

    def get_remaining_time(self):
        remaining, _ = self.get_remaining_time_safe()
        return remaining

    def is_time_up(self):
        return self.get_remaining_time() <= 0

    def get_password(self):
        if not os.path.exists(self.LOCK_FILE):
            return None
        with open(self.LOCK_FILE) as f:
            data = json.load(f)
        return data.get("password")

    def unlock_password(self, force_recovery=False, recovery_key_input=None):
        """
        FIX (مشکل ۱): این تابع حالا در مسیر عادی برنامه (پایان شمارش) هم
        صدا زده می‌شه، نه فقط در مسیر Force Recovery. یعنی رمز واقعاً از
        روی فایل رمزگشایی می‌شه، نه اینکه از متغیر حافظه‌ی GUI خونده بشه.

        FIX (مشکل ۲): تصمیم‌گیری «هنوز قفله یا نه» به‌جای وابستگی مستقیم
        به wall-clock، از get_remaining_time_safe (مقاوم در برابر دستکاری
        ساعت) استفاده می‌کنه.
        """
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

            # این کلید recovery همین الان مصرف شد. طبق مکانیزم مورد نظر:
            # ۱) قفل فعلی دیگه لازم نیست شمارشش ادامه پیدا کنه، چون رمز
            #    از طریق ریکاوری همین الان لو رفته.
            # ۲) کلید recovery بلافاصله rotate می‌شه تا همین کلید قدیمی
            #    نتونه برای قفل بعدی هم استفاده بشه.
            # ۳) flag نمایش ریست می‌شه تا دفعه‌ی بعد که کاربر روی
            #    "Generate New Recovery Key" کلیک کنه، همین کلید تازه‌ی
            #    rotate‌شده بهش نشون داده بشه.
            if os.path.exists(self.LOCK_FILE):
                os.remove(self.LOCK_FILE)

            self.rotate_recovery_key()

            state["recovery_shown"] = False
            self.save_state(state)

            return password, "success"

        # تشخیص عقب رفتن ساعت (feature قبلی، دست‌نخورده)
        now = self.safe_time(state)
        if now is None:
            return None, "Warning: system clock was rolled back"

        # تشخیص جلو رفتن ساعت + تصمیم فاز قفل (temp vs master)
        remaining, tampered = self.get_remaining_time_safe()

        try:
            if remaining > 0:
                temp_key = bytes.fromhex(state["active_temp_key"])
                dek = self.unwrap_key(
                    temp_key, bytes.fromhex(data["temp_nonce"]), bytes.fromhex(data["temp_wrapped"])
                )
            else:
                dek = self.unwrap_key(
                    master_key, bytes.fromhex(data["master_nonce"]), bytes.fromhex(data["master_wrapped"])
                )
        except Exception:
            return None, "Key decryption failed"

        password = self.decrypt_password(
            dek, bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"])
        )
        return password, "success"