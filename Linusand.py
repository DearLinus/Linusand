import os
import json
import time
import secrets
import pyperclip
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

STATE_FILE = "state.json"
LOCK_FILE = "lock.json"
MASTER_KEY_FILE = "master.key"
RECOVERY_KEY_FILE = "recovery.key"

def generate_strong_password(length=18):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def load_master_key():
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            return f.read()
    key = AESGCM.generate_key(bit_length=256)
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(MASTER_KEY_FILE, 0o600)
    return key

def create_new_recovery_key():
    key = AESGCM.generate_key(bit_length=256)
    with open(RECOVERY_KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(RECOVERY_KEY_FILE, 0o600)
    print("\n" + "="*70)
    print("🛡️ RECOVERY KEY جدید (فقط یک بار نمایش)")
    print("="*70)
    print(key.hex())
    print("="*70)
    print("⚠️ این کلید را در جای امن ذخیره کنید!")
    input("\nEnter بزنید...")
    return key

def get_recovery_key():
    if not os.path.exists(RECOVERY_KEY_FILE):
        return create_new_recovery_key()
    with open(RECOVERY_KEY_FILE, "rb") as f:
        return f.read()

def load_state():
    if not os.path.exists(STATE_FILE):
        return {"last_seen": time.time(), "temp_version": 0, "active_temp_key": None}
    with open(STATE_FILE, "r") as f:
        state = json.load(f)
    state.setdefault("temp_version", 0)
    state.setdefault("active_temp_key", None)
    return state

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)

def safe_time(state):
    now = time.time()
    if now < state.get("last_seen", 0) - 15:
        print("⚠️  هشدار: زمان سیستم دستکاری شده!")
        return None
    state["last_seen"] = now
    save_state(state)
    return now

def encrypt_password(dek, password):
    aes = AESGCM(dek)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, password.encode('utf-8'), None)
    return nonce, ct

def decrypt_password(dek, nonce, ct):
    aes = AESGCM(dek)
    return aes.decrypt(nonce, ct, None).decode('utf-8')

def wrap_key(wrapping_key, key_to_wrap):
    aes = AESGCM(wrapping_key)
    nonce = os.urandom(12)
    return nonce, aes.encrypt(nonce, key_to_wrap, None)

def unwrap_key(wrapping_key, nonce, wrapped):
    aes = AESGCM(wrapping_key)
    return aes.decrypt(nonce, wrapped, None)

def create_new_lock():
    master_key = load_master_key()
    recovery_key = get_recovery_key()
    state = load_state()

    print("\nمدت زمان قفل:")
    print("1. ۳۰ دقیقه   2. ۲ ساعت   3. ۶ ساعت   4. ۱ روز   5. دلخواه")
    choice = input("انتخاب (1-5): ").strip()
    durations = {"1": 1800, "2": 7200, "3": 21600, "4": 86400}
    duration = durations.get(choice, int(input("تعداد ثانیه: ") or 1800))

    state["temp_version"] = state.get("temp_version", 0) + 1
    temp_key = AESGCM.generate_key(bit_length=256)
    state["active_temp_key"] = temp_key.hex()
    save_state(state)

    password = generate_strong_password(18)
    unlock_time = time.time() + duration
    dek = AESGCM.generate_key(bit_length=256)

    nonce, ciphertext = encrypt_password(dek, password)
    m_nonce, m_wrapped = wrap_key(master_key, dek)
    t_nonce, t_wrapped = wrap_key(temp_key, dek)
    r_nonce, r_wrapped = wrap_key(recovery_key, dek)

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

    with open(LOCK_FILE, "w") as f:
        json.dump(lock_data, f, indent=4)

    print(f"\n✅ رمز: {password}")
    print(f"⏰ باز شدن: {datetime.fromtimestamp(unlock_time).strftime('%H:%M:%S')}")
    return password, unlock_time

def unlock_password(force_recovery=False):
    if not os.path.exists(LOCK_FILE):
        print("❌ لاک فعالی وجود ندارد.")
        return

    master_key = load_master_key()
    state = load_state()
    now = safe_time(state)
    if now is None:
        return

    with open(LOCK_FILE) as f:
        data = json.load(f)

    if force_recovery:
        print("🛡️ Force Recovery Mode")
        print("Recovery Key خود را (hex) وارد کنید:")
        user_input = input("Recovery Key: ").strip()
        
        try:
            recovery_key = bytes.fromhex(user_input)
        except:
            print("❌ فرمت Recovery Key اشتباه است.")
            return

        try:
            dek = unwrap_key(recovery_key, bytes.fromhex(data["recovery_nonce"]), bytes.fromhex(data["recovery_wrapped"]))
            print("✅ Recovery Key درست بود")
            
            # ساخت Recovery Key جدید
            new_recovery_key = create_new_recovery_key()
            r_nonce, r_wrapped = wrap_key(new_recovery_key, dek)
            data["recovery_nonce"] = r_nonce.hex()
            data["recovery_wrapped"] = r_wrapped.hex()
            with open(LOCK_FILE, "w") as f:
                json.dump(data, f, indent=4)
            
        except:
            print("❌ Recovery Key اشتباه است.")
            return
    elif data["unlock_time"] - now > 0:
        print("⚠️ هنوز زمان نرسیده!")
        confirm = input("آیا مطمئن هستید؟ (y/N): ")
        if confirm.lower() != 'y':
            return
        temp_key = bytes.fromhex(state["active_temp_key"])
        dek = unwrap_key(temp_key, bytes.fromhex(data["temp_nonce"]), bytes.fromhex(data["temp_wrapped"]))
    else:
        dek = unwrap_key(master_key, bytes.fromhex(data["master_nonce"]), bytes.fromhex(data["master_wrapped"]))

    password = decrypt_password(dek, bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"]))
    print(f"\n🔓 رمز شما:\n{password}")
    return password

if __name__ == "__main__":
    print("=== Time Lock Password ===\n")

    if os.path.exists(LOCK_FILE):
        choice = input("(n) جدید | (u) آنلاک | (r) Force Recovery: ").strip().lower()
        if choice == 'r':
            unlock_password(force_recovery=True)
        elif choice == 'u':
            unlock_password()
        else:
            create_new_lock()
    else:
        create_new_lock()