# test_core.py
from Linusand import TimeLockCore
import time

core = TimeLockCore()

print("=== تست TimeLockCore ===")

# تست ۱: ساخت لاک جدید
print("\n1. ساخت لاک جدید (۳۰ ثانیه)...")
password, unlock_time = core.create_new_lock(30)
print(f"رمز تولید شده: {password}")
print(f"زمان باز شدن: {time.ctime(unlock_time)}")

# تست ۲: چک کردن زمان باقی‌مانده
print("\n2. زمان باقی‌مانده:", int(core.get_remaining_time()), "ثانیه")

# صبر برای تست
print("\nچند ثانیه صبر می‌کنیم...")
time.sleep(5)

print("زمان باقی‌مانده:", int(core.get_remaining_time()), "ثانیه")

# تست ۳: باز کردن رمز (بعد از زمان)
if core.is_time_up():
    password, status = core.unlock_password()
    print(f"رمز بازیابی شد: {password}")
else:
    print("زمان هنوز نرسیده")

print("\nتست تمام شد.")