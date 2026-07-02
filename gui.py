# gui.py
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import time
import json
import os
from core import TimeLockCore
from countdown import CountdownManager

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class TimeLockGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Time Lock")
        self.geometry("800x650")
        self.resizable(False, False)

        self.core = TimeLockCore()
        self.countdown_manager = CountdownManager(self)

        self.current_password = None
        self.unlock_time = None
        self.pending_duration = None
        self.countdown_started = False

        # FIX (مشکل ۴): به‌جای همیشه رفتن به Home Screen، اول چک می‌کنیم
        # آیا یک لاک فعال از اجرای قبلی برنامه روی دیسک باقی مونده یا نه.
        self.resume_or_start()

    def resume_or_start(self):
        """
        FIX (مشکل ۴): وضعیت رو از روی فایل‌های روی دیسک (lock.json) بازیابی
        می‌کنه، نه از متغیرهای حافظه‌ای که با بستن برنامه از بین می‌رن.
        """
        if os.path.exists(self.core.LOCK_FILE):
            remaining, _tampered = self.core.get_remaining_time_safe()
            if remaining > 0:
                self.countdown_started = True
                self.countdown_manager.start(self.show_final_unlock)
            else:
                self.show_final_unlock()
        else:
            self.create_home_screen()

    def create_home_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

        self.countdown_started = False
        self.pending_duration = None

        title = ctk.CTkLabel(self, text="Time Lock", font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(pady=30)

        ctk.CTkLabel(self, text="Select lock duration:", font=ctk.CTkFont(size=18)).pack(pady=10)

        self.time_var = tk.StringVar(value="")

        options = [
            ("30 minutes", "30"),
            ("2 hours", "120"),
            ("6 hours", "360"),
            ("1 day", "1440"),
        ]

        for text, minutes in options:
            ctk.CTkRadioButton(self, text=text, variable=self.time_var, value=minutes).pack(pady=8)

        custom_frame = ctk.CTkFrame(self)
        custom_frame.pack(pady=15)
        ctk.CTkLabel(custom_frame, text="Custom time (minutes):").pack(side="left", padx=10)
        self.custom_entry = ctk.CTkEntry(custom_frame, width=100, placeholder_text="e.g. 45")
        self.custom_entry.pack(side="left", padx=10)

        ctk.CTkButton(self, text="Start New Lock", font=ctk.CTkFont(size=16), height=50,
                     command=self.start_new_lock).pack(pady=30)

        ctk.CTkButton(self, text="Force Recovery", fg_color="red",
                     command=self.show_recovery_input).pack(pady=10)

        ctk.CTkButton(self, text="Generate New Recovery Key", fg_color="orange",
                     command=self.generate_new_recovery).pack(pady=10)

    def start_new_lock(self):
        """
        FIX (مشکل شمارش زودهنگام): این تابع دیگه core.create_new_lock رو
        صدا نمی‌زنه (چون اون کار unlock_time رو زودتر از موعد ثابت می‌کرد).
        فقط رمز رو برای نمایش تولید می‌کنه و duration انتخابی رو نگه می‌داره.
        قفل واقعی وقتی ساخته می‌شه که کاربر دکمه‌ی سبز رو بزنه.
        """
        try:
            if self.custom_entry.get().strip():
                minutes = int(self.custom_entry.get())
            elif self.time_var.get():
                minutes = int(self.time_var.get())
            else:
                messagebox.showerror("Error", "Please select or enter a time")
                return
            duration = minutes * 60
        except Exception:
            messagebox.showerror("Error", "Please enter a valid time")
            return

        self.pending_duration = duration
        self.current_password = self.core.generate_strong_password()
        self.unlock_time = None
        self.show_password_screen()

    def show_password_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self, text="Password Generated!", font=ctk.CTkFont(size=22)).pack(pady=20)

        frame = ctk.CTkFrame(self)
        frame.pack(pady=20, padx=50, fill="x")

        self.pass_label = ctk.CTkLabel(frame, text=self.current_password, font=ctk.CTkFont(size=24, weight="bold"))
        self.pass_label.pack(pady=30)

        ctk.CTkButton(self, text="Copy Password", command=self.copy_password).pack(pady=10)

        # فقط این دکمه شمارش رو شروع می‌کنه
        ctk.CTkButton(self, text="I have set it on my phone - Start Countdown", fg_color="green",
                     command=self.start_countdown).pack(pady=20)

        ctk.CTkButton(self, text="Force Recovery", fg_color="red",
                     command=self.show_recovery_input).pack(pady=10)

    def copy_password(self):
        self.clipboard_clear()
        self.clipboard_append(self.current_password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def start_countdown(self):
        """
        FIX (مشکل شمارش زودهنگام): قفل واقعی (و در نتیجه unlock_time /
        duration_seconds / created_wall / created_mono در core) دقیقاً
        همین‌جا، لحظه‌ی کلیک روی دکمه‌ی سبز، ساخته می‌شه.

        رمزی که قبلاً تولید و نشون داده شده بود (self.current_password)
        دوباره به create_new_lock پاس داده می‌شه تا رمز نمایش‌داده‌شده و
        رمز رمزنگاری‌شده دقیقاً یکی باشن.
        """
        if self.countdown_started or self.pending_duration is None:
            return
        self.countdown_started = True
        self.current_password, self.unlock_time = self.core.create_new_lock(
            self.pending_duration, password=self.current_password
        )
        self.countdown_manager.start(self.show_final_unlock)

    def show_final_unlock(self, password=None):
        """
        FIX (مشکل ۱): اگه password پاس داده نشه، رمز از core.unlock_password()
        (رمزگشایی واقعی از روی lock.json) گرفته می‌شه — همون مسیر پایان
        عادی شمارش.

        اگه password از قبل پاس داده شده باشه (مثلاً از مسیر Force Recovery
        که رمز رو همون لحظه گرفته)، دوباره unlock_password صدا زده نمی‌شه؛
        چون اون لحظه دیگه قفلی روی دیسک وجود نداره (حذف شده) و صدا زدن
        دوباره باعث خطای «لاک فعالی وجود ندارد» می‌شد.
        """
        if password is None:
            password, status = self.core.unlock_password()
            if not password:
                messagebox.showerror("خطا", status)
                self.create_home_screen()
                return

        self.current_password = password

        for widget in self.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self, text="Time is Up!", font=ctk.CTkFont(size=26, weight="bold")).pack(pady=30)

        ctk.CTkLabel(self, text="Your Phone Password:", font=ctk.CTkFont(size=18)).pack(pady=10)

        ctk.CTkLabel(self, text=self.current_password, font=ctk.CTkFont(size=28, weight="bold")).pack(pady=20)

        ctk.CTkButton(self, text="Copy Password", command=self.copy_password).pack(pady=10)
        ctk.CTkButton(self, text="Back to Home", command=self.create_home_screen).pack(pady=10)

    def show_recovery_input(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Force Recovery")
        dialog.geometry("600x250")
        dialog.attributes('-topmost', True)

        ctk.CTkLabel(dialog, text="Enter Recovery Key (hex):", font=ctk.CTkFont(size=16)).pack(pady=10)

        entry = ctk.CTkEntry(dialog, width=500, height=40, font=ctk.CTkFont(size=14))
        entry.pack(pady=10, padx=20)
        entry.focus()

        def submit():
            recovery_input = entry.get().strip()
            dialog.destroy()
            if recovery_input:
                password, status = self.core.unlock_password(force_recovery=True, recovery_key_input=recovery_input)
                if password:
                    # FIX: شمارش رو همین‌جا، قبل از هر رویداد دیگه‌ای (مثل
                    # messagebox یا برگشت به mainloop) متوقف می‌کنیم. اگه
                    # این تیک از شمارش که قبلاً زمان‌بندی شده اجازه پیدا
                    # کنه اجرا بشه، چون lock.json دیگه وجود نداره، یه
                    # پنجره‌ی خطای اضافه‌ی «لاک فعالی وجود ندارد» باز می‌کرد.
                    self.countdown_manager.stop()
                    self.countdown_started = False
                    self.pending_duration = None
                    # به‌جای پاپ‌آپ، مستقیم می‌ریم به صفحه‌ی نهایی نمایش رمز
                    # (همون صفحه‌ای که در پایان عادی شمارش هم نشون داده می‌شه)
                    self.show_final_unlock(password=password)
                else:
                    messagebox.showerror("Error", status)

        ctk.CTkButton(dialog, text="Unlock", height=40, command=submit).pack(pady=10)
        dialog.bind("<Return>", lambda e: submit())

    def generate_new_recovery(self):
        """
        منطق جدید (تکراری‌شونده):
        - این دکمه فقط کلید recovery *فعلی* رو نشون می‌ده، خودش کلید
          جدید نمی‌سازه (rotate کردن فقط بعد از مصرف یک کلید، در
          core.unlock_password، به‌صورت خودکار انجام می‌شه).
        - تا وقتی کلید فعلی نشون داده شده و هنوز استفاده نشده باشه
          (state["recovery_shown"] == True)، این دکمه دوباره چیزی نشون
          نمی‌ده.
        - وقتی کلید از طریق Force Recovery مصرف بشه، state["recovery_shown"]
          خودکار False می‌شه و کلید تازه (که همون‌جا rotate شده) دوباره
          با همین دکمه قابل مشاهده می‌شه.
        """
        state = self.core.load_state()
        if state.get("recovery_shown", False):
            messagebox.showinfo(
                "Info",
                "Recovery Key قبلاً نمایش داده شده و هنوز معتبره.\n"
                "بعد از این‌که در یک شرایط اضطراری استفاده بشه، دفعه‌ی بعد "
                "می‌تونید کلید تازه رو با همین دکمه ببینید."
            )
            return

        recovery_key = self.core.get_recovery_key()
        recovery_hex = recovery_key.hex()

        dialog = ctk.CTkToplevel(self)
        dialog.title("New Recovery Key")
        dialog.geometry("700x300")
        dialog.attributes('-topmost', True)

        ctk.CTkLabel(dialog, text="New Recovery Key (Save it securely!)", font=ctk.CTkFont(size=16)).pack(pady=10)

        key_frame = ctk.CTkFrame(dialog)
        key_frame.pack(pady=10, padx=20, fill="x")

        key_label = ctk.CTkLabel(key_frame, text=recovery_hex, font=ctk.CTkFont(size=14))
        key_label.pack(pady=10)

        ctk.CTkButton(dialog, text="Copy Key", command=lambda: self.copy_to_clipboard(recovery_hex, dialog)).pack(pady=10)
        ctk.CTkButton(dialog, text="Close", command=dialog.destroy).pack(pady=10)

        state["recovery_shown"] = True
        self.core.save_state(state)

    def copy_to_clipboard(self, text, dialog=None):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Copied to clipboard!")
        if dialog:
            dialog.destroy()


if __name__ == "__main__":
    app = TimeLockGUI()
    app.mainloop()