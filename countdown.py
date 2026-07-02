# countdown.py
import customtkinter as ctk


class CountdownManager:
    """
    FIX (مشکل ۲ و ۴): این نسخه دیگه unlock_time رو جدا نگه نمی‌داره و
    خودش با time.time() محاسبه نمی‌کنه. به‌جاش هر tick مستقیم از
    core.get_remaining_time_safe() می‌پرسه که چقدر زمان مونده.

    این یعنی:
    - اگه ساعت سیستم دستکاری بشه، core خودش تشخیص می‌ده (مقاوم‌سازی مشکل ۲)
    - اگه برنامه بسته و دوباره باز بشه، کافیه countdown دوباره start بشه؛
      چون منبع حقیقت (lock.json) روی دیسکه، نه متغیر حافظه (مشکل ۴)
    """

    def __init__(self, gui_app):
        self.gui = gui_app
        self.count_label = None
        self.tamper_label = None
        self.count_job = None
        self.is_running = False
        self.on_finish = None

    def start(self, on_finish_callback):
        if self.is_running:
            return
        self.is_running = True
        self.on_finish = on_finish_callback
        self.show_countdown_ui()
        self.gui.after(200, self.update_countdown)

    def show_countdown_ui(self):
        for widget in self.gui.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self.gui, text="Lock is Active", font=ctk.CTkFont(size=24)).pack(pady=30)

        self.count_label = ctk.CTkLabel(self.gui, text="", font=ctk.CTkFont(size=32))
        self.count_label.pack(pady=20)

        self.tamper_label = ctk.CTkLabel(
            self.gui, text="", font=ctk.CTkFont(size=13), text_color="orange"
        )
        self.tamper_label.pack(pady=5)

        ctk.CTkButton(
            self.gui, text="Force Recovery", fg_color="red",
            command=self.gui.show_recovery_input
        ).pack(pady=20)

    def update_countdown(self):
        if not self.is_running:
            return

        remaining, tampered = self.gui.core.get_remaining_time_safe()

        if self.tamper_label is not None:
            if tampered:
                self.tamper_label.configure(text="⚠ System clock tampering detected")
            else:
                self.tamper_label.configure(text="")

        if remaining <= 0:
            self.finish()
            return

        mins, secs = divmod(int(remaining), 60)
        if self.count_label is not None:
            self.count_label.configure(text=f"{mins:02d}:{secs:02d}")

        self.count_job = self.gui.after(1000, self.update_countdown)

    def finish(self):
        self.is_running = False
        if self.count_job:
            self.gui.after_cancel(self.count_job)
            self.count_job = None
        if self.on_finish:
            self.on_finish()

    def stop(self):
        """
        متوقف کردن شمارش بدون صدا زدن on_finish. برای وقتی استفاده می‌شه
        که رمز از مسیر دیگه‌ای (مثل Force Recovery) به‌دست اومده و دیگه
        نیازی به نمایش صفحه‌ی «Time is Up» نیست.
        امن است حتی اگه شمارش در حال اجرا نباشه.
        """
        self.is_running = False
        if self.count_job:
            self.gui.after_cancel(self.count_job)
            self.count_job = None