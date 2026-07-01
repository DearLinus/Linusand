# countdown.py
import time
import customtkinter as ctk

class CountdownManager:
    def __init__(self, gui_app):
        self.gui = gui_app
        self.count_label = None
        self.count_job = None
        self.is_running = False

    def start(self, unlock_time, on_finish_callback):
        if self.is_running:
            return
        self.is_running = True
        self.unlock_time = unlock_time
        self.on_finish = on_finish_callback
        self.show_countdown_ui()
        # شمارش رو با تأخیر شروع کن
        self.gui.after(500, self.update_countdown)  # تأخیر ۰.۵ ثانیه

    def show_countdown_ui(self):
        for widget in self.gui.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self.gui, text="Lock is Active", font=ctk.CTkFont(size=24)).pack(pady=30)

        self.count_label = ctk.CTkLabel(self.gui, text="", font=ctk.CTkFont(size=32))
        self.count_label.pack(pady=40)

        ctk.CTkButton(self.gui, text="Force Recovery", fg_color="red", 
                     command=self.gui.show_recovery_input).pack(pady=20)

    def update_countdown(self):
        if not self.is_running:
            return

        remaining = self.unlock_time - time.time()
        if remaining <= 0:
            self.finish()
            return

        mins, secs = divmod(int(remaining), 60)
        self.count_label.configure(text=f"{mins:02d}:{secs:02d}")

        self.count_job = self.gui.after(1000, self.update_countdown)

    def finish(self):
        self.is_running = False
        if self.count_job:
            self.gui.after_cancel(self.count_job)
        if self.on_finish:
            self.on_finish()