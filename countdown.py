# countdown.py
"""
Ported from v1's CountdownManager. Behavior is unchanged -- still
polls every tick rather than trusting a locally-computed unlock_time
-- but it now reads through lock_engine.get_remaining_time() instead
of a bespoke get_remaining_time_safe() tuple, since that's the new
core's API shape (RemainingTimeResult, not a tuple).
"""
import customtkinter as ctk


class CountdownManager:
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

        result = self.gui.app.lock_engine.get_remaining_time()

        if self.tamper_label is not None:
            if result.tampered:
                self.tamper_label.configure(text="⚠ System clock tampering detected")
            else:
                self.tamper_label.configure(text="")

        if result.remaining_seconds <= 0:
            self.finish()
            return

        mins, secs = divmod(int(result.remaining_seconds), 60)
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
        self.is_running = False
        if self.count_job:
            self.gui.after_cancel(self.count_job)
            self.count_job = None
