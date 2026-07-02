# gui.py
"""
Ported from v1's gui.py. The UI flow and widget layout are unchanged
-- what changed is that every call into the security core now goes
through `self.app` (built by composition.build_app()) instead of a
single TimeLockCore object. Concretely:

  self.core.get_remaining_time_safe() -> tuple
    becomes
  self.app.lock_engine.get_remaining_time() -> RemainingTimeResult

  self.core.unlock_password(force_recovery=True, recovery_key_input=x)
    becomes
  self.app.recovery_engine.force_unlock(x)

GUI still contains zero crypto/HMAC/file logic itself -- it only ever
calls into self.app and renders whatever comes back, same as v1's
actual practice (this part of v1 was already right, so it's preserved
as-is, just repointed at the new engines).
"""
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import time
import socket
import sys

from composition import build_app
from core.recovery_engine import RECOVERY_ACK_PHRASE
from countdown import CountdownManager

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Single-instance guard -- unchanged from v1.
_SINGLE_INSTANCE_PORT = 47285


def _acquire_single_instance_lock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", _SINGLE_INSTANCE_PORT))
        sock.listen(1)
        return sock
    except OSError:
        return None


class TimeLockGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Time Lock")
        self.geometry("800x650")
        self.resizable(False, False)

        # Composition root builds and wires all adapters + engines.
        # This is the ONLY place the GUI touches concrete adapters --
        # everywhere else it talks to self.app.lock_engine /
        # self.app.recovery_engine.
        self.app = build_app()
        self.countdown_manager = CountdownManager(self)

        self.current_password = None
        self.unlock_time = None
        self.pending_duration = None
        self.countdown_started = False

        self.resume_or_start()

    def resume_or_start(self):
        warnings = self.app.security_warnings()
        if warnings:
            messagebox.showwarning("Security Warning", "\n\n".join(warnings))

        if self.app.check_lock_tamper_evidence():
            messagebox.showwarning(
                "Warning",
                "A previous lock appears to have been deleted manually "
                "(outside the app) before it finished."
            )
            self.app.clear_lock_tamper_evidence()

        if self.app.lock_engine.has_active_lock():
            result = self.app.lock_engine.get_remaining_time()
            if result.remaining_seconds > 0:
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
        self._last_radio_value = ""

        options = [
            ("30 minutes", "30"),
            ("2 hours", "120"),
            ("6 hours", "360"),
            ("1 day", "1440"),
        ]

        for text, minutes in options:
            ctk.CTkRadioButton(
                self, text=text, variable=self.time_var, value=minutes,
                command=lambda v=minutes: self._on_time_radio_click(v),
            ).pack(pady=8)

        custom_frame = ctk.CTkFrame(self)
        custom_frame.pack(pady=15)
        ctk.CTkLabel(custom_frame, text="Custom time (minutes):").pack(side="left", padx=10)
        self.custom_entry = ctk.CTkEntry(custom_frame, width=100, placeholder_text="e.g. 45")
        self.custom_entry.pack(side="left", padx=10)

        ctk.CTkButton(self, text="Start New Lock", font=ctk.CTkFont(size=16), height=50,
                     command=self.start_new_lock).pack(pady=30)

        ctk.CTkButton(self, text="Generate New Recovery Key", fg_color="orange",
                     command=self.generate_new_recovery).pack(pady=10)

    def _on_time_radio_click(self, value):
        if self._last_radio_value == value:
            self.time_var.set("")
            self._last_radio_value = ""
        else:
            self._last_radio_value = value

    def start_new_lock(self):
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
        self.current_password = self.app.lock_engine.generate_strong_password()
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

        # Deliberately no "Copy Password" button here -- same reasoning
        # as v1: clipboard history would defeat the point of the lock.
        ctk.CTkLabel(
            self, text="Type this into your phone's lock screen now.",
            font=ctk.CTkFont(size=13), text_color="gray70",
        ).pack(pady=(0, 10))

        ctk.CTkButton(self, text="I have set it on my phone - Start Countdown", fg_color="green",
                     command=self.start_countdown).pack(pady=20)

        ctk.CTkButton(self, text="Back", command=self.create_home_screen).pack(pady=10)

    def copy_password(self):
        self.clipboard_clear()
        self.clipboard_append(self.current_password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def start_countdown(self):
        if self.countdown_started or self.pending_duration is None:
            return
        self.countdown_started = True
        self.current_password, self.unlock_time = self.app.lock_engine.create_new_lock(
            self.pending_duration, password=self.current_password
        )
        self.countdown_manager.start(self.show_final_unlock)

    def show_final_unlock(self, password=None):
        if password is None:
            password, status = self.app.lock_engine.unlock()
            if not password:
                messagebox.showerror("Error", status)
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
        status = self.app.recovery_engine.get_cooldown_status()

        if status.seconds_remaining > 0:
            self._show_recovery_cooldown_screen(status.seconds_remaining, status.history)
        else:
            self._show_recovery_acknowledgment_screen(status.required_ack_count, status.history)

    def _show_recovery_cooldown_screen(self, remaining, history):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Force Recovery - On Cooldown")
        dialog.geometry("520x320")
        dialog.attributes('-topmost', True)

        ctk.CTkLabel(
            dialog, text="Force Recovery isn't available yet",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(20, 10))

        mins, secs = divmod(int(remaining), 60)
        hrs, mins = divmod(mins, 60)
        time_str = f"{hrs}h {mins:02d}m {secs:02d}s" if hrs else f"{mins}m {secs:02d}s"

        ctk.CTkLabel(
            dialog,
            text=f"Available again in: {time_str}",
            font=ctk.CTkFont(size=16),
            text_color="orange",
        ).pack(pady=10)

        ctk.CTkLabel(
            dialog,
            text=f"You've used early recovery {len(history)} time(s) before.\n"
                 "Each use makes the next wait longer.",
            font=ctk.CTkFont(size=13),
            justify="center",
        ).pack(pady=15)

        ctk.CTkButton(dialog, text="Close", command=dialog.destroy).pack(pady=15)

    def _show_recovery_acknowledgment_screen(self, required_acks, history):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Force Recovery")
        dialog.geometry("620x480")
        dialog.attributes('-topmost', True)

        ctk.CTkLabel(
            dialog, text="Before you continue",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(20, 5))

        if history:
            recent = history[-3:]
            lines = [
                time.strftime("%b %d, %H:%M", time.localtime(h["ts"]))
                for h in recent
            ]
            hist_text = "Previous early unlocks: " + ", ".join(lines)
            ctk.CTkLabel(
                dialog, text=hist_text, font=ctk.CTkFont(size=12),
                text_color="gray70", justify="center", wraplength=560,
            ).pack(pady=(0, 10))

        phrase = RECOVERY_ACK_PHRASE
        ctk.CTkLabel(
            dialog,
            text=f'Type the following phrase exactly, {required_acks} time'
                 f'{"s" if required_acks != 1 else ""} in a row, to continue:',
            font=ctk.CTkFont(size=14),
            wraplength=560, justify="center",
        ).pack(pady=(5, 5))

        ctk.CTkLabel(
            dialog, text=f'"{phrase}"',
            font=ctk.CTkFont(size=14, weight="bold", slant="italic"),
            wraplength=560, justify="center",
        ).pack(pady=(0, 15))

        progress_label = ctk.CTkLabel(dialog, text=f"0 / {required_acks}", font=ctk.CTkFont(size=13))
        progress_label.pack(pady=(0, 5))

        ack_entry = ctk.CTkEntry(dialog, width=560, height=36)
        ack_entry.pack(pady=5, padx=20)

        def _block_paste(event=None):
            return "break"

        ack_entry.bind("<<Paste>>", _block_paste)
        ack_entry.bind("<Control-v>", _block_paste)
        ack_entry.bind("<Control-V>", _block_paste)
        ack_entry.bind("<Button-2>", _block_paste)

        state = {"count": 0}

        def check_ack(event=None):
            typed = ack_entry.get().strip()
            ack_entry.delete(0, "end")
            if typed == phrase:
                state["count"] += 1
                progress_label.configure(text=f"{state['count']} / {required_acks}")
                if state["count"] >= required_acks:
                    dialog.destroy()
                    self._show_recovery_key_form()
            else:
                state["count"] = 0
                progress_label.configure(text=f"0 / {required_acks} (didn't match, try again)")

        ack_entry.bind("<Return>", check_ack)
        ack_entry.focus()

        ctk.CTkButton(dialog, text="Cancel", fg_color="gray40", command=dialog.destroy).pack(pady=20)

    def _show_recovery_key_form(self):
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
                password, status = self.app.recovery_engine.force_unlock(recovery_input)
                if password:
                    # Stop the countdown before anything else can run
                    # against a lock that no longer represents an
                    # active lock -- same reasoning as v1.
                    self.countdown_manager.stop()
                    self.countdown_started = False
                    self.pending_duration = None
                    self.show_final_unlock(password=password)
                else:
                    messagebox.showerror("Error", status)

        ctk.CTkButton(dialog, text="Unlock", height=40, command=submit).pack(pady=10)
        dialog.bind("<Return>", lambda e: submit())

    def generate_new_recovery(self):
        state = self.app.load_state()
        if state.get("recovery_shown", False):
            messagebox.showinfo(
                "Info",
                "This recovery key is still valid.\n"
                "A new one will appear here after it's used."
            )
            return

        recovery_key = self.app.get_recovery_key()
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
        self.app.save_state(state)

    def copy_to_clipboard(self, text, dialog=None):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Copied to clipboard!")
        if dialog:
            dialog.destroy()


if __name__ == "__main__":
    _lock_socket = _acquire_single_instance_lock()
    if _lock_socket is None:
        sys.exit(0)

    app = TimeLockGUI()
    app.mainloop()
