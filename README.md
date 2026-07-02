# Linusand
# Time Lock

A local desktop app that locks a randomly generated password behind a countdown timer, designed to help you stay off your phone for a set period without relying on willpower alone.

You pick a duration, the app generates a strong password, you set that password as your phone's lock screen password, and the app reveals it back to you only after the timer runs out — or through a deliberately painful emergency-recovery path if you truly need in early.

## Why this exists

Willpower-based self-control tools fail the moment you *decide* to bypass them. This project's actual goal isn't to build an unbreakable vault — it's to make bypassing it annoying enough, and consequential enough, that the path of least resistance is just waiting it out. See [Threat Model](#threat-model) below for what that means concretely.

## Features

- Countdown-gated password reveal, with duration presets or a custom time
- AES-GCM authenticated encryption for the password itself
- Tamper-resistant timing: cross-checks wall-clock time against the OS monotonic clock to detect system-clock manipulation
- Integrity-signed lock state (HMAC over all timing fields) — hand-editing the lock file to skip ahead gets detected and rejected, not silently trusted
- Emergency "Force Recovery" path, gated behind:
  - an escalating cooldown that doubles with each use (capped at 8 hours)
  - a hand-typed (paste-blocked) acknowledgment phrase, repeated more times the more it's been used before
- Recovery-key rotation: a recovery key can only be used once before a new one is required
- OS credential store integration (Windows Credential Manager via `keyring`) for master key, recovery key, and usage history — resistant to a simple "back up the folder, restore it later" bypass
- Resumes correctly across app restarts and, within limits, system reboots

## Architecture

```
gui.py         — CustomTkinter UI, screen flow, user interaction
core.py        — all cryptography, timing logic, and tamper detection
countdown.py   — countdown timer UI + polling loop
```

**Key hierarchy:**

```
password  ->  encrypted with a random DEK (Data Encryption Key)
DEK       ->  wrapped separately with:
                - master key    (used once the timer expires)
                - recovery key  (used for emergency Force Recovery)
```

Both the master key and recovery key live in the OS credential store when `keyring` is available, rather than plaintext files — removing them from a simple folder copy/backup.

**Timing integrity:** every field that determines "how much time is left" (`duration_seconds`, `created_wall`, `created_mono`, `checkpoint_wall`, `checkpoint_mono`, `trusted_elapsed`) is covered by a single HMAC-SHA256 signature keyed with the master key. If any of these are hand-edited on disk, the signature check fails and the app treats the lock as **locked out**, never as unlocked — tampering can only make things worse, never better.

## Threat Model

Stated explicitly, because most projects don't and it matters here:

**This defends against:** the person's own impulsive decision, in the moment, to disable the lock — the "I'll just quickly turn this off" instinct. Every mechanism (clock-tamper detection, integrity-signed state, escalating recovery friction, signed usage history) is built to punish quick, casual bypass attempts and make each subsequent one worse, not better.

**This does not defend against:** a determined attacker with full access to the source code, the Python interpreter, and the local filesystem — which, for a fully local desktop app, is the same person as the owner. Someone willing to read `core.py`, run a debugger, or call `unlock_password()` directly from a script can defeat any of this. That's a fundamental limitation of any purely local, no-server architecture, not a bug — see [Future Directions](#future-directions) for what would actually close that gap.

In short: **friction against yourself, not security against an adversary.** If your use case needs the latter, this isn't there yet.

## Requirements

```
customtkinter
cryptography
keyring          # optional but strongly recommended -- see Threat Model
```

```bash
pip install customtkinter cryptography keyring
```

## Usage

```bash
python gui.py
```

Data (keys, lock state) is stored in:
- Windows: `%LOCALAPPDATA%\TimeLock`
- Linux/macOS: `~/.timelock`

## Future Directions

Ideas under consideration, roughly in order of how much they'd change the threat model versus just the UX:

- **Server-held master key** — the single biggest architectural change available. If the master key never touches the local machine at all (held by a small server component, released only after the timer expires), this stops being "friction against the owner" and becomes actual access control, closing the fundamental gap described above.
- **Mobile companion app** — since the whole point is keeping the phone locked, a native mobile component (rather than a desktop app the user sets the phone's password from) could tie more directly into the phone's own lock mechanism.
- **Telegram bot integration** — for remote status/notifications ("your lock ends in 10 minutes"), or as a lightweight remote-trigger/companion interface without needing a full mobile app.
- **GUI library migration** — CustomTkinter is fine for a single-user desktop tool, but if this grows toward a real product, worth evaluating PySide6/Qt (richer desktop widgets, cross-platform polish) or a web-based frontend (Flask/FastAPI backend + a proper frontend framework) if a server component happens anyway.

## License

*(decide before making the repo public -- see project notes)*
