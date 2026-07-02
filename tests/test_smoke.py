"""
Not a full test suite yet (that's a later step) -- this is a smoke
test to prove the refactor didn't silently break behavior, and to
codify the exact regression v1's own comments warned about: hand-
editing trusted_elapsed must be rejected, not silently trusted.

Run with: python -m tests.test_smoke   (from the timelock_v2/ dir)
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from composition import build_app


def test_create_and_unlock_after_expiry():
    tmp = tempfile.mkdtemp()
    try:
        app = build_app(data_dir=tmp)

        password, unlock_time = app.lock_engine.create_new_lock(duration_seconds=0)
        assert isinstance(password, str) and len(password) == 18

        result = app.lock_engine.get_remaining_time()
        assert result.remaining_seconds == 0
        assert result.tampered is False

        unlocked_password, status = app.lock_engine.unlock()
        assert status == "success"
        assert unlocked_password == password

        assert app.lock_engine.has_active_lock() is False
        print("PASS: create_and_unlock_after_expiry")
    finally:
        shutil.rmtree(tmp)


def test_still_locked_before_expiry():
    tmp = tempfile.mkdtemp()
    try:
        app = build_app(data_dir=tmp)
        app.lock_engine.create_new_lock(duration_seconds=3600)

        result = app.lock_engine.get_remaining_time()
        assert result.remaining_seconds > 3500
        assert result.tampered is False

        password, status = app.lock_engine.unlock()
        assert password is None
        assert "still active" in status
        print("PASS: still_locked_before_expiry")
    finally:
        shutil.rmtree(tmp)


def test_hand_edited_trusted_elapsed_is_rejected():
    """This is the exact bug class v1's _state_hmac fix was written
    for. If this test ever fails, the integrity signature is broken."""
    tmp = tempfile.mkdtemp()
    try:
        app = build_app(data_dir=tmp)
        app.lock_engine.create_new_lock(duration_seconds=3600)

        lock_path = Path(tmp) / "lock.json"
        data = json.loads(lock_path.read_text())
        data["trusted_elapsed"] = 3600.0  # attacker tries to skip to the end
        lock_path.write_text(json.dumps(data))

        result = app.lock_engine.get_remaining_time()
        assert result.tampered is True
        assert result.remaining_seconds > 0  # NOT unlocked early

        password, status = app.lock_engine.unlock()
        assert password is None
        print("PASS: hand_edited_trusted_elapsed_is_rejected")
    finally:
        shutil.rmtree(tmp)


def test_recovery_cooldown_escalates():
    tmp = tempfile.mkdtemp()
    try:
        app = build_app(data_dir=tmp)
        app.lock_engine.create_new_lock(duration_seconds=3600)

        status_before = app.recovery_engine.get_cooldown_status()
        assert status_before.seconds_remaining == 0
        assert status_before.required_ack_count == 1

        recovery_key = app.keyvault.get_or_create_recovery_key()
        password, status = app.recovery_engine.force_unlock(recovery_key.hex())
        assert status == "success"

        # simulate a second lock + second recovery attempt
        app.lock_engine.create_new_lock(duration_seconds=3600)
        status_after = app.recovery_engine.get_cooldown_status()
        assert status_after.seconds_remaining > 0  # now on cooldown
        assert status_after.required_ack_count == 2  # escalated
        print("PASS: recovery_cooldown_escalates")
    finally:
        shutil.rmtree(tmp)


def test_audit_log_chain_is_valid():
    tmp = tempfile.mkdtemp()
    try:
        app = build_app(data_dir=tmp)
        app.lock_engine.create_new_lock(duration_seconds=0)
        app.lock_engine.unlock()

        assert app.logger.verify_chain() is True

        # tamper with one entry and confirm the chain breaks
        log_path = Path(tmp) / "audit.log"
        lines = log_path.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["metadata"] = {"duration_seconds": 999999}
        lines[0] = json.dumps(entry)
        log_path.write_text("\n".join(lines) + "\n")

        assert app.logger.verify_chain() is False
        print("PASS: audit_log_chain_is_valid")
    finally:
        shutil.rmtree(tmp)


def test_external_deletion_leaves_tamper_evidence():
    tmp = tempfile.mkdtemp()
    try:
        app = build_app(data_dir=tmp)
        app.lock_engine.create_new_lock(duration_seconds=3600)

        # Simulate someone deleting the whole data folder to silently
        # cancel the countdown, outside the app.
        lock_path = Path(tmp) / "lock.json"
        lock_path.unlink()

        if app.keyvault.get_active_lock_marker() is None:
            print("SKIP: external_deletion_leaves_tamper_evidence (no keyring backend available in this environment)")
            return

        assert app.lock_engine.check_tamper_evidence() is True
        app.lock_engine.clear_tamper_evidence()
        assert app.lock_engine.check_tamper_evidence() is False
        print("PASS: external_deletion_leaves_tamper_evidence")
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    test_create_and_unlock_after_expiry()
    test_still_locked_before_expiry()
    test_hand_edited_trusted_elapsed_is_rejected()
    test_recovery_cooldown_escalates()
    test_audit_log_chain_is_valid()
    test_external_deletion_leaves_tamper_evidence()
    print("\nAll smoke tests passed.")
