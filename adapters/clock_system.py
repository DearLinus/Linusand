from __future__ import annotations

import time

from core.interfaces import IClock


class SystemClock(IClock):
    def now_wall(self) -> float:
        return time.time()

    def now_monotonic(self) -> float:
        return time.monotonic()
