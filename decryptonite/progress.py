"""Minimal dependency-free progress bar with percentage and ETA.

Renders to ``stderr`` so it never pollutes ``stdout`` (keeps ``--json`` output
clean) and stays silent when ``stderr`` is not a TTY unless forced.
"""

from __future__ import annotations

import sys
import time
from typing import TextIO


def _fmt_eta(seconds: float) -> str:
    if seconds < 0 or seconds != seconds:  # negative or NaN
        return "--:--"
    seconds = int(seconds)
    if seconds >= 3600:
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h:d}:{m:02d}:{s:02d}"
    m, s = divmod(seconds, 60)
    return f"{m:02d}:{s:02d}"


class ProgressBar:
    """A single-line, self-updating progress bar.

    Usage::

        bar = ProgressBar(total, label="judging")
        for item in items:
            ...
            bar.advance()
        bar.close()
    """

    def __init__(
        self,
        total: int,
        label: str = "",
        width: int = 26,
        stream: "TextIO | None" = None,
        enabled: "bool | None" = None,
    ) -> None:
        self.total = max(total, 0)
        self.label = label
        self.width = width
        self.stream = stream or sys.stderr
        if enabled is None:
            enabled = self.stream.isatty()
        self.enabled = enabled and self.total > 0
        self.current = 0
        self._start = time.monotonic()
        self._last_render = 0.0
        if self.enabled:
            self._render(force=True)

    def advance(self, step: int = 1) -> None:
        self.current = min(self.current + step, self.total)
        self._render()

    def _render(self, force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        # throttle to ~20 fps unless finished or forced
        if not force and self.current < self.total and now - self._last_render < 0.05:
            return
        self._last_render = now

        frac = self.current / self.total if self.total else 1.0
        filled = int(round(frac * self.width))
        bar = "█" * filled + "░" * (self.width - filled)

        elapsed = now - self._start
        rate = self.current / elapsed if elapsed > 0 and self.current else 0.0
        remaining = (self.total - self.current) / rate if rate > 0 else -1.0
        eta = _fmt_eta(remaining)

        prefix = f"{self.label} " if self.label else ""
        line = (
            f"\r{prefix}[{bar}] {frac * 100:5.1f}%  "
            f"{self.current}/{self.total}  ETA {eta}"
        )
        self.stream.write(line)
        self.stream.flush()

    def close(self) -> None:
        if not self.enabled:
            return
        self.current = self.total
        self._render(force=True)
        self.stream.write("\n")
        self.stream.flush()

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
