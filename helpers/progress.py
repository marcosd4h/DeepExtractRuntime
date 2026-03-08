"""Minimal progress feedback for long-running operations.

All output goes to **stderr** so that stdout remains clean for JSON
output (per the workspace JSON output contract).

Usage::

    from helpers.progress import ProgressReporter, progress_iter

    # Class-based (manual control):
    with ProgressReporter(total=1166, label="classify_module") as prog:
        for func in functions:
            classify(func)
            prog.update()

    # Iterator wrapper (automatic):
    for func in progress_iter(functions, label="scan_module"):
        verify(func)

    # One-off status:
    from helpers.progress import status_message
    status_message("Building call graph...")
"""

from __future__ import annotations

import sys
import time
from typing import Iterable, Iterator, Optional, TypeVar

T = TypeVar("T")

_MIN_INTERVAL = 0.5  # seconds between progress updates (avoids spam)


class ProgressReporter:
    """Throttled progress reporter that writes to stderr.

    Parameters
    ----------
    total:
        Total number of items to process.
    label:
        Short label for the operation (shown in output).
    output:
        Writable file object.  Defaults to ``sys.stderr``.
    json_mode:
        When ``True``, emits structured JSON progress lines instead of
        human-readable text.
    enabled:
        Set to ``False`` to create a no-op reporter (useful when callers
        want to conditionally suppress progress).
    """

    def __init__(
        self,
        total: int,
        label: str = "",
        *,
        output=None,
        json_mode: bool = False,
        enabled: bool = True,
    ) -> None:
        self._total = total
        self._label = label
        self._output = output or sys.stderr
        self._json_mode = json_mode
        self._enabled = enabled and total > 0
        self._current = 0
        self._last_emit: float = 0.0
        self._start_time: float = 0.0

    def __enter__(self) -> "ProgressReporter":
        self._start_time = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.finish()

    def update(self, n: int = 1) -> None:
        """Increment progress by *n* items and maybe emit an update."""
        self._current += n
        if not self._enabled:
            return
        now = time.monotonic()
        if now - self._last_emit >= _MIN_INTERVAL or self._current >= self._total:
            self._emit()
            self._last_emit = now

    def finish(self) -> None:
        """Emit a final progress line (with elapsed time)."""
        if not self._enabled:
            return
        elapsed = time.monotonic() - self._start_time if self._start_time else 0
        if self._json_mode:
            import json
            line = json.dumps({
                "progress": {
                    "current": self._current,
                    "total": self._total,
                    "label": self._label,
                    "done": True,
                    "elapsed_s": round(elapsed, 1),
                }
            })
            self._output.write(line + "\n")
        else:
            pct = (self._current * 100 // self._total) if self._total else 100
            self._output.write(
                f"[{self._label}] {self._current}/{self._total} ({pct}%)"
                f" done in {elapsed:.1f}s\n"
            )
        self._output.flush()

    def _emit(self) -> None:
        if self._json_mode:
            import json
            line = json.dumps({
                "progress": {
                    "current": self._current,
                    "total": self._total,
                    "label": self._label,
                }
            })
            self._output.write(line + "\n")
        else:
            pct = (self._current * 100 // self._total) if self._total else 0
            self._output.write(
                f"[{self._label}] {self._current}/{self._total} ({pct}%)\n"
            )
        self._output.flush()


def progress_iter(
    iterable: Iterable[T],
    total: Optional[int] = None,
    label: str = "",
    *,
    json_mode: bool = False,
    enabled: bool = True,
) -> Iterator[T]:
    """Wrap *iterable* with automatic progress reporting.

    If *total* is ``None``, attempts ``len(iterable)``; falls back to 0
    (which disables percentage display).
    """
    if total is None:
        total = len(iterable) if hasattr(iterable, "__len__") else 0

    reporter = ProgressReporter(
        total=total, label=label, json_mode=json_mode, enabled=enabled,
    )
    reporter._start_time = time.monotonic()
    for item in iterable:
        yield item
        reporter.update()
    reporter.finish()


def status_message(msg: str, *, output=None) -> None:
    """Write a one-off status message to stderr."""
    out = output or sys.stderr
    out.write(f"[status] {msg}\n")
    out.flush()
