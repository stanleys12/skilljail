"""Enforcement backends. ``pick()`` returns the first available backend for this host."""

from __future__ import annotations

import sys

from .base import Backend, LaunchSpec
from .bwrap import BwrapBackend
from .seatbelt import SeatbeltBackend

BACKENDS: dict[str, type[Backend]] = {"seatbelt": SeatbeltBackend, "bwrap": BwrapBackend}


def pick(name: str | None = None) -> Backend:
    if name:
        if name not in BACKENDS:
            raise ValueError(f"unknown backend {name!r}; choose from {sorted(BACKENDS)}")
        b = BACKENDS[name]()
        if not b.available():
            raise RuntimeError(f"backend {name!r} is not available on this host: {b.unavailable_reason()}")
        return b
    order = ["seatbelt", "bwrap"] if sys.platform == "darwin" else ["bwrap", "seatbelt"]
    for n in order:
        b = BACKENDS[n]()
        if b.available():
            return b
    raise RuntimeError("no sandbox backend available (need sandbox-exec on macOS or bwrap on Linux)")


__all__ = ["Backend", "LaunchSpec", "SeatbeltBackend", "BwrapBackend", "pick", "BACKENDS"]
