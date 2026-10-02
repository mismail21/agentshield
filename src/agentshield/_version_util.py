"""Tiny version comparison helper (avoids a packaging dependency)."""

from __future__ import annotations

import re


def vkey(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    if not parts:
        raise ValueError(f"not a version: {version!r}")
    return tuple(int(p) for p in parts[:4]) + (0,) * (4 - min(len(parts), 4))
