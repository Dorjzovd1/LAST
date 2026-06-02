"""Цагийн бүс — UTC хадгалах, API-д timezone-той ISO гаргах."""
from __future__ import annotations

from datetime import datetime, timezone

# Forensic UI — Монгол/Ulaanbaatar (UTC+8)
DISPLAY_TZ = "Asia/Ulaanbaatar"


def ensure_utc(dt: datetime | None) -> datetime | None:
    """SQLite-ээс ирсэн naive datetime-ийг UTC гэж үзнэ."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
