"""Response comparison helpers (stdlib difflib)."""

from __future__ import annotations

import difflib
import re

_WS_RE = re.compile(r"\s+")
_DENIAL = (
    "access denied", "not authorized", "unauthorized", "forbidden",
    "permission denied", "you do not have", "you don't have", "no permission",
    "not allowed", "login required", "please log in", "sign in to continue",
    "authentication required",
)


def normalize(text: str) -> str:
    return _WS_RE.sub(" ", (text or "").strip().lower())


def similarity(a: str, b: str) -> float:
    na, nb = normalize(a), normalize(b)
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    return difflib.SequenceMatcher(None, na[:20000], nb[:20000]).ratio()


def looks_like_denial(text: str) -> bool:
    n = normalize(text)
    return any(m in n for m in _DENIAL)


def redact(text: str, limit: int = 500) -> str:
    s = (text or "")[:limit]
    s = re.sub(r"[\w.\-+]+@[\w.\-]+\.\w+", "[REDACTED-EMAIL]", s)
    s = re.sub(r"\b\d{6,}\b", "[REDACTED-NUM]", s)
    if len(text or "") > limit:
        s += " ...[truncated]"
    return s
