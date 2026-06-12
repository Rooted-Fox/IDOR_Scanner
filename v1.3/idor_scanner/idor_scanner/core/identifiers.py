"""Object-identifier detection and sequence analysis (stdlib)."""

from __future__ import annotations

import re
from collections import defaultdict

from .models import IdentifierKind, ObjectReference

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_HASH_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_NUMERIC_RE = re.compile(r"^\d+$")
_PREFIXED_SEQ_RE = re.compile(r"^([A-Za-z][A-Za-z_\-]*?)[-_]?(\d{2,})$")

_OBJECTISH_NAMES = {
    "id", "uid", "uuid", "guid", "userid", "user_id", "accountid", "account_id",
    "orderid", "order_id", "invoiceid", "invoice_id", "documentid", "document_id",
    "fileid", "file_id", "objectid", "object_id", "profileid", "profile_id",
    "customerid", "customer_id", "ref", "reference", "key", "no", "num",
    "number", "pid", "gid",
}


def classify(value: str) -> IdentifierKind:
    v = (value or "").strip()
    if not v:
        return IdentifierKind.UNKNOWN
    if _UUID_RE.match(v):
        return IdentifierKind.UUID
    if _NUMERIC_RE.match(v):
        return IdentifierKind.NUMERIC
    if _PREFIXED_SEQ_RE.match(v):
        return IdentifierKind.SEQUENTIAL
    if _HEX_HASH_RE.match(v):
        return IdentifierKind.HASH
    return IdentifierKind.OPAQUE


def looks_like_object_param(name: str, value: str) -> bool:
    if name and name.lower() in _OBJECTISH_NAMES:
        return True
    return classify(value) in (
        IdentifierKind.NUMERIC, IdentifierKind.UUID,
        IdentifierKind.HASH, IdentifierKind.SEQUENTIAL,
    )


def split_prefix_number(value: str):
    v = (value or "").strip()
    if _NUMERIC_RE.match(v):
        return ("", int(v))
    m = _PREFIXED_SEQ_RE.match(v)
    return (m.group(1).lower(), int(m.group(2))) if m else None


def detect_sequences(values: list[str]) -> dict[str, list[int]]:
    buckets: dict[str, list[int]] = defaultdict(list)
    for raw in values:
        parsed = split_prefix_number(raw)
        if parsed is not None:
            buckets[parsed[0]].append(parsed[1])
    out: dict[str, list[int]] = {}
    for prefix, nums in buckets.items():
        nums = sorted(set(nums))
        if len(nums) < 2:
            continue
        span = nums[-1] - nums[0] + 1
        density = len(nums) / span if span else 0.0
        if density >= 0.3 or _run(nums, 3):
            out[prefix] = nums
    return out


def _run(nums: list[int], run: int) -> bool:
    streak = 1
    for a, b in zip(nums, nums[1:]):
        streak = streak + 1 if b == a + 1 else 1
        if streak >= run:
            return True
    return False


def build_reference(value: str, location: str, source_url: str) -> ObjectReference:
    return ObjectReference(value, classify(value), location, source_url)
