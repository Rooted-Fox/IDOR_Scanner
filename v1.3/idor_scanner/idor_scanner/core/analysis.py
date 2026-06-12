"""Analysis / intelligence layer.

Turns raw recon (object references, parameters, observed requests) into a ranked
list of IDOR *candidates* - the parameters and object endpoints most likely to be
authorization-sensitive - so the agent tests the right things first, with no
manual parameter selection.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from .identifiers import classify
from .models import Candidate, IdentifierKind, ObjectReference

# Parameter names that strongly imply per-user ownership (highest priority).
STRONG_OWNERSHIP = {
    "userid", "user_id", "accountid", "account_id", "customerid", "customer_id",
    "invoiceid", "invoice_id", "orderid", "order_id", "documentid", "document_id",
    "profileid", "profile_id", "ticketid", "ticket_id", "fileid", "file_id",
    "uid", "memberid", "member_id", "clientid", "client_id",
}
# Generic id-ish names (medium priority).
GENERIC_IDS = {"id", "ref", "reference", "key", "no", "num", "number", "pid", "gid"}

_KIND_WEIGHT = {
    IdentifierKind.SEQUENTIAL: 0.30,
    IdentifierKind.NUMERIC: 0.28,
    IdentifierKind.HASH: 0.12,
    IdentifierKind.UUID: 0.06,
    IdentifierKind.OPAQUE: 0.04,
    IdentifierKind.UNKNOWN: 0.0,
}


def _param_name(location: str) -> str:
    # locations look like "query:userId", "json:accountId", "path:users"
    return location.split(":", 1)[1] if ":" in location else location


def param_priority(name: str) -> tuple[float, bool]:
    """Return (priority_weight, is_auth_sensitive) for a parameter name."""
    n = (name or "").lower()
    if n in STRONG_OWNERSHIP:
        return 0.45, True
    if n in GENERIC_IDS:
        return 0.25, True
    # name ending in 'id' is a soft signal
    if n.endswith("id") and len(n) > 2:
        return 0.30, True
    return 0.05, False


def prioritize_parameters(object_refs: list[ObjectReference]) -> list[dict]:
    """Aggregate discovered parameters and rank by authorization sensitivity."""
    by_param: dict[str, list[ObjectReference]] = defaultdict(list)
    for r in object_refs:
        by_param[_param_name(r.location)].append(r)

    rows = []
    for name, refs in by_param.items():
        weight, sensitive = param_priority(name)
        kinds = Counter(r.kind.value for r in refs)
        rows.append({
            "parameter": name,
            "sensitive": sensitive,
            "weight": weight,
            "observations": len(refs),
            "distinct_values": len({r.raw_value for r in refs}),
            "kinds": dict(kinds),
        })
    rows.sort(key=lambda r: (r["sensitive"], r["weight"], r["distinct_values"]), reverse=True)
    return rows


def build_candidates(object_urls: dict[str, list[ObjectReference]],
                     object_refs: list[ObjectReference]) -> list[Candidate]:
    """Produce a ranked list of IDOR candidates from discovered object endpoints."""
    # How many distinct values seen per parameter (enumerability signal).
    distinct_per_param: dict[str, set[str]] = defaultdict(set)
    for r in object_refs:
        distinct_per_param[_param_name(r.location)].add(r.raw_value)

    candidates: list[Candidate] = []
    seen: set[tuple[str, str]] = set()
    for url, refs in object_urls.items():
        for ref in refs:
            name = _param_name(ref.location)
            key = (url, name)
            if key in seen:
                continue
            seen.add(key)

            weight, sensitive = param_priority(name)
            kind = classify(ref.raw_value)
            prob = weight + _KIND_WEIGHT.get(kind, 0.0)
            reasons = []
            if sensitive:
                reasons.append(f"'{name}' implies per-user ownership")
            if kind in (IdentifierKind.NUMERIC, IdentifierKind.SEQUENTIAL):
                reasons.append("identifier is numeric/guessable")
            if ref.location.startswith("json") or "/api/" in url.lower():
                prob += 0.12
                reasons.append("appears in an API/JSON request")
            if len(distinct_per_param.get(name, ())) >= 3:
                prob += 0.15
                reasons.append("multiple values observed (enumerable)")

            candidates.append(Candidate(
                endpoint=url, parameter=name, object_id=ref.raw_value,
                kind=kind.value, sensitive_param=sensitive,
                probability=round(min(prob, 0.99), 2),
                rationale="; ".join(reasons) or "object reference observed",
            ))
    candidates.sort(key=lambda c: c.probability, reverse=True)
    return candidates
