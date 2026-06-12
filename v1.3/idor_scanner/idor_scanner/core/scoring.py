"""Confidence and severity scoring (stdlib)."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Confidence, Severity


@dataclass
class ProbeSignals:
    cross_principal_granted: bool
    status_2xx: bool
    similarity_to_owner: float
    owner_denied_baseline: bool
    sensitive_data_present: bool
    body_looks_like_denial: bool
    enumerable_sequence: bool
    anonymous: bool = False
    vertical: bool = False


def score_confidence(s: ProbeSignals) -> Confidence:
    if s.body_looks_like_denial or not s.cross_principal_granted:
        return Confidence.LOW
    score = 0
    if s.status_2xx:
        score += 1
    if s.anonymous:
        score += 2  # unauthenticated access to an object is a strong signal
    if s.similarity_to_owner >= 0.9:
        score += 2
    elif s.similarity_to_owner >= 0.6:
        score += 1
    if s.owner_denied_baseline:
        score += 1
    if s.sensitive_data_present:
        score += 1
    if score >= 4:
        return Confidence.HIGH
    if score >= 2:
        return Confidence.MEDIUM
    return Confidence.LOW


def score_severity(s: ProbeSignals) -> Severity:
    if not s.cross_principal_granted:
        return Severity.INFO
    if (s.vertical or s.anonymous) and s.sensitive_data_present:
        return Severity.CRITICAL
    if s.sensitive_data_present and s.enumerable_sequence:
        return Severity.CRITICAL
    if s.vertical or s.anonymous or s.sensitive_data_present or s.enumerable_sequence:
        return Severity.HIGH
    return Severity.MEDIUM
