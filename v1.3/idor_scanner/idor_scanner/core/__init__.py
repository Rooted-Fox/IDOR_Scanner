"""Autonomous IDOR scanner core (authorized use only)."""

from .auto_scanner import AutoScanner
from .browser import BrowserRecon, SessionBundle, capture_session
from .models import (
    Candidate, Confidence, Finding, ScanBudget, ScanMode, ScanResult,
    ScanStatus, Severity,
)
from .scope import ScopeError, ScopeGuard

__version__ = "2.0.0"
__all__ = [
    "AutoScanner", "BrowserRecon", "SessionBundle", "capture_session",
    "ScanMode", "ScanBudget", "ScanResult", "ScanStatus", "Finding",
    "Candidate", "Severity", "Confidence", "ScopeGuard", "ScopeError",
    "__version__",
]
