"""Scope guard - the safety boundary.

Kept deliberately small for a laptop tool, but still enforced in code:
  * The user must confirm authorization (the UI checkbox sets authorized=True).
  * Requests may only target hosts that the user explicitly entered as targets.
  * Only non-destructive (read-only) HTTP methods are issued.
"""

from __future__ import annotations

from urllib.parse import urlparse

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class ScopeError(PermissionError):
    pass


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


class ScopeGuard:
    def __init__(self, target_urls: list[str], authorized: bool) -> None:
        self.authorized = authorized
        self.allowed_hosts = {host_of(u) for u in target_urls if host_of(u)}

    def assert_authorized(self) -> None:
        if not self.authorized:
            raise ScopeError(
                "You must confirm you are authorized to test these targets "
                "before scanning."
            )
        if not self.allowed_hosts:
            raise ScopeError("No valid target hosts were provided.")

    def host_in_scope(self, url: str) -> bool:
        return host_of(url) in self.allowed_hosts

    def check(self, method: str, url: str) -> None:
        if (method or "GET").upper() not in SAFE_METHODS:
            raise ScopeError(f"Method '{method}' is disabled (read-only tool).")
        if not self.host_in_scope(url):
            raise ScopeError(f"Refusing out-of-scope host: {host_of(url) or url}")
