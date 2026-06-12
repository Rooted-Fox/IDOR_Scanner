"""Authenticated principals (requests-based, simple and synchronous)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

import requests

from .scope import ScopeGuard


@dataclass
class SessionSpec:
    """A principal the scanner can act as. An anonymous principal has no creds."""

    name: str
    role: str = "user"            # user | admin | anonymous
    auth_type: str = "none"       # none | cookie | bearer | jwt
    cookies: dict[str, str] = field(default_factory=dict)
    token: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    # Optional ground-truth ownership: object label -> URL this principal owns.
    owned_objects: dict[str, str] = field(default_factory=dict)


@dataclass
class ProbeResult:
    status_code: int
    text: str
    elapsed_ms: float
    url: str
    error: Optional[str] = None


class Principal:
    def __init__(self, spec: SessionSpec, timeout: float, user_agent: str) -> None:
        self.spec = spec
        self.timeout = timeout
        self.sess = requests.Session()
        self.sess.headers.update({"User-Agent": user_agent})
        self.sess.headers.update(spec.headers)
        for k, v in spec.cookies.items():
            self.sess.cookies.set(k, v)
        if spec.auth_type in ("bearer", "jwt") and spec.token:
            self.sess.headers["Authorization"] = f"Bearer {spec.token}"

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def role(self) -> str:
        return self.spec.role

    def get(self, url: str, guard: ScopeGuard) -> ProbeResult:
        guard.check("GET", url)
        start = time.monotonic()
        try:
            r = self.sess.get(url, timeout=self.timeout, allow_redirects=True)
            return ProbeResult(r.status_code, r.text, (time.monotonic() - start) * 1000, r.url)
        except requests.RequestException as exc:
            return ProbeResult(0, "", (time.monotonic() - start) * 1000, url, str(exc))


class RateLimiter:
    def __init__(self, rps: float) -> None:
        self.interval = 1.0 / rps if rps > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        delta = self.interval - (time.monotonic() - self._last)
        if delta > 0:
            time.sleep(delta)
        self._last = time.monotonic()
