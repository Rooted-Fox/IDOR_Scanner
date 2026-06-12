"""Autonomous browser-based reconnaissance (Playwright).

Drives a real Chromium browser like a user would: loads pages, follows links,
and records the XHR/fetch traffic the app fires - which is how modern SPAs and
APIs are discovered. Also pulls in well-known API descriptors (OpenAPI/Swagger,
sitemap, robots) and parses JavaScript for endpoint hints.

Everything here is read-only: pages are navigated and links followed, but forms
are *mapped, not submitted*, and no state-changing actions are taken.

If Playwright or its browser isn't available, recon transparently falls back to
a lightweight requests-based crawl so the tool still runs (with less coverage).
"""

from __future__ import annotations

import json
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests

from . import discovery
from .identifiers import build_reference, classify, looks_like_object_param
from .models import ApiEndpoint, IdentifierKind, ObjectReference, RequestRecord
from .scope import ScopeGuard, host_of

log = logging.getLogger("idor.browser")

_WELL_KNOWN_SPECS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/v2/api-docs", "/v3/api-docs", "/api/swagger.json",
]
_JS_URL_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-./{}$:]+)['"`]""")
_API_HINT = re.compile(r"(/api/|/v\d+/|/rest/|/graphql|/gql)", re.I)
_AUTH_HEADERS = ("authorization", "x-api-key", "x-auth-token", "x-access-token")


@dataclass
class SessionBundle:
    """Captured authentication state for one principal."""

    name: str
    role: str = "user"
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    local_storage: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "SessionBundle":
        return cls(**json.loads(text))


@dataclass
class ReconResult:
    pages: list[str] = field(default_factory=list)
    requests: list[RequestRecord] = field(default_factory=list)
    object_refs: list[ObjectReference] = field(default_factory=list)
    object_urls: dict[str, list[ObjectReference]] = field(default_factory=dict)
    param_names: set[str] = field(default_factory=set)
    apis: list[ApiEndpoint] = field(default_factory=list)

    def raw_ids(self) -> list[str]:
        return [r.raw_value for r in self.object_refs]


def to_template(url: str) -> str:
    """Turn a concrete object URL into a template, e.g. /users/123 -> /users/{id}."""
    parsed = urlparse(url)
    path = "/".join(
        "{id}" if seg.isdigit() or classify(seg) in
        (IdentifierKind.UUID, IdentifierKind.SEQUENTIAL) else seg
        for seg in parsed.path.split("/")
    )
    return f"{parsed.scheme}://{parsed.netloc}{path}"


# ---------------------------------------------------------------------------
# Session capture (one-time, interactive login) - removes manual header config
# ---------------------------------------------------------------------------

def capture_session(target: str, name: str, role: str = "user",
                    timeout_s: int = 300, launch_args: list[str] | None = None) -> SessionBundle:
    """Open a real browser, let the user log in once, then capture the session.

    Returns a SessionBundle with cookies, any Authorization-style headers seen on
    XHR/fetch traffic, and localStorage. The user never copies headers by hand.
    """
    from playwright.sync_api import sync_playwright  # local import

    captured_headers: dict[str, str] = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False, args=launch_args or [])
        ctx = browser.new_context()
        page = ctx.new_page()

        def on_request(req):
            for h, v in req.headers.items():
                if h.lower() in _AUTH_HEADERS and v:
                    captured_headers[h] = v

        page.on("request", on_request)
        page.goto(target)
        print(f"\n[session capture] Log in as '{name}' in the opened browser, "
              f"then return here and press Enter (timeout {timeout_s}s)...")
        try:
            input()
        except EOFError:
            page.wait_for_timeout(timeout_s * 1000)

        cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        try:
            ls_raw = page.evaluate("() => JSON.stringify(window.localStorage)")
            local_storage = json.loads(ls_raw) if ls_raw else {}
        except Exception:
            local_storage = {}
        browser.close()

    # Promote a bearer-looking localStorage token to an Authorization header.
    if "authorization" not in {h.lower() for h in captured_headers}:
        for k, v in local_storage.items():
            if isinstance(v, str) and v.count(".") == 2 and len(v) > 40:
                captured_headers["Authorization"] = f"Bearer {v}"
                break
    return SessionBundle(name=name, role=role, cookies=cookies,
                         headers=captured_headers, local_storage=local_storage)


# ---------------------------------------------------------------------------
# Recon
# ---------------------------------------------------------------------------

class BrowserRecon:
    def __init__(self, guard: ScopeGuard, max_pages: int, max_depth: int,
                 user_agent: str, launch_args: list[str] | None = None,
                 bundle: SessionBundle | None = None, timeout_ms: int = 15000) -> None:
        self.guard = guard
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.user_agent = user_agent
        self.launch_args = launch_args or []
        self.bundle = bundle
        self.timeout_ms = timeout_ms

    def recon(self, target: str) -> ReconResult:
        try:
            result = self._recon_playwright(target)
        except Exception as exc:  # noqa: BLE001
            log.warning("Browser recon unavailable (%s); falling back to HTTP crawl.", exc)
            result = self._recon_http(target)
        self._discover_apis(target, result)
        return result

    # -- Playwright path --------------------------------------------------

    def _recon_playwright(self, target: str) -> ReconResult:
        from playwright.sync_api import sync_playwright

        res = ReconResult()
        root = host_of(target)
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=self.launch_args)
            ctx = browser.new_context(user_agent=self.user_agent)
            if self.bundle:
                self._apply_bundle(ctx, target)
            page = ctx.new_page()
            page.on("request", lambda r: self._on_request(r, res))

            queue: deque[tuple[str, int]] = deque([(target, 0)])
            seen: set[str] = set()
            while queue and len(seen) < self.max_pages:
                url, depth = queue.popleft()
                if url in seen or depth > self.max_depth or host_of(url) != root:
                    continue
                if not self.guard.host_in_scope(url):
                    continue
                seen.add(url)
                self._record_url(url, res)
                try:
                    page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
                except Exception as exc:  # noqa: BLE001
                    log.debug("goto failed %s: %s", url, exc)
                    continue
                for link in self._links(page, url):
                    self._record_url(link, res)
                    if link not in seen and host_of(link) == root:
                        queue.append((link, depth + 1))
            browser.close()
        res.pages = list(seen)
        return res

    def _apply_bundle(self, ctx, target: str) -> None:
        from urllib.parse import urlparse as _up
        host = host_of(target)
        ctx.add_cookies([
            {"name": k, "value": v, "domain": host, "path": "/"}
            for k, v in self.bundle.cookies.items()
        ])
        if self.bundle.headers:
            ctx.set_extra_http_headers(self.bundle.headers)

    def _on_request(self, req, res: ReconResult) -> None:
        rtype = req.resource_type
        is_api = rtype in ("xhr", "fetch") or bool(_API_HINT.search(req.url))
        try:
            post = req.post_data or ""
        except Exception:
            post = ""
        res.requests.append(RequestRecord(req.method, req.url, rtype, post[:2000], is_api))
        self._record_url(req.url, res, from_api=is_api)
        if post:
            self._record_json_refs(post, req.url, res)

    @staticmethod
    def _links(page, base: str) -> list[str]:
        try:
            hrefs = page.eval_on_selector_all(
                "a[href], form[action], link[href]",
                "els => els.map(e => e.getAttribute('href') || e.getAttribute('action'))",
            )
        except Exception:
            return []
        return [urljoin(base, h) for h in hrefs if h]

    # -- HTTP fallback ----------------------------------------------------

    def _recon_http(self, target: str) -> ReconResult:
        from .session import Principal, RateLimiter, SessionSpec
        spec = SessionSpec(name="recon", role="user",
                           cookies=(self.bundle.cookies if self.bundle else {}),
                           headers=(self.bundle.headers if self.bundle else {}))
        principal = Principal(spec, 12.0, self.user_agent)
        out = discovery.crawl(principal, self.guard, RateLimiter(4.0),
                              target, self.max_pages, self.max_depth)
        res = ReconResult(pages=list(out.visited),
                          object_refs=out.object_refs,
                          object_urls=out.object_urls,
                          param_names=out.param_names)
        for u in out.object_urls:
            res.requests.append(RequestRecord("GET", u, "document", "", False))
        return res

    # -- shared helpers ---------------------------------------------------

    def _record_url(self, url: str, res: ReconResult, from_api: bool = False) -> None:
        refs = discovery.extract_query_refs(url) + discovery.extract_path_refs(url)
        res.param_names.update(discovery.all_param_names(url))
        if refs:
            res.object_refs.extend(refs)
            res.object_urls.setdefault(url, refs)

    def _record_json_refs(self, body: str, src: str, res: ReconResult) -> None:
        try:
            data = json.loads(body)
        except Exception:
            return
        self._walk_json(data, src, res)

    def _walk_json(self, node, src: str, res: ReconResult, prefix: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    self._walk_json(v, src, res, k)
                elif looks_like_object_param(k, str(v)):
                    res.param_names.add(k)
                    res.object_refs.append(build_reference(str(v), f"json:{k}", src))
        elif isinstance(node, list):
            for item in node[:20]:
                self._walk_json(item, src, res, prefix)

    def _discover_apis(self, target: str, res: ReconResult) -> None:
        base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        seen_templates: set[str] = set()

        def add_api(method: str, url: str, source: str) -> None:
            tmpl = to_template(url)
            key = f"{method} {tmpl}"
            if key not in seen_templates:
                seen_templates.add(key)
                res.apis.append(ApiEndpoint(method, tmpl, source))

        for rec in res.requests:
            if rec.is_api:
                add_api(rec.method, rec.url, "network")

        sess = requests.Session()
        sess.headers["User-Agent"] = self.user_agent
        if self.bundle:
            for k, v in self.bundle.cookies.items():
                sess.cookies.set(k, v)
            sess.headers.update(self.bundle.headers)

        # OpenAPI / Swagger descriptors
        for path in _WELL_KNOWN_SPECS:
            url = base + path
            if not self.guard.host_in_scope(url):
                continue
            try:
                r = sess.get(url, timeout=8)
                if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                    for p in (r.json().get("paths") or {}):
                        add_api("GET", urljoin(base, p), "swagger")
            except Exception:
                pass

        # sitemap + robots
        for path in ("/sitemap.xml", "/robots.txt"):
            url = base + path
            try:
                r = sess.get(url, timeout=6)
                if r.status_code == 200:
                    for m in re.findall(r"https?://[^\s<>\"]+", r.text)[:200]:
                        if host_of(m) == host_of(target):
                            self._record_url(m, res)
            except Exception:
                pass

        # JS endpoint hints (capped)
        scripts = [rec.url for rec in res.requests if rec.resource_type == "script"][:15]
        for js_url in scripts:
            try:
                r = sess.get(js_url, timeout=8)
                if r.status_code != 200:
                    continue
                for m in _JS_URL_RE.findall(r.text):
                    if _API_HINT.search(m):
                        add_api("GET", urljoin(base, m), "js")
            except Exception:
                pass
