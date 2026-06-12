"""Autonomous scan orchestrator.

Given only a target URL (and optionally one or more captured login sessions), this
runs the full consultant-style workflow automatically:

  recon (browser) -> object/API/parameter inventory -> candidate ranking ->
  multi-context authorization testing -> evidence + scoring -> findings + matrix.

No manual parameter, endpoint, object, or payload selection is required. All
requests are read-only and confined to the authorized target host.

Authorization contexts are derived automatically:
  * an always-present ANONYMOUS context (drives forced-browsing checks), plus
  * one context per captured session (drives cross-user / vertical checks).
Ownership is inferred from what each context can reach - not a manual map.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from . import analysis, discovery
from .ai import AIReasoner
from .browser import BrowserRecon, ReconResult, SessionBundle, to_template
from .comparison import looks_like_denial, redact, similarity
from .identifiers import detect_sequences, split_prefix_number
from .models import (
    AccessExpectation, AccessOutcome, Confidence, Evidence, Finding, MatrixCell,
    ScanBudget, ScanMode, ScanResult, ScanStatus, Severity,
)
from .scope import ScopeError, ScopeGuard
from .scoring import ProbeSignals, score_confidence, score_severity
from .session import Principal, ProbeResult, RateLimiter, SessionSpec

log = logging.getLogger("idor.scan")

_SENSITIVE_RE = re.compile(
    r"(ssn|social security|iban|sort.?code|card.?number|cvv|date.?of.?birth|"
    r"\bdob\b|salary|balance|passport|tax.?id|\baddress\b|phone)", re.I)

RECOMMENDATION = (
    "Enforce object-level authorization server-side: derive the acting user from "
    "the session and verify ownership (or an explicit grant) of the requested "
    "object before returning it. Don't rely on unguessable IDs alone; add "
    "automated tests for cross-user and unauthenticated object access."
)

ProgressFn = Callable[[int, str], None]
UA = "IDOR-Scanner/2.0 (autonomous; authorized testing)"


def _outcome(res: ProbeResult, baseline: str) -> tuple[AccessOutcome, float]:
    if res.error or res.status_code == 0:
        return AccessOutcome.ERROR, 0.0
    if res.status_code in (401, 403):
        return AccessOutcome.DENIED, 0.0
    if res.status_code == 404:
        return AccessOutcome.NOT_FOUND, 0.0
    if 200 <= res.status_code < 300:
        if looks_like_denial(res.text):
            return AccessOutcome.DENIED, 0.0
        return AccessOutcome.GRANTED, (similarity(res.text, baseline) if baseline else 0.0)
    return AccessOutcome.ERROR, 0.0


@dataclass
class Context:
    """One authorization context (anonymous or a captured session)."""

    name: str
    role: str
    principal: Principal
    own_urls: set[str] = field(default_factory=set)

    @property
    def anonymous(self) -> bool:
        return self.role == "anonymous"


class AutoScanner:
    def __init__(self, target: str, mode: ScanMode, bundles: list[SessionBundle],
                 guard: ScopeGuard, launch_args: Optional[list[str]] = None) -> None:
        self.target = target
        self.mode = mode
        self.budget = ScanBudget.for_mode(mode)
        self.guard = guard
        self.bundles = bundles
        self.launch_args = launch_args or []
        self.limiter = RateLimiter(self.budget.rps)

    # -- public -----------------------------------------------------------

    def run(self, progress: Optional[ProgressFn] = None) -> ScanResult:
        prog = progress or (lambda *_: None)
        result = ScanResult(target=self.target, status=ScanStatus.RUNNING,
                            scan_mode=self.mode.value,
                            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        def emit(pct: int, msg: str) -> None:
            result.progress = pct
            result.log.append(f"[{pct:3d}%] {msg}")
            log.info(msg)
            prog(pct, msg)

        try:
            self.guard.assert_authorized()
            self.guard.check("GET", self.target)
        except ScopeError as exc:
            result.status = ScanStatus.BLOCKED
            result.message = str(exc)
            result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return result

        # 1. Recon (browser) as the primary context.
        emit(5, "Reconnaissance: crawling and capturing traffic")
        primary_bundle = self.bundles[0] if self.bundles else None
        recon = BrowserRecon(
            self.guard, self.budget.max_pages, self.budget.max_depth, UA,
            self.launch_args, primary_bundle,
        ).recon(self.target)
        result.endpoints = len(recon.pages)
        result.parameters = len(recon.param_names)
        result.objects = len({r.raw_value for r in recon.object_refs})
        result.api_endpoints = len(recon.apis)
        result.requests_observed = len(recon.requests)
        emit(40, f"Mapped {result.endpoints} pages, {result.api_endpoints} APIs, "
                 f"{result.objects} object refs")

        # 2. Analysis: prioritize parameters + rank candidates.
        emit(45, "Analyzing attack surface and ranking IDOR candidates")
        result.candidates = analysis.build_candidates(recon.object_urls, recon.object_refs)[:50]

        # 3. Build authorization contexts (+ per-context ownership crawl).
        contexts = self._build_contexts(recon, emit)
        result.contexts_tested = [c.name for c in contexts]

        # 4. Authorization testing.
        emit(60, "Testing object-level authorization across contexts")
        self._test_authorization(recon, contexts, result)

        emit(85, "Checking sequential-ID enumeration")
        self._test_enumeration(recon, contexts, result)

        # 5. Optional AI enrichment.
        if self.budget.use_ai:
            emit(92, "Applying AI reasoning to findings")
            AIReasoner(enabled=True).enrich_all(result.findings)

        result.status = ScanStatus.DONE
        result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        emit(100, f"Scan complete: {len(result.findings)} finding(s)")
        return result

    # -- contexts ---------------------------------------------------------

    def _build_contexts(self, recon: ReconResult, emit) -> list[Context]:
        contexts: list[Context] = []
        anon = Context("anonymous", "anonymous",
                       Principal(SessionSpec("anonymous", "anonymous"), 12.0, UA))
        contexts.append(anon)
        for b in self.bundles:
            spec = SessionSpec(name=b.name, role=b.role, auth_type="cookie",
                               cookies=b.cookies, headers=b.headers)
            contexts.append(Context(b.name, b.role, Principal(spec, 12.0, UA)))

        # Primary recon's object URLs belong to the primary context.
        primary = contexts[1] if len(contexts) > 1 else contexts[0]
        primary.own_urls.update(recon.object_urls.keys())

        # Per-context ownership crawl (Standard/Deep) to learn what each
        # context can reach on its own - this is how ownership is inferred.
        if self.budget.per_context_crawl and len(contexts) > 1:
            for ctx in contexts:
                emit(50, f"Mapping reachable objects as '{ctx.name}'")
                ctx.own_urls.update(self._own_urls(ctx))
        return contexts

    def _own_urls(self, ctx: Context) -> set[str]:
        out = discovery.crawl(
            ctx.principal, self.guard, RateLimiter(self.budget.rps),
            self.target, max(10, self.budget.max_pages // 2),
            max(1, self.budget.max_depth - 1),
        )
        return set(out.object_urls.keys())

    # -- authorization tests ----------------------------------------------

    def _test_authorization(self, recon: ReconResult, contexts: list[Context],
                            result: ScanResult) -> None:
        anon = next(c for c in contexts if c.anonymous)
        authed = [c for c in contexts if not c.anonymous]
        tested = 0

        # (a) Forced browsing: can anonymous reach an authed context's objects?
        for owner in authed:
            for url in list(owner.own_urls)[: self.budget.max_objects]:
                base = self._probe(owner, url)
                anon_res = self._probe(anon, url)
                self._record(result, anon, url, base.text, anon_res,
                             expected=AccessExpectation.DENY)
                if _outcome(anon_res, base.text)[0] == AccessOutcome.GRANTED:
                    self._finding(result, anon, url, base.text, anon_res,
                                  anonymous=True, vertical=False, enumerable=False,
                                  test_case="Forced browsing (unauthenticated)")
                tested += 1
                if tested >= self.budget.max_objects * 2:
                    break

        # (b) Cross-user / vertical: actor reaches owner-only objects.
        for owner in authed:
            for actor in authed:
                if actor.name == owner.name:
                    continue
                cross = list(owner.own_urls - actor.own_urls)[: self.budget.max_objects]
                for url in cross:
                    base = self._probe(owner, url)
                    actor_res = self._probe(actor, url)
                    outcome, sim = _outcome(actor_res, base.text)
                    self._record(result, actor, url, base.text, actor_res,
                                 expected=AccessExpectation.DENY)
                    if outcome == AccessOutcome.GRANTED and (sim >= 0.5 or _sensitive(actor_res.text)):
                        self._finding(result, actor, url, base.text, actor_res,
                                      anonymous=False, vertical=(owner.role == "admin"),
                                      enumerable=False,
                                      test_case=("Vertical privilege escalation"
                                                 if owner.role == "admin"
                                                 else "Cross-user object access"))

        # Record owner-allow baseline cells (matrix completeness).
        for owner in authed:
            for url in list(owner.own_urls)[: min(10, self.budget.max_objects)]:
                res = self._probe(owner, url)
                self._record(result, owner, url, res.text, res,
                             expected=AccessExpectation.ALLOW)

    def _test_enumeration(self, recon: ReconResult, contexts: list[Context],
                          result: ScanResult) -> None:
        sequences = detect_sequences(recon.raw_ids())
        if not sequences:
            return
        actor = next((c for c in contexts if not c.anonymous), contexts[0])
        for prefix, nums in sequences.items():
            template = self._template_for(prefix, nums, recon)
            if not template or "{id}" not in template:
                continue
            lo, hi = nums[0], nums[-1]
            sample = list(range(lo, hi + 1))[: self.budget.max_enum]
            distinct, last, example = set(), None, ""
            for n in sample:
                url = template.replace("{id}", str(n))
                res = self._probe(actor, url)
                if _outcome(res, "")[0] == AccessOutcome.GRANTED:
                    distinct.add(redact(res.text)[:120])
                    last, example = res, url
            if len(distinct) >= 3 and last is not None:
                self._finding(result, actor, example, "", last, anonymous=actor.anonymous,
                              vertical=False, enumerable=True,
                              test_case="Mass object enumeration",
                              object_id=f"{lo}..{hi}", parameter=f"{prefix or 'id'} (sequential)")

    # -- helpers ----------------------------------------------------------

    def _probe(self, ctx: Context, url: str) -> ProbeResult:
        self.limiter.wait()
        return ctx.principal.get(url, self.guard)

    def _record(self, result: ScanResult, ctx: Context, url: str, baseline: str,
                res: ProbeResult, expected: AccessExpectation) -> None:
        outcome, _ = _outcome(res, baseline)
        object_id = self._id_from(url)
        result.matrix.append(MatrixCell(
            principal=ctx.name, role=ctx.role, object_label=object_id,
            object_id=object_id, expected=expected, actual=outcome,
            status_code=res.status_code,
        ))

    def _finding(self, result: ScanResult, ctx: Context, url: str, baseline: str,
                 res: ProbeResult, anonymous: bool, vertical: bool, enumerable: bool,
                 test_case: str, object_id: str = "", parameter: str = "") -> None:
        sim = _outcome(res, baseline)[1]
        sensitive = _sensitive(res.text)
        signals = ProbeSignals(
            cross_principal_granted=True, status_2xx=200 <= res.status_code < 300,
            similarity_to_owner=sim, owner_denied_baseline=True,
            sensitive_data_present=sensitive, body_looks_like_denial=False,
            enumerable_sequence=enumerable, anonymous=anonymous, vertical=vertical,
        )
        conf = score_confidence(signals)
        if conf == Confidence.LOW and not sensitive and not anonymous:
            return
        sev = score_severity(signals)
        oid = object_id or self._id_from(url)
        kind = "Unauthenticated" if anonymous else "Vertical" if vertical else "Horizontal"
        desc = (f"{kind} broken object-level authorization. Context '{ctx.name}' "
                f"({ctx.role}) retrieved object {oid} at {url} with HTTP "
                f"{res.status_code}"
                + (f"; response similarity to the owner was {sim:.0%}." if sim else ".")
                + (" Sensitive data markers were present." if sensitive else ""))
        result.findings.append(Finding(
            endpoint=url, parameter=parameter or self._param_from(url), object_id=oid,
            role_tested=ctx.role, test_case=test_case, severity=sev, confidence=conf,
            description=desc, recommendation=RECOMMENDATION,
            evidence=[Evidence(
                principal=ctx.name, role=ctx.role, request_method="GET",
                request_url=url, status_code=res.status_code,
                response_length=len(res.text), similarity_to_owner=round(sim, 3),
                body_snippet=redact(res.text), elapsed_ms=round(res.elapsed_ms, 1),
            )],
        ))

    def _template_for(self, prefix: str, nums: list[int], recon: ReconResult) -> str:
        for url, refs in recon.object_urls.items():
            for r in refs:
                parsed = split_prefix_number(r.raw_value)
                if parsed and parsed[0] == prefix and parsed[1] in nums:
                    return url.replace(r.raw_value, "{id}")
        return ""

    @staticmethod
    def _id_from(url: str) -> str:
        from urllib.parse import urlparse, parse_qsl
        q = parse_qsl(urlparse(url).query)
        if q:
            return q[-1][1]
        seg = [s for s in urlparse(url).path.split("/") if s]
        return seg[-1] if seg else url

    @staticmethod
    def _param_from(url: str) -> str:
        from urllib.parse import urlparse, parse_qsl
        q = parse_qsl(urlparse(url).query)
        if q:
            return q[-1][0]
        seg = [s for s in urlparse(url).path.split("/") if s]
        return f"path:{seg[-2]}" if len(seg) >= 2 else "path"


def _sensitive(text: str) -> bool:
    return bool(_SENSITIVE_RE.search(text or ""))
