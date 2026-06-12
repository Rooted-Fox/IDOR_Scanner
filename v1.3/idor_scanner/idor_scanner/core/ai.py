"""Optional AI reasoning layer.

When an Anthropic API key is available (env ANTHROPIC_API_KEY) and the scan mode
enables it, this enriches findings with consultant-style narratives and can
re-rank candidates. It degrades gracefully: with no key/SDK it is a no-op and the
heuristic analysis already produced by ``analysis.py`` stands on its own.

Only metadata is sent to the model (endpoint, parameter, id type, status,
similarity) - never raw response bodies / victim data.
"""

from __future__ import annotations

import json
import logging
import os

from .models import Finding

log = logging.getLogger("idor.ai")

_SYSTEM = (
    "You are a senior application security consultant reviewing automated IDOR "
    "findings. For the given finding metadata return STRICT JSON with keys "
    "'description', 'business_impact', 'recommendation'. Be precise, factual, and "
    "non-sensational. Never invent data not present in the input."
)


class AIReasoner:
    def __init__(self, enabled: bool, model: str = "claude-sonnet-4-5",
                 api_key_env: str = "ANTHROPIC_API_KEY") -> None:
        self.client = None
        if not enabled:
            return
        key = os.environ.get(api_key_env)
        if not key:
            log.info("AI enabled but %s not set; using heuristic narratives.", api_key_env)
            return
        try:
            import anthropic  # type: ignore
            self.client = anthropic.Anthropic(api_key=key)
            self.model = model
        except Exception as exc:  # noqa: BLE001
            log.info("Anthropic SDK unavailable (%s); using heuristic narratives.", exc)
            self.client = None

    @property
    def available(self) -> bool:
        return self.client is not None

    def enrich(self, finding: Finding) -> None:
        if not self.available:
            return
        meta = {
            "test_case": finding.test_case, "endpoint": finding.endpoint,
            "parameter": finding.parameter, "object_id": finding.object_id,
            "role_tested": finding.role_tested, "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "evidence": [{"status": e.status_code, "similarity": e.similarity_to_owner,
                          "length": e.response_length} for e in finding.evidence],
        }
        try:
            msg = self.client.messages.create(
                model=self.model, max_tokens=600, system=_SYSTEM,
                messages=[{"role": "user", "content": json.dumps(meta)}],
            )
            text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
            data = json.loads(text[text.find("{"): text.rfind("}") + 1])
            finding.description = data.get("description", finding.description)
            finding.recommendation = data.get("recommendation", finding.recommendation)
        except Exception as exc:  # noqa: BLE001
            log.debug("AI enrich failed: %s", exc)

    def enrich_all(self, findings: list[Finding]) -> None:
        for f in findings:
            self.enrich(f)
