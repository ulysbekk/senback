"""Analysis orchestration."""

from __future__ import annotations

from typing import Optional

from ..config import Settings
from ..schemas import AnalyzeResponse
from .lexicon import get_lexicon
from .llm import assess_with_llm
from .rules import analyze_url, detect_rules
from .scoring import build_response, merge_findings


class AnalysisEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def analyze(self, message: str, url: Optional[str]) -> AnalyzeResponse:
        findings = detect_rules(message)

        if self.settings.lexicon_enabled:
            lexicon_result = get_lexicon().assess(message)
            findings = merge_findings(findings, lexicon_result.findings)

        findings.extend(analyze_url(url))

        llm_result = await assess_with_llm(message, url, self.settings)
        llm_score = None
        if llm_result is not None:
            findings.extend(llm_result.findings)
            llm_score = llm_result.score

        return build_response(findings, llm_score=llm_score)
