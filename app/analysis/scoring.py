"""Turn findings into the score, level, and warnings the frontend renders."""

from __future__ import annotations

from typing import Iterable, List, Optional

from ..schemas import AnalyzeResponse, Warning
from .types import SEVERITY_FLOOR, SEVERITY_RANK, Finding


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    """Keep one finding per title, preferring the more severe version."""
    best: dict[str, Finding] = {}
    for finding in findings:
        key = " ".join(finding.title.split()).casefold()
        current = best.get(key)
        if current is None or finding.sort_key() < current.sort_key():
            best[key] = finding
    return sorted(best.values(), key=lambda finding: finding.sort_key())


def merge_findings(primary: Iterable[Finding], extra: Iterable[Finding]) -> List[Finding]:
    """Merge extra evidence into primary findings that share a group.

    A rule warning and a lexicon warning for the same behavior should be one
    warning, not two. When both exist, keep the rule's title and description,
    add the new quotes, and take the stronger weight and severity.
    """
    merged = list(primary)
    by_group = {finding.group: finding for finding in merged if finding.group}

    for finding in extra:
        current = by_group.get(finding.group) if finding.group else None
        if current is None:
            merged.append(finding)
            if finding.group:
                by_group[finding.group] = finding
            continue

        for quote in finding.evidence:
            if quote.casefold() not in {item.casefold() for item in current.evidence}:
                current.evidence.append(quote)
        current.evidence = current.evidence[:3]
        current.weight = max(current.weight, finding.weight)
        if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(current.severity, 0):
            current.severity = finding.severity

    return merged


def level_for(score: int) -> str:
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def score_findings(findings: Iterable[Finding]) -> int:
    findings = list(findings)
    if not findings:
        return 0

    total = sum(max(0, finding.weight) for finding in findings)
    strongest = max(
        (finding.severity for finding in findings),
        key=lambda severity: SEVERITY_RANK.get(severity, 0),
    )
    # A single severe warning shouldn't be labeled low risk just because its
    # numeric weight is small.
    return min(100, max(total, SEVERITY_FLOOR.get(strongest, 0)))


def build_response(
    findings: Iterable[Finding],
    llm_score: Optional[int] = None,
) -> AnalyzeResponse:
    findings = dedupe(findings)
    score = score_findings(findings)

    # The LLM can raise the score but not lower it. The rule engine stays the
    # floor, so a flaky or manipulated model cannot hide an obvious scam.
    if llm_score is not None:
        score = max(score, min(100, max(0, llm_score)))

    return AnalyzeResponse(
        risk_score=score,
        risk_level=level_for(score),
        warnings=[
            Warning(
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                evidence=finding.evidence[:3],
            )
            for finding in findings
        ],
    )
