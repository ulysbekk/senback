"""Regression tests for campaign-level gambling / SMS-spam phrases."""

import asyncio

from app.analysis.engine import AnalysisEngine
from app.analysis.lexicon import get_lexicon
from app.analysis.rules import analyze_url, detect_rules
from app.analysis.scoring import build_response, merge_findings
from app.config import Settings


def _analyze(message: str, url=None):
    findings = detect_rules(message)
    findings = merge_findings(findings, get_lexicon().assess(message).findings)
    findings.extend(analyze_url(url))
    return build_response(findings)


def test_gambling_campaign_is_flagged():
    result = _analyze("Join today and enjoy 400% casino bonus, START https://example.com/x")
    assert result.risk_level in {"medium", "high", "critical"}
    assert any("casino" in warning.title.casefold() for warning in result.warnings)


def test_alcohol_delivery_campaign_is_flagged():
    text = "We just missed you today! Schedule a redelivery-tomorrow afternoon |- https://example.com/r"
    result = _analyze(text, "https://example.com/r")
    assert result.risk_score >= 25
    assert any("delivery" in warning.title.casefold() for warning in result.warnings)


def test_missed_call_notification_campaign_is_flagged():
    text = "You have a missed call from 00447700903000, time 13:45"
    result = _analyze(text)
    assert result.risk_score >= 25
    assert any("missed-call" in warning.title.casefold() for warning in result.warnings)


def test_crypto_prepaid_card_campaign_is_flagged():
    text = "Deposit only make 30 sms and receive an instant bonus with your crypto"
    result = _analyze(text)
    assert result.risk_score >= 25
    assert any("crypto" in warning.title.casefold() for warning in result.warnings)


def test_prize_syndicate_campaign_is_flagged():
    text = "congratulations you have won 1000 pounds in the international lottery prize syndicate"
    result = _analyze(text)
    assert result.risk_score >= 25
    assert get_lexicon().assess(text).category_scores.get("prizes", 0) > 0


def test_engine_wrapper_agrees_with_helper():
    engine = AnalysisEngine(Settings())
    import asyncio

    result = asyncio.run(engine.analyze("casino bonus free spins", None))
    assert result.risk_score == _analyze("casino bonus free spins").risk_score
