import asyncio

from app.analysis.engine import AnalysisEngine
from app.analysis.lexicon import CATEGORY_CAP, Category, Lexicon, Phrase, get_lexicon
from app.analysis.rules import detect_rules
from app.analysis.scoring import build_response, merge_findings
from app.analysis.types import Finding
from app.config import Settings

SAFE_NOTICE = (
    "Your quarterly statement for the retirement account ending in 4821 is now available. "
    "To view it, sign in through our mobile app or type our web address directly into your "
    "browser. We will never ask for your password or a one-time code by email, text, or phone."
)


def test_seed_corpus_loads():
    lexicon = get_lexicon()
    assert len(lexicon.phrases) >= 100
    assert "returns" in lexicon.categories
    assert "credentials" in lexicon.categories


def test_phrase_matches_case_and_punctuation_at_token_boundaries():
    result = get_lexicon().assess("Guaranteed-returns are back!")

    assert "returns" in result.category_scores
    finding = next(item for item in result.findings if item.id == "lexicon_returns")
    assert finding.severity == "critical"
    assert finding.evidence
    assert "Guaranteed-returns" in finding.evidence[0]


def test_negated_phrase_is_ignored():
    result = get_lexicon().assess("We do not share your password with anyone.")

    assert "credentials" not in result.category_scores
    assert not any(item.id == "lexicon_credentials" for item in result.findings)


def test_safe_account_notice_does_not_trigger_a_password_request():
    result = get_lexicon().assess(SAFE_NOTICE)

    assert "credentials" not in result.category_scores
    # A safe notice may still match low-value account wording, which is fine.
    assert result.category_scores.get("account", 0) <= 6


def test_category_score_is_capped():
    result = get_lexicon().assess(
        ("guaranteed returns double your money " * 20)
    )

    assert result.category_scores["returns"] == CATEGORY_CAP


def test_overlapping_phrases_are_not_double_counted():
    categories = {"x": Category("x", "X", "test", "high", "x")}
    lexicon = Lexicon(
        categories,
        [
            Phrase("guaranteed", "x", 8, "high"),
            Phrase("guaranteed returns", "x", 18, "high"),
        ],
    )

    result = lexicon.assess("guaranteed returns")

    # Both phrases match, but the longer, more specific one wins.
    assert result.category_scores["x"] == 18


def test_token_boundary_prevents_partial_word_matches():
    result = get_lexicon().assess("The coin did 100xyz in a day.")

    assert "prediction" not in result.category_scores


def test_merge_keeps_one_warning_and_combines_evidence():
    rule = Finding(
        id="guaranteed_returns",
        title="Guaranteed high returns",
        description="rule description",
        severity="critical",
        weight=35,
        evidence=["guarantees 40% returns"],
        group="returns",
    )
    lexicon = Finding(
        id="lexicon_returns",
        title="Known scam wording about returns",
        description="lexicon description",
        severity="critical",
        weight=18,
        evidence=["ZERO risk"],
        group="returns",
    )

    merged = merge_findings([rule], [lexicon])

    assert merged == [rule]
    assert rule.evidence == ["guarantees 40% returns", "ZERO risk"]
    assert rule.weight == 35


def test_engine_combines_rules_and_lexicon():
    engine = AnalysisEngine(Settings())
    result = asyncio.run(engine.analyze("This is a guaranteed return with zero risk.", None))

    assert result.risk_level == "critical"
    titles = [warning.title for warning in result.warnings]
    assert "Guaranteed high returns" in titles
    # One merged returns warning, not a separate rule warning and lexicon warning.
    assert sum("return" in title.lower() or "risk" in title.lower() for title in titles) == 1


def test_lexicon_does_not_change_clean_message():
    result = get_lexicon().assess("Let's meet for coffee on Tuesday and catch up.")

    assert result.findings == []
    assert result.matches == []


def test_engine_does_not_overweight_lexicon_on_a_medium_pitch():
    message = (
        "Hi, I came across your profile on LinkedIn. Our firm offers pre-construction real "
        "estate investments with projected annual returns of 18–22%. The minimum investment "
        "is $10,000. Would you be open to a quick call this week? Happy to send over our brochure."
    )
    engine = AnalysisEngine(Settings())
    result = asyncio.run(engine.analyze(message, None))

    assert result.risk_level == "medium"
    assert 25 <= result.risk_score < 50


def test_lexicon_can_stand_alone_when_rules_miss():
    # "trading bot" is in the corpus but not a hard rule by itself.
    findings = detect_rules("Our trading bot is excellent.")
    lexicon = get_lexicon().assess("Our trading bot is excellent.")
    merged = build_response(merge_findings(findings, lexicon.findings))

    assert merged.risk_level == "high"
    assert any("investment" in warning.title.lower() for warning in merged.warnings)
