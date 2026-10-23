from pathlib import Path

from app.analysis.rules import analyze_url, detect_rules
from app.analysis.scoring import build_response, dedupe, score_findings
from app.analysis.types import Finding

GOVERNMENT_PAYMENT_PHISHING = (
    Path(__file__).parent / "fixtures" / "government_payment_phishing.txt"
).read_text(encoding="utf-8")

CRITICAL_MESSAGE = (
    "Hi! I'm Jessica, a senior portfolio manager at a top crypto fund. Our AI trading bot "
    "guarantees 40% returns every month with ZERO risk. I only have 3 spots left in our VIP "
    "group and the offer closes tonight. Send at least $500 in USDT to the wallet below to "
    "get started, and don't tell your bank, they'll try to block it! Withdrawals unlock as "
    "soon as you hit your profit target."
)

HIGH_MESSAGE = (
    "Oh sorry, wrong number! Since you're here though: my uncle works at a biotech company "
    "that's about to announce FDA approval. The stock is under $1 now and will be over $10 by "
    "next week. I already bought 50,000 shares. Get in before the news goes public. I can add "
    "you to our private trading group on WhatsApp."
)

MEDIUM_MESSAGE = (
    "Hi, I came across your profile on LinkedIn. Our firm offers pre-construction real estate "
    "investments with projected annual returns of 18–22%. The minimum investment is $10,000. "
    "Would you be open to a quick call this week? Happy to send over our brochure."
)

LOW_MESSAGE = (
    "Your quarterly statement for the retirement account ending in 4821 is now available. To "
    "view it, sign in through our mobile app or type our web address directly into your "
    "browser. We will never ask for your password or a one-time code by email, text, or phone."
)


def titles(findings):
    return {finding.title for finding in findings}


def test_critical_sample_is_critical_and_explains_itself():
    result = build_response(detect_rules(CRITICAL_MESSAGE))

    assert result.risk_level == "critical"
    assert result.risk_score >= 75
    found = {warning.title for warning in result.warnings}
    assert "Guaranteed high returns" in found
    assert "Payment in crypto" in found
    assert "Told to keep it from your bank" in found
    assert "Pressure to act immediately" in found
    assert "Conditions on withdrawals" in found
    assert all(warning.severity for warning in result.warnings)
    assert any(warning.evidence for warning in result.warnings)


def test_government_payment_phishing_is_critical_and_explains_itself():
    result = build_response(detect_rules(GOVERNMENT_PAYMENT_PHISHING))

    assert result.risk_level == "critical"
    assert result.risk_score >= 75
    found = {warning.title for warning in result.warnings}
    assert "Request for sensitive identity or banking details" in found
    assert "Suspicious government benefit or refund offer" in found
    assert "Pressure to act within a deadline" in found
    evidence = [quote for warning in result.warnings for quote in warning.evidence]
    assert any("Social Security number" in quote for quote in evidence)
    assert any("Bank account number" in quote for quote in evidence)


def test_safe_warning_about_sensitive_details_is_not_a_request():
    text = (
        "We will never ask you to provide your Social Security number, bank account number, "
        "debit-card details, or online banking password by email or text. Your Social Security "
        "number is already on file."
    )
    result = build_response(detect_rules(text))

    assert "Request for sensitive identity or banking details" not in titles(detect_rules(text))
    assert result.risk_score < 25


def test_request_for_banking_credentials_is_flagged():
    text = "Please send your bank account number and Social Security number."
    findings = detect_rules(text)
    result = build_response(findings)

    assert result.risk_level in {"high", "critical"}
    assert "Request for sensitive identity or banking details" in titles(findings)


def test_wrong_number_sample_is_high():
    result = build_response(detect_rules(HIGH_MESSAGE))

    assert result.risk_level == "high"
    found = {warning.title for warning in result.warnings}
    assert 'Unsolicited "wrong number" contact' in found
    assert "Claims of insider information" in found
    assert "Unrealistic price prediction" in found


def test_real_estate_sample_is_medium():
    result = build_response(detect_rules(MEDIUM_MESSAGE))

    assert result.risk_level == "medium"
    found = {warning.title for warning in result.warnings}
    assert "Unsolicited investment offer" in found
    assert "High projected annual returns" in found
    assert "Large minimum investment" in found


def test_safe_account_notice_stays_low():
    result = build_response(detect_rules(LOW_MESSAGE))

    assert result.risk_level == "low"
    assert result.risk_score < 25
    assert [warning.title for warning in result.warnings] == ["Account notices can be spoofed"]
    # The "we will never ask for your password" line must not be treated as a request.
    assert "Request for passwords or one-time codes" not in titles(detect_rules(LOW_MESSAGE))


def test_clean_message_has_no_warnings():
    result = build_response(detect_rules("Let's meet for coffee on Tuesday and catch up."))

    assert result.risk_score == 0
    assert result.risk_level == "low"
    assert result.warnings == []


def test_negated_guarantee_is_not_a_promise():
    text = "We do not guarantee returns. This is a diversified, regulated fund."
    assert "Guaranteed high returns" not in titles(detect_rules(text))


def test_strong_single_warning_never_reports_low_risk():
    finding = Finding(
        id="test",
        title="Critical test",
        description="A critical signal.",
        severity="critical",
        weight=5,
    )
    result = build_response([finding])
    assert result.risk_score >= 75
    assert result.risk_level == "critical"


def test_dedupe_keeps_more_severe_finding():
    low = Finding("a", "Same title", "low", "low", 5)
    high = Finding("b", "same TITLE", "high", "high", 20)
    assert dedupe([low, high]) == [high]


def test_monthly_percentage_is_critical_even_without_the_word_guarantee():
    findings = detect_rules("Our fund returns 8% every month with no risk.")
    result = build_response(findings)
    assert result.risk_level == "critical"


def test_annual_projection_is_flagged_as_medium():
    findings = detect_rules("The plan projects 18-22% annual returns.")
    assert "High projected annual returns" in titles(findings)
    assert build_response(findings).risk_level == "medium"


def test_url_ip_and_http_are_flagged():
    findings = analyze_url("http://192.168.1.10/login")
    found = titles(findings)
    assert "Link uses a raw IP address" in found
    assert "Link isn't encrypted" in found


def test_url_brand_lookalike_is_flagged():
    assert "Link may impersonate a known brand" in titles(analyze_url("https://paypal-secure.com"))
    assert "Link may impersonate a known brand" in titles(analyze_url("https://paypal.com.evil.xyz"))


def test_official_brand_domain_is_not_flagged():
    assert "Link may impersonate a known brand" not in titles(analyze_url("https://www.paypal.com"))


def test_shortener_is_flagged():
    assert "Shortened link hides its destination" in titles(analyze_url("https://bit.ly/abc123"))


def test_plain_https_link_is_quiet():
    assert analyze_url("https://example.com/offer") == []


def test_score_is_capped_at_100():
    findings = [
        Finding(str(index), f"Finding {index}", "desc", "critical", 40)
        for index in range(4)
    ]
    assert score_findings(findings) == 100
