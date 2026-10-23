"""Deterministic red-flag detection.

This is intentionally explainable: every warning comes from a named rule, a
severity, and the text that triggered it. That makes results testable and lets us
add an LLM later without giving up a reliable baseline.

Rules are not a substitute for judgment. They are weighted signals, and the
scoring layer turns them into a 0-100 score.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional, Pattern, Tuple
from urllib.parse import unquote, urlsplit

from .text import clean_quote, is_negated
from .types import Finding

# Common number formats, including ranges such as "18–22%".
_NUM_PERCENT = r"\d{1,3}(?:\.\d+)?(?:\s?[–-]\s?\d{1,3}(?:\.\d+)?)?\s?%"

# Words that make a percentage an investment-return claim rather than a generic
# statistic ("20% daily demand", "100% gas daily" must not match).
_RETURN_NOUN = r"(?:returns?|profits?|incomes?|gains?|interest|yields?|roi|payouts?)"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: str
    weight: int
    patterns: Tuple[Pattern[str], ...]
    group: str


def _p(*patterns: str) -> Tuple[Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE | re.UNICODE) for pattern in patterns)


RULES: Tuple[Rule, ...] = (
    Rule(
        id="guaranteed_returns",
        title="Guaranteed high returns",
        description=(
            "The message promises returns that cannot be guaranteed. Every investment "
            "carries risk, so a guarantee is a strong scam signal."
        ),
        severity="critical",
        weight=35,
        group="returns",
        patterns=_p(
            r"\b(?:guarantee(?:s|d)?|assured|promise(?:s|d)?)\b[^.!?\n]{0,45}"
            r"\b(?:returns?|profits?|income|gains?|payouts?)\b",
            r"\b(?:risk[- ]free|zero[- ]risk|no[- ]risk)\b[^.!?\n]{0,45}"
            r"\b(?:returns?|profits?|income|investment|gains?)\b",
            rf"\b(?:guarantee(?:s|d)?|risk[- ]free|zero[- ]risk)\b[^.!?\n]{{0,45}}{_NUM_PERCENT}",
        ),
    ),
    Rule(
        id="unrealistic_returns_monthly",
        title="Unrealistic monthly return claims",
        description=(
            "A return this high, repeated every month or week, is far beyond what real "
            "investments reliably produce. It is a common way to make a scam look attractive."
        ),
        severity="critical",
        weight=28,
        group="returns",
        patterns=_p(
            rf"\b{_NUM_PERCENT}\s*(?:per|a|each|every)\s+(?:day|week|month)\b",
            rf"\b{_RETURN_NOUN}\b[^.!?\n]{{0,25}}\b{_NUM_PERCENT}[^.!?\n]{{0,25}}\b(?:daily|weekly|monthly)\b",
            rf"\b{_NUM_PERCENT}[^.!?\n]{{0,25}}\b(?:daily|weekly|monthly)\b"
            rf"[^.!?\n]{{0,25}}\b{_RETURN_NOUN}\b",
        ),
    ),
    Rule(
        id="unrealistic_returns_annual",
        title="High projected annual returns",
        description=(
            "The advertised annual return is above what most real investments reliably "
            "produce. Ask how the projection is calculated and what happens if it is not met."
        ),
        severity="medium",
        weight=14,
        group="returns",
        patterns=_p(
            rf"\b{_NUM_PERCENT}\s*(?:per|a|each|every)\s+(?:year|annum)\b",
            rf"\b{_NUM_PERCENT}[^.!?\n]{{0,25}}\b(?:annual(?:ly)?|yearly)\b"
            rf"[^.!?\n]{{0,25}}\b{_RETURN_NOUN}\b",
            rf"\b{_RETURN_NOUN}\b[^.!?\n]{{0,25}}\b{_NUM_PERCENT}[^.!?\n]{{0,25}}\b(?:annual(?:ly)?|yearly)\b",
            rf"\b(?:annual(?:ly)?|yearly)\b[^.!?\n]{{0,25}}\b{_RETURN_NOUN}\b"
            rf"[^.!?\n]{{0,25}}{_NUM_PERCENT}",
            rf"\b{_RETURN_NOUN}\b[^.!?\n]{{0,25}}\b(?:annual(?:ly)?|yearly)\b"
            rf"[^.!?\n]{{0,25}}{_NUM_PERCENT}",
        ),
    ),
    Rule(
        id="crypto_payment",
        title="Payment in crypto",
        description=(
            "You're asked to pay in crypto, possibly to a wallet address. Crypto transfers "
            "are hard to trace and almost impossible to reverse, which is why scammers prefer them."
        ),
        severity="critical",
        weight=30,
        group="payment",
        patterns=_p(
            r"\b(?:send|transfer|pay|deposit|wire|top up)\b[^.!?\n]{0,60}"
            r"\b(?:usdt|tether|bitcoin|btc|eth|ethereum|crypto|wallet)\b",
            r"\b(?:usdt|tether|bitcoin|btc|eth|ethereum)\b[^.!?\n]{0,40}\bwallet\b",
            r"\b0x[a-f0-9]{40}\b",
            r"\bbc1[a-z0-9]{20,}\b",
            r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        ),
    ),
    Rule(
        id="secrecy",
        title="Told to keep it from your bank",
        description=(
            'Being told to keep the deal from your bank, family, or the authorities is a '
            'classic warning sign. Those are the people most likely to spot the fraud.'
        ),
        severity="high",
        weight=20,
        group="secrecy",
        patterns=_p(
            r"\b(?:don'?t|do not|never)\s+(?:tell|inform|mention (?:this )?to|let)\b"
            r"[^.!?\n]{0,30}\b(?:bank|family|friends|anyone|police|authorities|anybody)\b",
            r"\bkeep (?:this|it) (?:a )?secret\b",
            r"\b(?:just|only) between (?:us|you and me)\b",
            r"\bkeep (?:this|it|everything) between (?:us|you and me)\b",
            r"\bthis (?:is|stays) between (?:us|you and me)\b",
        ),
    ),
    Rule(
        id="urgency",
        title="Pressure to act immediately",
        description=(
            "The message pressures you to act before you can check the offer. Urgency and "
            "scarcity are standard manipulation tactics."
        ),
        severity="high",
        weight=15,
        group="urgency",
        patterns=_p(
            r"\b(?:only|just)\b[^.!?\n]{0,18}\d{1,2}\s+"
            r"(?:spots?|places?|slots?|seats?)\s+(?:left|remaining|available)\b",
            r"\b(?:offer|deal|opportunity)\s+(?:ends|closes|expires)\s+"
            r"(?:tonight|today|soon|tomorrow|in \d+)\b",
            r"\b(?:act|move|invest|get in)\s+(?:now|fast|quickly|immediately|today)\b",
            r"\b(?:limited[- ]time|while supplies last|before it'?s too late)\b",
        ),
    ),
    Rule(
        id="deadline_pressure",
        title="Pressure to act within a deadline",
        description=(
            "The message imposes a short deadline or threatens delays to stop you from "
            "checking the request. Real organizations give you time to verify through an "
            "official channel."
        ),
        severity="medium",
        weight=12,
        group="urgency",
        patterns=_p(
            r"\bwithin (?:the next )?\d{1,2}\s*hours?\b",
            r"\b(?:before|by)\s+(?:the\s+)?deadline\b",
            r"\b(?:must|need to|required to)\b[^.!?\n]{0,40}"
            r"\b(?:complete|verify|respond|act)\b[^.!?\n]{0,30}"
            r"\b(?:immediately|today|now)\b",
            r"\b(?:to prevent|avoid)\s+(?:delays?|cancellation|suspension|termination)\b",
        ),
    ),
    Rule(
        id="withdrawal_conditions",
        title="Conditions on withdrawals",
        description=(
            "The message says withdrawals depend on a target, fee, or another deposit. "
            "That is a common way to keep victims paying before they can take money out."
        ),
        severity="high",
        weight=20,
        group="withdrawal",
        patterns=_p(
            r"\bwithdraw(?:al|als)?\b[^.!?\n]{0,50}"
            r"\b(?:unlock|after|once|when|until|target|fee|tax)\b",
            r"\b(?:unlock|release)\b[^.!?\n]{0,30}\b(?:withdrawals?|funds|profits?|money)\b",
            r"\bhit (?:your )?(?:profit )?target\b",
        ),
    ),
    Rule(
        id="wrong_number_contact",
        title='Unsolicited "wrong number" contact',
        description=(
            "A stranger who texts the wrong number and then brings up money or investing is "
            "a common opening for relationship investment scams."
        ),
        severity="medium",
        weight=12,
        group="contact",
        patterns=_p(r"\bwrong (?:number|text|person)\b"),
    ),
    Rule(
        id="romance_scam",
        title="Known romance-scam wording",
        description=(
            "The message uses affectionate language common in relationship investment scams."
        ),
        severity="medium",
        weight=18,
        group="romance",
        patterns=_p(
            r"\bmy (?:dear|love|darling|sweetheart|honey)\b",
            r"\b(?:widow|widower|single mother|lonely)\b[^.!?\n]{0,40}\b(?:need|trust|help)\b",
            r"\btrust (?:me|you|a stranger)\b",
        ),
    ),
    Rule(
        id="unsolicited_contact",
        title="Unsolicited investment offer",
        description=(
            "The sender contacted you first about an investment. Legitimate advisers rarely "
            "cold-message strangers with investment offers."
        ),
        severity="medium",
        weight=12,
        group="contact",
        patterns=_p(
            r"\b(?:came across|found|saw|noticed)\b[^.!?\n]{0,20}"
            r"\byour (?:profile|number|contact|listing|resume)\b",
            r"\b(?:cold|unsolicited)\s+(?:call|message|text|dm|email)\b",
            r"\b(?:i|we) (?:found|got) your (?:number|profile|contact)\b",
        ),
    ),
    Rule(
        id="insider_info",
        title="Claims of insider information",
        description=(
            "The message claims access to non-public information. Trading on inside "
            "information is illegal, and scammers use this claim to make a pitch feel exclusive."
        ),
        severity="high",
        weight=20,
        group="insider",
        patterns=_p(
            r"\bbefore (?:the )?(?:news|announcement|information)\b[^.!?\n]{0,30}"
            r"\b(?:goes|is|becomes|hits|was)\b[^.!?\n]{0,15}\bpublic\b",
            r"\b(?:inside|insider)\s+(?:information|info|tip|knowledge|news)\b",
            r"\bmy (?:uncle|aunt|cousin|friend|brother|sister|father|mother)\b"
            r"[^.!?\n]{0,30}\bworks? (?:at|for)\b",
            r"\babout to announce\b",
        ),
    ),
    Rule(
        id="price_prediction",
        title="Unrealistic price prediction",
        description=(
            "The message predicts a large, quick price move. Promises like this are typical "
            "of pump-and-dump schemes, where promoters sell as new buyers push the price up."
        ),
        severity="high",
        weight=18,
        group="prediction",
        patterns=_p(
            r"\b(?:will|going to|bound to|set to|expected to)\b[^.!?\n]{0,30}"
            r"\b(?:rise|jump|soar|surge|double|triple|moon|explode)\b"
            r"[^.!?\n]{0,25}\b(?:by|to|in)\b",
            r"\b(?:will be|to be|worth)\s+(?:over|above|more than)?\s*\$?\d+(?:\.\d+)?\b"
            r"[^.!?\n]{0,25}\b(?:by|in|next|within)\b",
            r"\b(?:under|below)\s+\$?\d+(?:\.\d+)?\s+(?:now|today)\b"
            r"[^.!?\n]{0,60}\b(?:over|above|worth)\s+\$?\d+",
            r"\b\d{1,3}x\b[^.!?\n]{0,20}\b(?:by|in|next|within)\b",
            r"\b(?:to the moon|tenfold|100x|1000x|10x)\b",
        ),
    ),
    Rule(
        id="private_group",
        title="Invitation to a private group",
        description=(
            "You're invited into a private chat group. Scammers use these to control what "
            "you see, often with fake screenshots of profits from other members."
        ),
        severity="medium",
        weight=12,
        group="group",
        patterns=_p(
            r"\bprivate\s+(?:trading|investment|signal|vip|wealth)\s+"
            r"(?:group|channel|community|club)\b",
            r"\b(?:vip|exclusive)\s+(?:group|channel|community|club)\b",
            r"\b(?:whatsapp|telegram|discord|signal)\s+(?:group|channel|community)\b",
            r"\b(?:join|add (?:me|you) to)\b[^.!?\n]{0,25}\b(?:group|channel|community)\b",
        ),
    ),
    Rule(
        id="credential_request",
        title="Request for passwords or one-time codes",
        description=(
            "The message asks for a password, one-time code, or recovery phrase. Legitimate "
            "firms never ask for these by message, email, or phone."
        ),
        severity="critical",
        weight=30,
        group="credentials",
        patterns=_p(
            r"\b(?:send|share|provide|confirm|enter|reply with|give (?:me|us)|tell (?:me|us))\b"
            r"[^.!?\n]{0,40}\b(?:password|passcode|one[- ]time (?:code|password)|otp|pin|"
            r"recovery phrase|seed phrase|2fa code|verification code)\b",
            r"\b(?:verify|confirm|unlock|update)\b[^.!?\n]{0,30}"
            r"\b(?:account|identity|wallet|card)\b[^.!?\n]{0,30}"
            r"\b(?:link|here|now|immediately|click)\b",
        ),
    ),
    Rule(
        id="account_notice",
        title="Account notices can be spoofed",
        description=(
            "This looks like an account notice. Scammers copy these messages, so open the "
            "official app or type the company's address yourself instead of using a link."
        ),
        severity="low",
        weight=5,
        group="account",
        patterns=_p(
            r"\b(?:account|statement|balance)\b[^.!?\n]{0,45}"
            r"\b(?:ending(?: in)?|available|suspended|locked|on hold|limited)\b",
            r"\b(?:your|the)\s+(?:quarterly|monthly|annual|account)\s+"
            r"(?:statement|notice|summary)\b",
            r"\b(?:sign|log)\s+in\b[^.!?\n]{0,40}\b(?:app|website|account|online)\b",
        ),
    ),
    Rule(
        id="investment_offer",
        title="Investment offer needs verification",
        description=(
            "The message pitches an investment. Verify the firm and the specific offering "
            "with a financial regulator before sending money."
        ),
        severity="medium",
        weight=10,
        group="investment",
        patterns=_p(
            r"\b(?:investment|investing|trading)\s+(?:opportunity|offer|plan|program|fund|account)\b",
            r"\b(?:our|my) (?:firm|company|team|fund)\b[^.!?\n]{0,30}"
            r"\b(?:offers?|provides?|manages?|specializes?)\b",
            r"\b(?:projected|expected|targeted|guaranteed)\b[^.!?\n]{0,20}\breturns?\b",
            r"\bpre[- ]construction\b",
        ),
    ),
    Rule(
        id="large_minimum",
        title="Large minimum investment",
        description=(
            "A large minimum investment raises the cost of finding out it's a scam. Verify "
            "the firm and the offering before committing money."
        ),
        severity="low",
        weight=8,
        group="minimum",
        patterns=_p(
            r"\bminimum\s+(?:investment|deposit|buy[- ]?in|commitment)\b"
            r"[^.!?\n]{0,25}\$?\d[\d,]*(?:\.\d+)?\b",
            r"\$\d{1,3}(?:,\d{3})+\b[^.!?\n]{0,30}\bminimum\b",
        ),
    ),
    Rule(
        id="recovery_scam",
        title="Offer to recover lost money",
        description=(
            "The message offers to recover lost money for an upfront fee. Recovery-fee "
            "schemes often target people who were already scammed."
        ),
        severity="high",
        weight=22,
        group="recovery",
        patterns=_p(
            r"\b(?:recover|reclaim|refund|get back)\b[^.!?\n]{0,35}"
            r"\b(?:lost|stolen|scammed|scam)\b[^.!?\n]{0,35}"
            r"\b(?:crypto|funds|money|investment)\b",
            r"\b(?:pay|send)\b[^.!?\n]{0,30}\b(?:fee|tax|deposit|charge)\b"
            r"[^.!?\n]{0,30}\b(?:release|recover|withdraw|refund)\b",
            r"\b(?:advance fee|upfront fee|processing fee)\b[^.!?\n]{0,30}\b(?:recover|release|get back)\b",
        ),
    ),
    Rule(
        id="impersonation",
        title="Impersonation of a company or authority",
        description=(
            "The message impersonates a bank, company, or authority to make the request look "
            "official. Contact the organization through a channel you find yourself."
        ),
        severity="high",
        weight=20,
        group="impersonation",
        patterns=_p(
            r"\b(?:microsoft|apple|amazon|paypal|google|facebook|netflix|irs|hmrc|police|"
            r"government|social security)\b[^.!?\n]{0,45}"
            r"\b(?:suspended|locked|unusual activity|verify|arrest|warrant|refund|cancel(?:led|ed)?)\b",
        ),
    ),
    Rule(
        id="benefit_payment_phishing",
        title="Suspicious government benefit or refund offer",
        description=(
            "The message claims a government payment, refund, or cost-of-living adjustment is "
            "waiting and needs personal verification. Scammers use official-sounding benefit "
            "programs to collect identity and banking details. Check the program with the "
            "government agency directly, using a website or phone number you find yourself."
        ),
        severity="high",
        weight=30,
        group="impersonation",
        patterns=_p(
            r"\b(?:economic adjustment|cost[- ]of[- ]living adjustment|economic assistance|"
            r"emergency refund|stimulus payment|government benefit|benefit payment)\b",
            r"\b(?:national|federal|state|government)\b[^.!?\n]{0,45}"
            r"\b(?:assistance|benefit|payment)\b[^.!?\n]{0,45}"
            r"\b(?:center|department|agency|division|administration|processing)\b",
            r"\b(?:payment|benefit|refund)\b[^.!?\n]{0,45}"
            r"\b(?:pending|held|on hold|awaiting)\b[^.!?\n]{0,45}"
            r"\b(?:verification|release|eligibility|approval)\b",
            r"\b(?:preliminary eligibility|eligibility screening|verification portal|"
            r"secure verification|financial assistance verification)\b",
        ),
    ),
    Rule(
        id="too_good_to_be_true",
        title="Money-multiplying promise",
        description=(
            "The message promises to multiply your money. Returns that sound too good to be "
            "true usually are."
        ),
        severity="high",
        weight=18,
        group="too_good",
        patterns=_p(
            r"\b(?:double|triple)\s+your\s+(?:money|investment|bitcoin|crypto)\b",
            r"\bturn\s+\$?\d[\d,]*\s+into\s+\$?\d[\d,]*\b",
            r"\bgive (?:you|me)\b[^.!?\n]{0,20}\d{1,3}%\b[^.!?\n]{0,30}\b(?:compensation|commission)\b",
            r"\b\d{1,3}%\s+(?:as\s+)?(?:compensation|commission|cut)\b",
        ),
    ),
    Rule(
        id="no_regulation",
        title="Seller says they are not regulated",
        description=(
            "The message admits the seller is not registered or regulated. Check the firm "
            "with your local financial regulator before investing."
        ),
        severity="medium",
        weight=12,
        group="regulation",
        patterns=_p(
            r"\b(?:unregistered|unregulated|unlicensed|"
            r"not (?:registered|regulated|licensed))\b",
        ),
    ),
    Rule(
        id="offshore",
        title="Offshore or tax-free pitch",
        description=(
            "Offshore or tax-free claims make it harder to verify the seller and recover "
            "money if something goes wrong."
        ),
        severity="low",
        weight=6,
        group="offshore",
        patterns=_p(r"\b(?:offshore|tax[- ]free|no taxes|tax haven)\b"),
    ),
)


# ---------------------------------------------------------------------------
# Sensitive-information requests
# ---------------------------------------------------------------------------

# These are the details that let someone steal an identity or drain an account.
# They are only flagged when the message also contains a request cue; mentioning
# that a bank will never ask for them is not itself suspicious.
_SENSITIVE_ITEMS: Tuple[Tuple[str, Pattern[str]], ...] = (
    (
        "Social Security number",
        re.compile(r"\bsocial security (?:number|no\.?|#)\b|\bssn\b", re.IGNORECASE),
    ),
    (
        "bank account number",
        re.compile(
            r"\bbank account (?:number|no\.?|#|details|information)\b|\bbank details\b|\bbanking (?:details|information)\b|\baccount (?:details|information)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "debit-card details",
        re.compile(
            r"\b(?:debit|credit)[- ]card (?:information|details|number)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "online banking credentials",
        re.compile(
            r"\bonline banking (?:username|login|credentials|password)\b"
            r"|\bbanking username and password\b|\b(?:routing|iban|swift)\b[^.!?\n]{0,20}\b(?:number|code)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "one-time verification code",
        re.compile(
            r"\bone[- ]time (?:verification )?code\b|\bverification code\b|\b(?:otp|mfa)\b[^.!?\n]{0,10}\b(?:code)\b",
            re.IGNORECASE,
        ),
    ),
)

_REQUEST_CUE = re.compile(
    r"\b(?:provide|send|share|submit|enter|supply|confirm|verify|reply with|"
    r"give (?:me|us)|tell (?:me|us)|asked to provide|must complete|i need|all i need|need (?:me|us)?)\b",
    re.IGNORECASE,
)
_NEGATED_REQUEST = re.compile(
    r"\b(?:do not|don't|never|will not|won't|no need to|not)\b[^.!?\n]{0,45}$",
    re.IGNORECASE,
)


def _detect_sensitive_data_request(text: str) -> Optional[Finding]:
    """Find a request for identity or banking details, ignoring safe warnings.

    The request cue has to appear shortly before the detail, and negated cues
    ("never send your Social Security number") are ignored. A single listed
    detail is enough when the message is explicitly asking for it.
    """
    cue_positions = [
        match.start()
        for match in _REQUEST_CUE.finditer(text)
        if not _NEGATED_REQUEST.search(text[max(0, match.start() - 50) : match.start()])
    ]
    if not cue_positions:
        return None

    found: List[Tuple[str, re.Match[str]]] = []
    for label, pattern in _SENSITIVE_ITEMS:
        for match in pattern.finditer(text):
            if is_negated(text, match.start()):
                continue
            if not any(match.start() - 260 <= cue < match.start() for cue in cue_positions):
                continue
            found.append((label, match))
            break

    if not found:
        return None

    evidence: List[str] = []
    for _, match in found:
        quote = clean_quote(match.group(0))
        if quote and quote.casefold() not in {item.casefold() for item in evidence}:
            evidence.append(quote)
        if len(evidence) >= 3:
            break

    return Finding(
        id="sensitive_data_request",
        title="Request for sensitive identity or banking details",
        description=(
            "The message asks for information that can be used to steal your identity or "
            "take money from your accounts, such as a Social Security number, bank account "
            "number, card details, banking login, or one-time code. Legitimate organizations "
            "do not request these by message. Contact them through an official channel you "
            "find yourself."
        ),
        severity="high",
        weight=36,
        evidence=evidence,
        group="credentials",
    )


# ---------------------------------------------------------------------------
# Campaign-level rules
# ---------------------------------------------------------------------------

# These cover the high-volume categories that bulk SMS and phishing email
# corpora are dominated by (gambling, missed delivery, missed calls, task/job
# scams). They are paired with the weighted lexicon so a single ambiguous word
# does not become a high score on its own.
_CAMPAIGN_RULES: Tuple[Rule, ...] = (
    Rule(
        id="gambling_promotion",
        title="Casino or betting promotion",
        description=(
            "The message promotes a casino, betting bonus, or free spins. This is a "
            "high-volume SMS spam category and often hides subscription traps or malware links."
        ),
        severity="medium",
        weight=12,
        group="gambling",
        patterns=_p(
            r"\b(?:casino|sportsbook|betting)\b[^.!?\n]{0,40}"
            r"\b(?:bonus|free spins?|credit|deposit|wager|jackpot|play)\b",
            r"\b(?:free spins?|no deposit bonus|welcome bonus|betting bonus|free bet)\b",
            r"\b(?:online casino|live dealer|slot machine|roulette|blackjack)\b",
        ),
    ),
    Rule(
        id="missed_delivery",
        title="Missed delivery or redelivery request",
        description=(
            "The message claims a delivery was missed or a parcel is waiting and asks you to "
            "reschedule through a link. Check the carrier's official app or website instead."
        ),
        severity="medium",
        weight=12,
        group="mis_delivery",
        patterns=_p(
            r"\b(?:missed|failed|attempted)\b[^.!?\n]{0,25}\b(?:delivery|parcel|package)\b",
            r"\b(?:schedule|arrange|book)\b[^.!?\n]{0,20}\b(?:redelivery|delivery|re-delivery)\b",
            r"\b(?:redelivery|re-delivery)\b[^.!?\n]{0,30}\b(?:today|tomorrow|afternoon|fee)\b",
            r"\b(?:parcel|package)\b[^.!?\n]{0,25}\b(?:waiting|on hold|held|undelivered)\b",
        ),
    ),
    Rule(
        id="missed_call_notice",
        title="Missed-call or voicemail notice",
        description=(
            "The message reports a missed call or voicemail from an unknown number. Call-back "
            "scams (wangiri) charge premium rates, so verify the number independently."
        ),
        severity="medium",
        weight=10,
        group="missed_call",
        patterns=_p(
            r"\bmissed\s+call\b[^.!?\n]{0,25}\bfrom\b",
            r"\b(?:you have|new)\b[^.!?\n]{0,15}\b(?:missed call|voicemail)\b",
            r"\bwe tried to (?:call|reach) you\b",
        ),
    ),
    Rule(
        id="task_scam",
        title="Task or easy-money job offer",
        description=(
            "The message offers simple paid tasks, app reviews, or package reshipping. These "
            "are common fronts for advance-fee and money-mule scams."
        ),
        severity="medium",
        weight=12,
        group="job",
        patterns=_p(
            r"\b(?:earn|make)\b[^.!?\n]{0,25}\b(?:per (?:day|task|hour)|daily|weekly)\b"
            r"[^.!?\n]{0,20}\b(?:task|review|like|order)\b",
            r"\b(?:task|order|review)\b[^.!?\n]{0,25}\b(?:commission|payout|payment|reward)\b",
            r"\b(?:reship|forward|receive)\b[^.!?\n]{0,30}\bpackages?\b",
            r"\b(?:no experience|work from home|flexible hours)\b[^.!?\n]{0,40}"
            r"\b(?:pay|earn|income|salary)\b",
        ),
    ),
    Rule(
        id="tech_support_impersonation",
        title="Tech support impersonation",
        description=(
            "The message impersonates a tech support provider and pressures you to call "
            "a support number for a fake renewal, subscription, or protection issue."
        ),
        severity="high",
        weight=22,
        group="tech_support",
        patterns=_p(
            r"\b(?:geek squad|best buy tech|microsoft (?:support|365)|apple care|norton|mcafee|totalav|avast|webroot)\b"
            r"[^.!?\n]{0,90}\b(?:support|renew|subscription|protection|warranty|continuity|service|technician)\b",
            r"\b(?:protection|subscription|warranty|coverage|service)\b[^.!?\n]{0,70}\b(?:geek squad|microsoft|norton|mcafee|apple|best buy)\b",
            r"\b(?:call|contact)\b[^.!?\n]{0,50}\b(?:support (?:desk|team|line|center)|customer (?:support|service))\b"
            r"[^.!?\n]{0,40}\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        ),
    ),
    Rule(
        id="support_isolation_tactic",
        title="Support channel isolation tactic",
        description=(
            "The message claims only a specific channel can help and other channels cannot "
            "process requests, a common tactic to prevent verification."
        ),
        severity="high",
        weight=20,
        group="secrecy",
        patterns=_p(
            r"\b(?:handled exclusively|only via|only through|exclusively via)\b[^.!?\n]{0,70}\b(?:channel|support|customer service|digital|online)\b",
            r"\b(?:retail store|physical store|store location|brick and mortar).{0,60}\b(?:cannot|can't|do not|won't|will not).{0,60}\b(?:help|process|handle|administrat)",
            r"\bdo not maintain\b[^.!?\n]{0,60}\b(?:capability|ability|authority|access)\b[^.!?\n]{0,60}\b(?:process|handle|administrat|request|update|cancel)",
        ),
    ),
    Rule(
        id="fake_renewal_notice",
        title="Fake service renewal or continuity notice",
        description=(
            "The message fabricates a service renewal/continuity notice with account details "
            "and pressures you to call or adjust settings."
        ),
        severity="high",
        weight=18,
        group="impersonation",
        patterns=_p(
            r"\b(?:service continuity|protection (?:plan|status)|subscription (?:renewal|status)|coverage (?:status|continuity))\b[^.!?\n]{0,90}\b(?:scheduled|renew|continu|active|expire|expir)\b",
            r"\b(?:member profile|service specification|coverage horizon|registered units|account (?:profile|parameters))\b[^.!?\n]{0,80}\b(?:usd|\$)\s*\d",
            r"\b(?:review|adjust|update|verify).{0,60}\b(?:profile|account|setting|preference).{0,60}\b(?:call|contact).{0,40}\b(?:support|service)",
        ),
    ),
)


def detect_rules(text: str) -> List[Finding]:
    """Return one finding per rule group, keeping the strongest match.

    Rules that share a group (for example, guaranteed returns and unrealistic
    returns) describe the same underlying behavior. Keeping only the strongest
    one avoids double-counting and duplicate warnings.
    """
    best: dict[str, Finding] = {}

    for rule in RULES + _CAMPAIGN_RULES:
        evidence: List[str] = []
        for pattern in rule.patterns:
            for match in pattern.finditer(text):
                if is_negated(text, match.start()):
                    continue
                quote = clean_quote(match.group(0))
                if quote and quote.casefold() not in {item.casefold() for item in evidence}:
                    evidence.append(quote)
                if len(evidence) >= 3:
                    break
            if len(evidence) >= 3:
                break

        if not evidence:
            continue

        finding = Finding(
            id=rule.id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            weight=rule.weight,
            evidence=evidence,
            group=rule.group,
        )
        current = best.get(rule.group)
        if current is None or finding.sort_key() < current.sort_key():
            best[rule.group] = finding

    sensitive = _detect_sensitive_data_request(text)
    if sensitive is not None:
        current = best.get(sensitive.group)
        if current is None or sensitive.sort_key() < current.sort_key():
            best[sensitive.group] = sensitive

    return list(best.values())


# ---------------------------------------------------------------------------
# URL checks
# ---------------------------------------------------------------------------

SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "link",
    "work",
    "support",
    "rest",
    "cfd",
    "sbs",
    "icu",
    "buzz",
    "monster",
    "quest",
    "cyou",
    "cam",
    "bar",
}

BRANDS = {
    "paypal",
    "apple",
    "amazon",
    "microsoft",
    "google",
    "facebook",
    "netflix",
    "coinbase",
    "binance",
    "kraken",
    "metamask",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "hsbc",
    "barclays",
    "revolut",
    "wise",
    "robinhood",
    "fidelity",
    "vanguard",
    "schwab",
}

# Words that show up in credential-harvesting or "free money" link paths.
RISKY_LINK_WORDS = re.compile(
    r"(?:wallet[-_]?connect|seed|recovery|airdrop|claim|verify|unlock|bonus|gift|"
    r"vip|profit|pump|signal|free[-_]?money|double[-_]?your)",
    re.IGNORECASE,
)

EXECUTABLE_SUFFIXES = (".apk", ".exe", ".scr", ".msi", ".dmg", ".pkg")


def analyze_url(url: Optional[str]) -> List[Finding]:
    """Static URL checks. We never fetch the link: fetching user-supplied URLs from
    the server would create an SSRF risk and slow down every analysis."""
    if not url:
        return []

    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().strip(".")
        port = parsed.port
    except ValueError:
        return []

    if not host:
        return []

    findings: List[Finding] = []

    def add(
        finding_id: str,
        title: str,
        description: str,
        severity: str,
        weight: int,
    ) -> None:
        findings.append(
            Finding(
                id=finding_id,
                title=title,
                description=description,
                severity=severity,
                weight=weight,
                evidence=[clean_quote(url, 200)],
                group=finding_id,
            )
        )

    if parsed.scheme == "http":
        add(
            "url_http",
            "Link isn't encrypted",
            "The link uses http:// instead of https://, so information sent through it "
            "is not encrypted. Real financial sites use https://.",
            "low",
            5,
        )

    if parsed.username or parsed.password or "@" in parsed.netloc:
        add(
            "url_userinfo",
            "Link disguises its destination",
            "The part before the @ in this link can make it look like it points to one "
            "site while actually sending you to another.",
            "high",
            22,
        )

    if _is_ip(host):
        add(
            "url_ip",
            "Link uses a raw IP address",
            "Legitimate financial services use a domain name, not a bare IP address. "
            "This is common in phishing and disposable scam sites.",
            "high",
            20,
        )

    if host.startswith("xn--") or ".xn--" in host:
        add(
            "url_punycode",
            "Link uses a disguised international domain",
            "The domain uses punycode (xn--), which can make a lookalike address appear "
            "as a familiar brand. Check the address carefully.",
            "high",
            18,
        )

    if _is_shortener(host):
        add(
            "url_shortener",
            "Shortened link hides its destination",
            "Short links hide the real website. Expand the link or type the official "
            "address yourself before opening it.",
            "medium",
            12,
        )

    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        add(
            "url_tld",
            "Unusual domain ending",
            f"The .{tld} domain ending is cheap and frequently used for temporary scam "
            "sites. That alone isn't proof, but it is worth checking.",
            "medium",
            10,
        )

    brand = _impersonated_brand(host)
    if brand:
        add(
            "url_brand",
            "Link may impersonate a known brand",
            f"The address contains “{brand}” but is not that company's official domain. "
            "Scammers use lookalike addresses to steal logins and payments.",
            "high",
            20,
        )

    if RISKY_LINK_WORDS.search(unquote(parsed.path) + " " + host):
        add(
            "url_words",
            "Link uses high-pressure or credential terms",
            "The web address contains words often used in fake giveaways, wallet "
            "connection pages, and account-verification scams.",
            "low",
            4,
        )

    path = parsed.path.lower()
    if path.endswith(EXECUTABLE_SUFFIXES):
        add(
            "url_executable",
            "Link downloads an app or installer",
            "The link points directly at an executable file. Installing software from a "
            "message is a common way to get malware. Use the official app store instead.",
            "high",
            25,
        )

    if len(url) > 120:
        add(
            "url_long",
            "Unusually long link",
            "Long links can hide the real destination. Check the domain at the start of "
            "the address before opening it.",
            "low",
            3,
        )

    labels = host.split(".")
    if len(labels) > 3:
        add(
            "url_subdomains",
            "Link uses many subdomains",
            "A long chain of subdomains can push the real domain out of view on a phone "
            "screen. Read the address from the right.",
            "low",
            5,
        )

    if host.count("-") >= 3:
        add(
            "url_hyphens",
            "Domain name is padded with hyphens",
            "Domains with several hyphens are often registered to imitate a brand or "
            "describe an offer. Verify the company independently.",
            "low",
            4,
        )

    if port is not None and port not in (80, 443):
        add(
            "url_port",
            "Link uses an unusual port",
            "The link connects on a non-standard network port. That is unusual for a "
            "normal financial website.",
            "low",
            4,
        )

    return findings


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_shortener(host: str) -> bool:
    return any(host == shortener or host.endswith("." + shortener) for shortener in SHORTENER_HOSTS)


def _registrable_parts(host: str) -> Tuple[str, str]:
    """A small, dependency-free approximation of the registrable domain.

    It handles common two-level suffixes such as co.uk, com.au, and org.uk. It is
    only used for lookalike-brand checks, so a rare suffix being misparsed is
    acceptable.
    """
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {
        "co",
        "com",
        "org",
        "net",
        "gov",
        "ac",
        "edu",
    }:
        return labels[-3], ".".join(labels[-3:])
    if len(labels) >= 2:
        return labels[-2], ".".join(labels[-2:])
    return host, host


def _impersonated_brand(host: str) -> Optional[str]:
    registered_label, _ = _registrable_parts(host)
    labels = host.split(".")
    for brand in BRANDS:
        if brand not in host:
            continue
        if registered_label == brand:
            return None
        in_subdomain = any(brand in label for label in labels[:-2])
        in_registered = brand in registered_label
        if in_subdomain:
            return brand
        if in_registered and (
            "-" in registered_label
            or any(
                word in registered_label
                for word in ("secure", "login", "verify", "support", "account", "update", "wallet", "official")
            )
        ):
            return brand
    return None
