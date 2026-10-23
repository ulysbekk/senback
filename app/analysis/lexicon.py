"""Phrase-corpus matching with token-level Aho-Corasick.

A flat bag of suspicious words produces too many false positives ("never ask for
your password" is a safe sentence). This layer instead matches curated phrases at
token boundaries, ignores negated matches, weights phrases by specificity, and
caps how much any one category can contribute.

The output is still a list of Findings, so it composes with the rule engine and
the URL checks. Categories that map to an existing rule group are merged into
that warning instead of producing a duplicate.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Tuple

from .text import clean_quote, is_negated, tokenize, tokenize_with_spans
from .types import SEVERITY_RANK, Finding

logger = logging.getLogger(__name__)

# No single category can add more than this. Repetition and keyword stuffing
# should not turn into a high score by themselves.
CATEGORY_CAP = 18

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "scam_phrases.json"


@dataclass(frozen=True)
class Category:
    id: str
    title: str
    description: str
    default_severity: str
    rule_group: Optional[str] = None
    cap: int = CATEGORY_CAP


@dataclass(frozen=True)
class Phrase:
    text: str
    category: str
    weight: int
    severity: str


@dataclass
class PhraseMatch:
    phrase: Phrase
    evidence: str
    start: int
    end: int


@dataclass
class LexiconResult:
    findings: List[Finding] = field(default_factory=list)
    matches: List[PhraseMatch] = field(default_factory=list)
    category_scores: Dict[str, int] = field(default_factory=dict)


class _Node:
    __slots__ = ("children", "fail", "outputs")

    def __init__(self) -> None:
        self.children: Dict[str, "_Node"] = {}
        self.fail: Optional["_Node"] = None
        self.outputs: List[Tuple[int, int]] = []  # (phrase index, token length)


class PhraseMatcher:
    """Aho-Corasick over normalized tokens, so one pass finds every phrase."""

    def __init__(self, phrases: Iterable[Phrase]) -> None:
        self.phrases = list(phrases)
        self.root = _Node()
        self.root.fail = self.root

        for index, phrase in enumerate(self.phrases):
            tokens = tokenize(phrase.text)
            if not tokens:
                continue
            node = self.root
            for token in tokens:
                node = node.children.setdefault(token, _Node())
            node.outputs.append((index, len(tokens)))

        self._build_failure_links()

    def _build_failure_links(self) -> None:
        queue: Deque[_Node] = deque()
        for child in self.root.children.values():
            child.fail = self.root
            queue.append(child)

        while queue:
            current = queue.popleft()
            for token, child in current.children.items():
                queue.append(child)
                fallback = current.fail or self.root
                while fallback is not self.root and token not in fallback.children:
                    fallback = fallback.fail or self.root
                child.fail = fallback.children.get(token, self.root)
                child.outputs = child.outputs + child.fail.outputs

    def find(self, text: str) -> List[PhraseMatch]:
        tokens = list(tokenize_with_spans(text))
        if not tokens:
            return []

        matches: List[PhraseMatch] = []
        state = self.root
        for index, (token, _, end) in enumerate(tokens):
            while state is not self.root and token not in state.children:
                state = state.fail or self.root
            state = state.children.get(token, self.root)

            for phrase_index, length in state.outputs:
                start_index = index - length + 1
                if start_index < 0:
                    continue
                char_start = tokens[start_index][1]
                if is_negated(text, char_start):
                    continue
                matches.append(
                    PhraseMatch(
                        phrase=self.phrases[phrase_index],
                        evidence=text[char_start:end],
                        start=char_start,
                        end=end,
                    )
                )
        return matches


class Lexicon:
    def __init__(self, categories: Dict[str, Category], phrases: List[Phrase]) -> None:
        self.categories = categories
        self.phrases = phrases
        self.matcher = PhraseMatcher(phrases)

    @classmethod
    def from_file(cls, path: Path) -> "Lexicon":
        data = json.loads(path.read_text(encoding="utf-8"))
        raw_categories = data.get("categories", {})
        categories: Dict[str, Category] = {}
        for category_id, raw in raw_categories.items():
            categories[category_id] = Category(
                id=category_id,
                title=str(raw.get("title") or category_id.replace("_", " ").title()),
                description=str(raw.get("description") or "Known scam wording."),
                default_severity=str(raw.get("default_severity") or "medium"),
                rule_group=raw.get("rule_group"),
                cap=max(0, int(raw.get("cap", CATEGORY_CAP))),
            )

        phrases: List[Phrase] = []
        seen = set()
        for raw in data.get("phrases", []):
            text = str(raw.get("text") or "").strip()
            category_id = str(raw.get("category") or "")
            if not text or category_id not in categories:
                continue
            key = (text.casefold(), category_id)
            if key in seen:
                continue
            seen.add(key)
            severity = str(raw.get("severity") or categories[category_id].default_severity)
            phrases.append(
                Phrase(
                    text=text,
                    category=category_id,
                    weight=max(0, int(raw.get("weight", 0))),
                    severity=severity,
                )
            )

        return cls(categories=categories, phrases=phrases)

    @classmethod
    def empty(cls) -> "Lexicon":
        return cls(categories={}, phrases=[])

    def assess(self, text: str) -> LexiconResult:
        if not self.phrases:
            return LexiconResult()

        matches = self.matcher.find(text)
        by_category: Dict[str, List[PhraseMatch]] = defaultdict(list)
        for match in matches:
            by_category[match.phrase.category].append(match)

        findings: List[Finding] = []
        category_scores: Dict[str, int] = {}
        for category_id, category_matches in by_category.items():
            selected = _best_non_overlapping(category_matches)
            category = self.categories[category_id]
            score = min(category.cap, sum(match.phrase.weight for match in selected))
            if score <= 0:
                continue
            severity = max(
                (match.phrase.severity for match in selected),
                key=lambda value: SEVERITY_RANK.get(value, 0),
            )
            evidence: List[str] = []
            for match in sorted(selected, key=lambda item: (-item.phrase.weight, item.start)):
                quote = clean_quote(match.evidence)
                if quote and quote.casefold() not in {item.casefold() for item in evidence}:
                    evidence.append(quote)
                if len(evidence) >= 3:
                    break

            category_scores[category_id] = score
            findings.append(
                Finding(
                    id=f"lexicon_{category_id}",
                    title=category.title,
                    description=category.description,
                    severity=severity,
                    weight=score,
                    evidence=evidence,
                    group=category.rule_group,
                )
            )

        return LexiconResult(
            findings=findings,
            matches=matches,
            category_scores=category_scores,
        )


def _best_non_overlapping(matches: List[PhraseMatch]) -> List[PhraseMatch]:
    """Prefer the most specific phrase when matches overlap.

    "guaranteed" and "guaranteed returns" should not both add weight to the same
    category. Greedy by weight, then length, is enough for this corpus size.
    """
    selected: List[PhraseMatch] = []
    for match in sorted(
        matches,
        key=lambda item: (-item.phrase.weight, -(item.end - item.start), item.start),
    ):
        if all(match.end <= other.start or match.start >= other.end for other in selected):
            selected.append(match)
    return sorted(selected, key=lambda item: item.start)


@lru_cache(maxsize=1)
def get_lexicon() -> Lexicon:
    try:
        return Lexicon.from_file(_DATA_PATH)
    except Exception as error:  # noqa: BLE001 - malformed data must not take the API down
        logger.exception("Could not load scam phrase corpus from %s: %s", _DATA_PATH, error)
        return Lexicon.empty()
