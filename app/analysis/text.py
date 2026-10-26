"""Small text utilities shared by the rule and lexicon matchers."""

from __future__ import annotations

import re
from typing import Iterator, List, Tuple

_TOKEN = re.compile(r"[^\W_]+(?:['’][^\W_]+)?", re.UNICODE)

_NEGATION_BEFORE = re.compile(
    r"\b(?:not|never|no|without|cannot|can't|don't|doesn't|won't|isn't|aren't|wasn't|weren't)\b"
    r"(?:\s+\w+){0,3}\s*$",
    re.IGNORECASE,
)


def tokenize(text: str) -> List[str]:
    return [normalize_token(match.group(0)) for match in _TOKEN.finditer(text)]


def tokenize_with_spans(text: str) -> Iterator[Tuple[str, int, int]]:
    for match in _TOKEN.finditer(text):
        yield normalize_token(match.group(0)), match.start(), match.end()


def normalize_token(token: str) -> str:
    return token.replace("’", "'").casefold()


def is_negated(text: str, start: int) -> bool:
    prefix = text[max(0, start - 50) : start]
    return bool(_NEGATION_BEFORE.search(prefix))


def clean_quote(text: str, limit: int = 160) -> str:
    quote = " ".join(text.split())
    if len(quote) > limit:
        quote = quote[: limit - 1].rstrip() + "…"
    return quote
