"""Shared analysis types.

We use a small dataclass instead of Pydantic for internal findings so the rule
engine has no framework dependency and is easy to unit test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

SEVERITIES = ("low", "medium", "high", "critical")

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# A single strong warning should not produce a "low risk" label just because its
# weight is small. These floors keep score and severity consistent.
SEVERITY_FLOOR = {"low": 0, "medium": 25, "high": 50, "critical": 75}


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: str
    weight: int
    evidence: List[str] = field(default_factory=list)
    # Findings that describe the same behavior share a group. The merger uses
    # this to avoid emitting two warnings for, say, a rule and a lexicon phrase.
    group: Optional[str] = None

    def sort_key(self) -> tuple:
        return (-SEVERITY_RANK.get(self.severity, 0), -self.weight, self.title)
