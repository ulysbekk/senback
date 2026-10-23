#!/usr/bin/env python3
"""Evaluate the deterministic Sentinel engine against labelled message datasets.

This script is deliberately dataset-agnostic. Public scam/phishing corpora use
many different label spellings (``spam``, ``Spam``, ``smishing``, ``Smishing``,
``phishing``, ``ham``, ``0``/``1``), so the label is normalised to ``scam`` or
``ham`` before scoring.

Raw datasets are not committed: they contain real phone numbers, email
addresses, and personal messages. They live in ``benchmarks/data`` (gitignored)
and are described by ``benchmarks/manifests/*.json``.

Usage:
    python -m benchmarks.evaluate --list
    python -m benchmarks.evaluate uci_sms
    python -m benchmarks.evaluate --thresholds 25,50,75 uci_sms sms_5971
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# Enron-Spam contains very long email bodies; raise csv's per-field ceiling.
csv.field_size_limit(10 * 1024 * 1024)

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.analysis.engine import AnalysisEngine  # noqa: E402
from app.analysis.lexicon import get_lexicon  # noqa: E402
from app.analysis.rules import analyze_url, detect_rules  # noqa: E402
from app.analysis.scoring import build_response, dedupe, merge_findings  # noqa: E402
from app.config import Settings  # noqa: E402

MANIFEST_DIR = Path(__file__).resolve().parent / "manifests"
DATA_DIR = Path(__file__).resolve().parent / "data"

# Label values that mean "this is a scam/phishing/spam message".
SCAM_LABELS = {
    "scam",
    "smishing",
    "phishing",
    "spam",
    "fraud",
    "malicious",
    "1",
    "yes",
    "bad",
}
HAM_LABELS = {"ham", "legitimate", "legit", "not spam", "notspam", "0", "no", "good", "benign"}

_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)


@dataclass
class Example:
    text: str
    label: str  # "scam" or "ham"
    url: Optional[str] = None


@dataclass
class DatasetReport:
    name: str
    total: int
    scam_total: int
    ham_total: int
    metrics: Dict[int, Dict[str, float]] = field(default_factory=dict)
    missed_scams: List[Tuple[int, str]] = field(default_factory=list)
    false_alarms: List[Tuple[int, str]] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "total": self.total,
            "scam_total": self.scam_total,
            "ham_total": self.ham_total,
            "metrics": {str(k): v for k, v in self.metrics.items()},
            "missed_scams": [{"score": s, "text": t} for s, t in self.missed_scams[:20]],
            "false_alarms": [{"score": s, "text": t} for s, t in self.false_alarms[:20]],
        }


def normalize_label(raw: object) -> Optional[str]:
    value = str(raw or "").strip().casefold()
    if not value:
        return None
    if value in SCAM_LABELS:
        return "scam"
    if value in HAM_LABELS:
        return "ham"
    # Handle labels like "spam message" or "phishing email".
    if "phish" in value or "smish" in value or "spam" in value or "scam" in value:
        return "scam"
    if "ham" in value or "legit" in value:
        return "ham"
    return None


def _pick(record: dict, keys: Sequence[str]) -> Optional[str]:
    lowered = {str(k).strip().casefold(): v for k, v in record.items() if k is not None}
    for key in keys:
        value = lowered.get(key.casefold())
        if value not in (None, ""):
            return str(value)
    return None


def _pick_all(record: dict, keys: Sequence[str]) -> Optional[str]:
    """Join every matching column, so email subject and body are both scored."""
    lowered = {str(k).strip().casefold(): v for k, v in record.items() if k is not None}
    parts = []
    for key in keys:
        value = lowered.get(key.casefold())
        if value not in (None, ""):
            parts.append(str(value))
    return "\n".join(parts) if parts else None


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def list_manifests() -> List[Path]:
    return sorted(MANIFEST_DIR.glob("*.json"))


def load_dataset(manifest: dict) -> List[Example]:
    dataset_path = DATA_DIR / manifest["file"]
    delimiter = str(manifest.get("delimiter", ","))
    encoding = str(manifest.get("encoding", "utf-8"))
    errors = str(manifest.get("errors", "replace"))
    has_header = bool(manifest.get("has_header", True))
    text_keys = manifest.get("text_columns", ["text", "message", "body", "v2", "email"])
    label_keys = manifest.get("label_columns", ["label", "class", "category", "v1", "spam"])
    url_keys = manifest.get("url_columns", ["url", "link"])
    text_prefix = manifest.get("text_prefix", "")
    text_suffix = manifest.get("text_suffix", "")
    default_label = manifest.get("default_label")
    examples: List[Example] = []
    # Some public corpora (notably Enron-Spam) contain stray NUL bytes that make
    # Python's csv module raise, so scrub them before parsing.
    with dataset_path.open("r", encoding=encoding, errors=errors, newline="") as handle:
        clean_lines = (line.replace("\x00", "") for line in handle)
        if has_header:
            reader: Iterable[dict] = csv.DictReader(clean_lines, delimiter=delimiter)
        else:
            reader = (
                {"v1": row[0], "v2": row[1]}
                for row in csv.reader(clean_lines, delimiter=delimiter)
                if len(row) >= 2
            )

        for record in reader:
            label = normalize_label(_pick(record, label_keys))
            if label is None and default_label:
                label = normalize_label(default_label)
            if label is None:
                continue
            body = _pick_all(record, text_keys)
            if not body or body.strip() == "*":
                continue
            text = f"{text_prefix}{body}{text_suffix}".strip()
            if not text:
                continue
            examples.append(Example(text=text, label=label, url=_pick(record, url_keys)))

    return examples


def extract_url(text: str, provided: Optional[str]) -> Optional[str]:
    if provided and provided.strip().casefold() not in {"no", "none", "false", ""}:
        return provided.strip()
    match = _URL_RE.search(text)
    return match.group(0).rstrip(".,)") if match else None


def score_engine(engine: AnalysisEngine, example: Example, with_llm: bool = False) -> int:
    import asyncio

    response = asyncio.run(
        engine.analyze(example.text, extract_url(example.text, example.url))
    )
    return response.risk_score


def score_text(text: str, url: Optional[str] = None) -> int:
    """Deterministic scoring without the optional LLM (fast enough for corpora)."""
    findings = detect_rules(text)
    findings = merge_findings(findings, get_lexicon().assess(text).findings)
    findings = dedupe(findings)
    findings.extend(analyze_url(url))
    return build_response(findings).risk_score


def evaluate_dataset(name: str, examples: Sequence[Example], thresholds: Sequence[int]) -> DatasetReport:
    """Score a dataset directly with the deterministic engine.

    This avoids per-message async setup and never calls an LLM, so a 68k-message
    corpus still finishes in a couple of minutes.
    """
    scored = []
    for example in examples:
        url = extract_url(example.text, example.url)
        scored.append((example.label, score_text(example.text, url), example.text))
    return _report(name, scored, thresholds)


def evaluate(
    name: str,
    examples: Sequence[Example],
    thresholds: Sequence[int],
    engine: AnalysisEngine,
) -> DatasetReport:
    scored = [(example.label, score_engine(engine, example), example.text) for example in examples]
    return _report(name, scored, thresholds)


def _report(
    name: str,
    scored: Sequence[Tuple[str, int, str]],
    thresholds: Sequence[int],
) -> DatasetReport:
    scam_total = sum(1 for label, _, _ in scored if label == "scam")
    ham_total = sum(1 for label, _, _ in scored if label == "ham")

    metrics: Dict[int, Dict[str, float]] = {}
    for threshold in thresholds:
        tp = sum(1 for label, score, _ in scored if label == "scam" and score >= threshold)
        fp = sum(1 for label, score, _ in scored if label == "ham" and score >= threshold)
        fn = scam_total - tp
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / scam_total if scam_total else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        metrics[threshold] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "accuracy": round(
                (sum(1 for label, s, _ in scored if (s >= threshold) == (label == "scam"))) / len(scored),
                4,
            )
            if scored
            else 0.0,
        }

    primary = int(thresholds[len(thresholds) // 2])
    missed = sorted(
        [(score, text) for label, score, text in scored if label == "scam" and score < primary],
        key=lambda item: item[0],
    )[:20]
    false_alarms = sorted(
        [(score, text) for label, score, text in scored if label == "ham" and score >= primary],
        key=lambda item: -item[0],
    )[:20]

    return DatasetReport(
        name=name,
        total=len(scored),
        scam_total=scam_total,
        ham_total=ham_total,
        metrics=metrics,
        missed_scams=missed,
        false_alarms=false_alarms,
    )


def print_report(report: DatasetReport, thresholds: Sequence[int]) -> None:
    print(f"\n=== {report.name} ===")
    print(f"messages: {report.total}  (scam={report.scam_total}, ham={report.ham_total})")
    header = "threshold  precision  recall   f1     tp    fp    fn"
    print(header)
    for threshold in thresholds:
        row = report.metrics[threshold]
        print(
            f"{threshold:^9}  {row['precision']:^9.3f}  {row['recall']:^6.3f}  {row['f1']:^6.3f} "
            f"{row['tp']:^5} {row['fp']:^5} {row['fn']:^5}"
        )
    if report.false_alarms:
        print("\nfalse alarms (ham scored high):")
        for score, text in report.false_alarms[:5]:
            print(f"  [{score}] {text[:120]!r}")
    if report.missed_scams:
        print("\nmissed scams (lowest scores):")
        for score, text in report.missed_scams[:5]:
            print(f"  [{score}] {text[:120]!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("datasets", nargs="*", help="manifest names without .json")
    parser.add_argument("--list", action="store_true", help="list available dataset manifests")
    parser.add_argument("--thresholds", default="25,50,75", help="comma-separated score thresholds")
    parser.add_argument("--json", help="write a JSON report to this path")
    args = parser.parse_args()

    thresholds = [int(value) for value in args.thresholds.split(",") if value.strip()]
    manifests = list_manifests()

    if args.list or not manifests:
        print("available datasets:")
        for path in manifests:
            manifest = load_manifest(path)
            status = "present" if (DATA_DIR / manifest["file"]).exists() else "MISSING"
            print(f"  {path.stem:<24} {status:<8} {manifest.get('description', '')}")
        print("\nrun: python -m benchmarks.download --all")
        return 0

    selected = args.datasets or [path.stem for path in manifests]
    engine = AnalysisEngine(Settings())
    reports = []

    for name in selected:
        manifest_path = MANIFEST_DIR / f"{name}.json"
        if not manifest_path.exists():
            print(f"unknown dataset: {name}", file=sys.stderr)
            return 2
        manifest = load_manifest(manifest_path)
        if not (DATA_DIR / manifest["file"]).exists():
            print(f"dataset file missing for {name}: run `python -m benchmarks.download {name}`", file=sys.stderr)
            continue
        examples = load_dataset(manifest)
        report = evaluate_dataset(name, examples, thresholds)
        print_report(report, thresholds)
        reports.append(report)

    if args.json:
        Path(args.json).write_text(
            json.dumps([report.as_dict() for report in reports], indent=2), encoding="utf-8"
        )
        print(f"\nwrote {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
