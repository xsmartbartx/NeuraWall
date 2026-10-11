"""Pins what the Tier 2 injection detector does with known evasion techniques.

A failure here means the detector changed. Update `tests/evasion_corpus.py` (the expected outcome
and note), then regenerate the report: `uv run python scripts/evasion_report.py`.
"""

import importlib.util
from pathlib import Path

import pytest

from tests.evasion_corpus import CASES

_spec = importlib.util.spec_from_file_location(
    "evasion_report", Path(__file__).resolve().parents[2] / "scripts" / "evasion_report.py"
)
report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report)


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c.klass}: {c.technique}")
def test_outcome_is_the_documented_one(case):
    outcome, confidence = report.measure(case)
    assert outcome == case.expect, f"{outcome} at {confidence:.2f}"


def test_the_published_report_is_current():
    assert report.OUT.exists() and report.OUT.read_text() == report.render(), (
        "docs/evasion-report.md is out of date: run scripts/evasion_report.py"
    )


def test_every_class_has_a_baseline_the_detector_flags_at_alert_grade():
    """Sanity: if the baselines stop being caught, the corpus itself is broken."""
    baselines = {
        "SQL injection": "baseline UNION SELECT",
        "Command injection": "separator + cat",
        "Template injection": "Jinja introspection",
        "Path traversal": "dot-dot-slash, three levels",
    }
    for klass, technique in baselines.items():
        case = next(c for c in CASES if c.klass == klass and c.technique == technique)
        assert report.measure(case)[0] == "alert", (klass, technique)


def test_the_corpus_has_both_catches_and_misses():
    expects = {c.expect for c in CASES}
    assert expects == {"alert", "caught", "missed"}
