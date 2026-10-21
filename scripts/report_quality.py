"""Runtime quality gates for SHAM AI incident reports.

These checks complement model instructions with deterministic safeguards.
They do not prove that a security classification is factually correct.
"""
from __future__ import annotations

import re
from typing import List, Tuple


_SECTION_PATTERNS = [
    ("incident classification", r"^###\s*1\.\s*Incident Classification"),
    ("technical analysis", r"^###\s*2\.\s*Analysis"),
    ("MITRE mapping", r"^###\s*3\.\s*MITRE"),
    ("historical memory context", r"^###\s*4\.\s*Historical"),
    ("containment status", r"^###\s*5\.\s*Containment"),
    ("human analyst recommendations", r"^###\s*6\.\s*Recommended"),
    ("diagnostic and audit notes", r"^###\s*7\.\s*Diagnostic"),
]
_CLASSIFICATION_PATTERN = re.compile(
    r"(?im)^\s*\*?\s*\*\*Classification\*\*\s*:\s*\**\s*"
    r"(TRUE POSITIVE|FALSE POSITIVE|SUSPICIOUS|BENIGN)\b"
)
_CONTAINMENT_SECTION = re.compile(
    r"(?ims)^###\s*5\.\s*Containment\s*(?:&|and)\s*Remediation\s*Status\s*\n"
    r".*?(?=^###\s*6\.|\Z)"
)

_VERIFIED_CONTAINMENT_SECTION = """### 5. Containment & Remediation Status
1. **Host isolation / network blocking**: NOT_EXECUTED. This version exposes read-only investigation tools to the model; no containment action was executed.
2. **Response actions**: Recommendations only. A human analyst must review and authorize any consequential response.
"""


def enforce_runtime_containment_status(report_text: str) -> str:
    """Replace model-authored containment claims with the orchestrator's verified status."""
    text = str(report_text or "").rstrip()
    if _CONTAINMENT_SECTION.search(text):
        return _CONTAINMENT_SECTION.sub(_VERIFIED_CONTAINMENT_SECTION + "\n", text, count=1)

    # If the model omitted section 5, insert the verified status before section 6 when possible.
    section_six = re.search(r"(?m)^###\s*6\.", text)
    if section_six:
        return text[:section_six.start()] + _VERIFIED_CONTAINMENT_SECTION + "\n" + text[section_six.start():]
    return (text + "\n\n" + _VERIFIED_CONTAINMENT_SECTION).strip() + "\n"


def evaluate_report_quality(report_text: str) -> Tuple[bool, List[str]]:
    """Check report structure and explicit classification; not a substitute for analyst review."""
    text = str(report_text or "")
    issues: List[str] = []
    if not re.search(r"(?im)^#\s+Incident Investigation Report\b", text):
        issues.append("Missing report title.")
    for label, pattern in _SECTION_PATTERNS:
        if not re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            issues.append("Missing required section: {}.".format(label))
    if not _CLASSIFICATION_PATTERN.search(text):
        issues.append("No supported explicit classification was found.")
    return not issues, issues


def append_output_quality_gate(report_text: str) -> str:
    """Append a transparent quality-gate result for the dashboard and audit record."""
    text = str(report_text or "").rstrip()
    passed, issues = evaluate_report_quality(text)
    if passed:
        details = "- Status: PASS. Required headings and an explicit classification are present. This is a format check, not proof that the findings are correct."
    else:
        details = "- Status: REVIEW_REQUIRED. Human review is required before relying on this report.\n" + "\n".join(
            "- " + issue for issue in issues
        )
    return text + "\n\n### 10. Automated Output Quality Gate\n" + details + "\n"
