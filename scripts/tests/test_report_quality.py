import unittest

from report_quality import (
    append_output_quality_gate,
    enforce_runtime_containment_status,
    evaluate_report_quality,
)


VALID_REPORT = """# Incident Investigation Report

### 1. Incident Classification & Severity Level
* **Classification**: **SUSPICIOUS**
* **Severity Level**: **HIGH**

### 2. Analysis & Technical Findings
Observed evidence only.

### 3. MITRE ATT&CK Mapping
No technique mapped.

### 4. Historical Memory Context (Vector DB)
No reviewed match available.

### 5. Containment & Remediation Status
1. **Host Isolation**: EXECUTED_AND_VERIFIED

### 6. Recommended Next Steps for Human Analysts
1. Review the evidence.

### 7. Diagnostic & Audit Notes
Provider status not checked.
"""


class ReportQualityTests(unittest.TestCase):
    def test_runtime_containment_status_overrides_model_claim(self):
        report = enforce_runtime_containment_status(VALID_REPORT)
        containment_section = report.split("### 5. Containment & Remediation Status", 1)[1].split("### 6.", 1)[0]
        self.assertIn("NOT_EXECUTED", containment_section)
        self.assertNotIn("EXECUTED_AND_VERIFIED", containment_section)
        self.assertIn("read-only investigation tools", containment_section)

    def test_complete_report_passes_format_gate(self):
        passed, issues = evaluate_report_quality(VALID_REPORT)
        self.assertTrue(passed)
        self.assertEqual(issues, [])
        gated = append_output_quality_gate(VALID_REPORT)
        self.assertIn("Status: PASS", gated)

    def test_incomplete_report_requires_human_review(self):
        passed, issues = evaluate_report_quality("# Incident Investigation Report\nInsufficient details.")
        self.assertFalse(passed)
        self.assertTrue(any("classification" in issue.lower() for issue in issues))
        gated = append_output_quality_gate("# Incident Investigation Report\nInsufficient details.")
        self.assertIn("REVIEW_REQUIRED", gated)
        self.assertIn("Human review is required", gated)


if __name__ == "__main__":
    unittest.main()
