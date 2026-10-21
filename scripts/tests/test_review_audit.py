import json
import os
import tempfile
import unittest

from review_audit import append_human_review


class HumanReviewAuditTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tempdir.name, "reviews.jsonl")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_accepted_decision_records_suggestion_and_human_decision(self):
        record = append_human_review(
            {
                "incident_id": "INC-TEST-001",
                "agent_classification": "suspicious",
                "decision": "accepted",
                "reviewer": "analyst-01",
                "agent_recommendations": ["Review authentication events"],
                "notes": "Evidence was consistent with the triage report.",
            },
            self.log_path,
        )
        self.assertEqual(record["human_decision"], "accepted")
        self.assertEqual(record["final_classification"], "suspicious")
        self.assertEqual(record["agent_recommendations"], ["Review authentication events"])
        with open(self.log_path, "r", encoding="utf-8") as handle:
            saved = json.loads(handle.readline())
        self.assertEqual(saved["incident_id"], "INC-TEST-001")
        self.assertEqual(saved["review_id"], record["review_id"])
        self.assertEqual(os.stat(self.log_path).st_mode & 0o777, 0o600)

    def test_corrected_decision_requires_a_different_final_classification(self):
        payload = {
            "incident_id": "INC-TEST-002",
            "agent_classification": "true_positive",
            "decision": "corrected",
            "reviewer": "analyst-02",
        }
        with self.assertRaisesRegex(ValueError, "requires final_classification"):
            append_human_review(payload, self.log_path)

        payload["final_classification"] = "true_positive"
        with self.assertRaisesRegex(ValueError, "must differ"):
            append_human_review(payload, self.log_path)

        payload["final_classification"] = "suspicious"
        record = append_human_review(payload, self.log_path)
        self.assertEqual(record["human_decision"], "corrected")
        self.assertEqual(record["final_classification"], "suspicious")

    def test_escalated_decision_does_not_claim_a_final_verdict(self):
        record = append_human_review(
            {
                "incident_id": "INC-TEST-003",
                "agent_classification": "suspicious",
                "decision": "escalated",
                "reviewer": "analyst-03",
            },
            self.log_path,
        )
        self.assertEqual(record["human_decision"], "escalated")
        self.assertIsNone(record["final_classification"])

    def test_review_records_are_appended_not_overwritten(self):
        base = {
            "incident_id": "INC-TEST-004",
            "agent_classification": "benign",
            "decision": "accepted",
            "reviewer": "analyst-01",
        }
        append_human_review(base, self.log_path)
        append_human_review({**base, "reviewer": "analyst-02"}, self.log_path)
        with open(self.log_path, "r", encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]
        self.assertEqual(len(records), 2)
        self.assertEqual([item["reviewer"] for item in records], ["analyst-01", "analyst-02"])


if __name__ == "__main__":
    unittest.main()
