import unittest

from scripts.grc.scoring import calculate_risk_score


class RiskScoringTests(unittest.TestCase):
    def test_risk_bands(self):
        cases = [
            (1, 1, (1, "Low")),
            (2, 2, (4, "Low")),
            (3, 3, (9, "Medium")),
            (4, 3, (12, "High")),
            (5, 5, (25, "Critical")),
        ]
        for likelihood, impact, expected in cases:
            with self.subTest(likelihood=likelihood, impact=impact):
                self.assertEqual(calculate_risk_score(likelihood, impact), expected)

    def test_rejects_values_outside_the_5x5_matrix(self):
        for likelihood, impact in [(0, 3), (6, 2), (2, 0), (3, 6)]:
            with self.subTest(likelihood=likelihood, impact=impact):
                with self.assertRaises(ValueError):
                    calculate_risk_score(likelihood, impact)


if __name__ == "__main__":
    unittest.main()
