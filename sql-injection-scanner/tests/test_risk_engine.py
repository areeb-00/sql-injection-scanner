"""
===========================================================
test_risk_engine.py
Tests for risk scoring
===========================================================
"""

import unittest

from modules.risk_engine import RiskEngine


class TestRiskEngine(unittest.TestCase):
    """Test RiskEngine functionality."""

    def test_no_evidence(self):
        """No evidence should produce NONE."""

        result = RiskEngine.calculate_score()

        self.assertEqual(
            result["score"],
            0
        )

        self.assertEqual(
            result["severity"],
            "NONE"
        )

    def test_sql_error(self):
        """SQL error evidence should produce high risk."""

        result = RiskEngine.calculate_score(
            sql_error=True
        )

        self.assertEqual(
            result["score"],
            70
        )

        self.assertEqual(
            result["severity"],
            "HIGH"
        )

    def test_boolean_behavior(self):
        """Boolean evidence should contribute to score."""

        result = RiskEngine.calculate_score(
            boolean_behavior=True
        )

        self.assertEqual(
            result["score"],
            25
        )

        self.assertEqual(
            result["severity"],
            "LOW"
        )

    def test_combined_evidence(self):
        """Multiple evidence types should combine."""

        result = RiskEngine.calculate_score(
            sql_error=True,
            boolean_behavior=True
        )

        self.assertEqual(
            result["score"],
            95
        )

        self.assertEqual(
            result["severity"],
            "HIGH"
        )

    def test_score_cap(self):
        """Score should never exceed 100."""

        result = RiskEngine.calculate_score(
            sql_error=True,
            boolean_behavior=True,
            status_change=True,
            content_change=True
        )

        self.assertLessEqual(
            result["score"],
            100
        )

    def test_recommendations(self):
        """Every severity should have a recommendation."""

        severities = [
            "HIGH",
            "MEDIUM",
            "LOW",
            "NONE"
        ]

        for severity in severities:

            recommendation = (
                RiskEngine.generate_recommendation(
                    severity
                )
            )

            self.assertTrue(
                recommendation
            )


if __name__ == "__main__":
    unittest.main()
