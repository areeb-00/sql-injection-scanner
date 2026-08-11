"""
===========================================================
risk_engine.py
Evidence scoring and risk classification for SQLi Scanner
===========================================================
"""


class RiskEngine:
    """Calculate SQL injection risk from collected evidence."""

    WEIGHTS = {
        "sql_error": 70,
        "boolean_behavior": 25,
        "status_change": 10,
        "content_change": 5
    }

    @classmethod
    def calculate_score(
        cls,
        sql_error=False,
        boolean_behavior=False,
        status_change=False,
        content_change=False
    ):
        """Calculate a weighted evidence score."""

        score = 0
        evidence = []

        if sql_error:
            score += cls.WEIGHTS["sql_error"]
            evidence.append(
                "SQL error signature detected"
            )

        if boolean_behavior:
            score += cls.WEIGHTS["boolean_behavior"]
            evidence.append(
                "Consistent boolean response behavior detected"
            )

        if status_change:
            score += cls.WEIGHTS["status_change"]
            evidence.append(
                "HTTP status code changed"
            )

        if content_change:
            score += cls.WEIGHTS["content_change"]
            evidence.append(
                "Response content changed"
            )

        if score >= 70:
            severity = "HIGH"

        elif score >= 40:
            severity = "MEDIUM"

        elif score > 0:
            severity = "LOW"

        else:
            severity = "NONE"

        return {
            "score": min(score, 100),
            "severity": severity,
            "evidence": evidence
        }

    @staticmethod
    def generate_recommendation(severity):
        """Generate a recommendation based on severity."""

        recommendations = {
            "HIGH": (
                "Potential SQL injection requires immediate "
                "manual verification."
            ),
            "MEDIUM": (
                "Suspicious behavior detected. Perform "
                "manual verification."
            ),
            "LOW": (
                "Weak indicator detected. Additional testing "
                "is recommended."
            ),
            "NONE": (
                "No significant SQL injection evidence detected."
            )
        }

        return recommendations.get(
            severity,
            recommendations["NONE"]
        )
