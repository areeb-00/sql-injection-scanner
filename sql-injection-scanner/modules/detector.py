"""
===========================================================
detector.py
SQL injection detection engine
===========================================================
"""

import re

from modules.risk_engine import RiskEngine


class SQLiDetector:
    """Analyze HTTP responses for SQL injection indicators."""

    SQL_ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"mysql_fetch",
        r"mysqli",
        r"postgresql.*error",
        r"pg_query",
        r"sqlite.*error",
        r"sqlite3.*error",
        r"ora-\d{4,5}",
        r"oracle.*error",
        r"microsoft sql server",
        r"odbc sql server driver",
        r"sql syntax.*error",
        r"unclosed quotation mark",
        r"jdbc.*sql"
    ]

    @classmethod
    def detect_sql_errors(cls, body):
        """Search response body for known SQL error signatures."""

        if isinstance(body, bytes):

            body = body.decode(
                "utf-8",
                errors="ignore"
            )

        body = str(body)

        matches = []

        for pattern in cls.SQL_ERROR_PATTERNS:

            if re.search(
                pattern,
                body,
                re.IGNORECASE
            ):
                matches.append(pattern)

        return {
            "detected": bool(matches),
            "matches": matches
        }

    @staticmethod
    def normalize_body(body):
        """Normalize response body for comparison."""

        if isinstance(body, bytes):

            body = body.decode(
                "utf-8",
                errors="ignore"
            )

        return " ".join(
            str(body).split()
        )

    @classmethod
    def calculate_similarity(
        cls,
        first_body,
        second_body
    ):
        """Calculate a lightweight response similarity."""

        first = cls.normalize_body(
            first_body
        )

        second = cls.normalize_body(
            second_body
        )

        if first == second:
            return 1.0

        if not first or not second:
            return 0.0

        shorter = min(
            len(first),
            len(second)
        )

        longer = max(
            len(first),
            len(second)
        )

        matching = 0

        for index in range(shorter):

            if first[index] == second[index]:

                matching += 1

        return matching / longer

    @classmethod
    def analyze_boolean_pair(
        cls,
        true_response,
        false_response
    ):
        """Analyze TRUE/FALSE response behavior."""

        true_body = true_response.get(
            "body",
            b""
        )

        false_body = false_response.get(
            "body",
            b""
        )

        true_status = true_response.get(
            "status_code"
        )

        false_status = false_response.get(
            "status_code"
        )

        true_length = len(
            true_body
        )

        false_length = len(
            false_body
        )

        length_difference = abs(
            true_length - false_length
        )

        status_changed = (
            true_status != false_status
        )

        similarity = cls.calculate_similarity(
            true_body,
            false_body
        )

        significant_difference = (
            status_changed
            or similarity < 0.90
        )

        return {
            "boolean_behavior": significant_difference,
            "true_status": true_status,
            "false_status": false_status,
            "true_length": true_length,
            "false_length": false_length,
            "length_difference": length_difference,
            "similarity": round(
                similarity,
                4
            )
        }

    @staticmethod
    def analyze_timing(
        baseline_response,
        test_response,
        threshold=2.0
    ):
        """
        Analyze response-time difference.

        A timing difference alone is NOT proof of SQL injection.
        """

        baseline_time = baseline_response.get(
            "response_time",
            0.0
        )

        test_time = test_response.get(
            "response_time",
            0.0
        )

        difference = (
            test_time - baseline_time
        )

        delayed = difference >= threshold

        return {
            "baseline_time": round(
                baseline_time,
                4
            ),
            "test_time": round(
                test_time,
                4
            ),
            "difference": round(
                difference,
                4
            ),
            "threshold": threshold,
            "delayed": delayed
        }

    @classmethod
    def analyze(
        cls,
        baseline_response,
        test_response,
        boolean_behavior=False,
        timing_behavior=False
    ):
        """Perform complete response analysis."""

        error_result = cls.detect_sql_errors(
            test_response.get(
                "body",
                b""
            )
        )

        baseline_body = baseline_response.get(
            "body",
            b""
        )

        test_body = test_response.get(
            "body",
            b""
        )

        baseline_length = len(
            baseline_body
        )

        test_length = len(
            test_body
        )

        length_difference = abs(
            baseline_length - test_length
        )

        status_changed = (
            baseline_response.get(
                "status_code"
            )
            != test_response.get(
                "status_code"
            )
        )

        content_changed = (
            cls.normalize_body(
                baseline_body
            )
            != cls.normalize_body(
                test_body
            )
        )

        risk = RiskEngine.calculate_score(
            sql_error=error_result["detected"],
            boolean_behavior=boolean_behavior,
            status_change=status_changed,
            content_change=content_changed
        )

        if timing_behavior:

            risk["score"] = min(
                risk["score"] + 20,
                100
            )

            if (
                risk["severity"] == "NONE"
                or risk["severity"] == "LOW"
            ):

                risk["severity"] = "MEDIUM"

            risk["evidence"].append(
                "Significant response-time delay detected"
            )

        recommendation = (
            RiskEngine.generate_recommendation(
                risk["severity"]
            )
        )

        return {
            "sql_error": error_result,
            "comparison": {
                "status_changed": status_changed,
                "content_changed": content_changed,
                "baseline_length": baseline_length,
                "test_length": test_length,
                "length_difference": length_difference
            },
            "risk": risk,
            "recommendation": recommendation
        }
