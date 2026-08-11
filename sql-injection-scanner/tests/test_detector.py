"""
===========================================================
test_detector.py
Tests for SQL injection detection logic
===========================================================
"""

import unittest

from modules.detector import SQLiDetector


class TestSQLiDetector(unittest.TestCase):
    """Test SQLiDetector functionality."""

    def create_response(
        self,
        body,
        status_code=200,
        response_time=0.5
    ):
        """Create a mock HTTP response."""

        return {
            "success": True,
            "status_code": status_code,
            "headers": {
                "Content-Type": "text/html"
            },
            "body": body,
            "url": "http://example.com/",
            "response_time": response_time,
            "error": None
        }

    def test_mysql_error_detection(self):
        """MySQL error should be detected."""

        body = (
            "You have an error in your SQL syntax"
        )

        result = SQLiDetector.detect_sql_errors(
            body
        )

        self.assertTrue(
            result["detected"]
        )

    def test_clean_response(self):
        """Normal response should not trigger SQL detection."""

        body = (
            "<html><body>Hello World</body></html>"
        )

        result = SQLiDetector.detect_sql_errors(
            body
        )

        self.assertFalse(
            result["detected"]
        )

    def test_response_similarity_identical(self):
        """Identical responses should have similarity 1."""

        result = SQLiDetector.calculate_similarity(
            "Hello World",
            "Hello World"
        )

        self.assertEqual(
            result,
            1.0
        )

    def test_response_similarity_different(self):
        """Different responses should have lower similarity."""

        result = SQLiDetector.calculate_similarity(
            "Hello World",
            "Completely different content"
        )

        self.assertLess(
            result,
            1.0
        )

    def test_boolean_pair_identical(self):
        """Identical TRUE/FALSE responses should not trigger."""

        response_a = self.create_response(
            "same content"
        )

        response_b = self.create_response(
            "same content"
        )

        result = SQLiDetector.analyze_boolean_pair(
            response_a,
            response_b
        )

        self.assertFalse(
            result["boolean_behavior"]
        )

        self.assertEqual(
            result["similarity"],
            1.0
        )

    def test_boolean_pair_different(self):
        """Different TRUE/FALSE responses should trigger."""

        response_a = self.create_response(
            "normal product page"
        )

        response_b = self.create_response(
            "no products found"
        )

        result = SQLiDetector.analyze_boolean_pair(
            response_a,
            response_b
        )

        self.assertTrue(
            result["boolean_behavior"]
        )

    def test_timing_detection(self):
        """Significant delay should be detected."""

        baseline = self.create_response(
            "normal",
            response_time=0.5
        )

        delayed = self.create_response(
            "normal",
            response_time=3.0
        )

        result = SQLiDetector.analyze_timing(
            baseline,
            delayed,
            threshold=2.0
        )

        self.assertTrue(
            result["delayed"]
        )

    def test_normal_timing(self):
        """Small timing variation should not trigger."""

        baseline = self.create_response(
            "normal",
            response_time=0.5
        )

        test = self.create_response(
            "normal",
            response_time=0.8
        )

        result = SQLiDetector.analyze_timing(
            baseline,
            test,
            threshold=2.0
        )

        self.assertFalse(
            result["delayed"]
        )


if __name__ == "__main__":
    unittest.main()

