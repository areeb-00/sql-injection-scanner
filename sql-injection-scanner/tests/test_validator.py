"""
===========================================================
test_validator.py
Tests for URL and input validation
===========================================================
"""

import unittest

from modules.validator import Validator


class TestValidator(unittest.TestCase):
    """Test Validator functionality."""

    def test_valid_http_url(self):
        """HTTP URL should be accepted."""

        valid, result = Validator.validate_url(
            "http://example.com"
        )

        self.assertTrue(valid)

        self.assertEqual(
            result.scheme,
            "http"
        )

    def test_valid_https_url(self):
        """HTTPS URL should be accepted."""

        valid, result = Validator.validate_url(
            "https://example.com"
        )

        self.assertTrue(valid)

        self.assertEqual(
            result.scheme,
            "https"
        )

    def test_empty_url(self):
        """Empty URL should be rejected."""

        valid, message = Validator.validate_url(
            ""
        )

        self.assertFalse(valid)

        self.assertIn(
            "empty",
            message.lower()
        )

    def test_invalid_scheme(self):
        """Unsupported URL schemes should be rejected."""

        valid, message = Validator.validate_url(
            "ftp://example.com"
        )

        self.assertFalse(valid)

    def test_missing_hostname(self):
        """URL without hostname should be rejected."""

        valid, message = Validator.validate_url(
            "http://"
        )

        self.assertFalse(valid)

    def test_markdown_url_rejected(self):
        """Markdown-formatted URLs should be rejected."""

        valid, message = Validator.validate_url(
            "[http://example.com](http://example.com)"
        )

        self.assertFalse(valid)

        self.assertIn(
            "markdown",
            message.lower()
        )

    def test_url_with_spaces_rejected(self):
        """URLs containing spaces should be rejected."""

        valid, message = Validator.validate_url(
            "http://example.com/test page"
        )

        self.assertFalse(valid)

    def test_url_with_newline_rejected(self):
        """URLs containing newline characters should be rejected."""

        valid, message = Validator.validate_url(
            "http://example.com/\n"
        )

        self.assertFalse(valid)

    def test_valid_timeout(self):
        """Positive timeout should be accepted."""

        valid, result = Validator.validate_timeout(
            10
        )

        self.assertTrue(valid)

        self.assertEqual(
            result,
            10
        )

    def test_zero_timeout(self):
        """Zero timeout should be rejected."""

        valid, message = Validator.validate_timeout(
            0
        )

        self.assertFalse(valid)

    def test_negative_timeout(self):
        """Negative timeout should be rejected."""

        valid, message = Validator.validate_timeout(
            -5
        )

        self.assertFalse(valid)

    def test_string_timeout(self):
        """String timeout should be rejected."""

        valid, message = Validator.validate_timeout(
            "10"
        )

        self.assertFalse(valid)

        self.assertIn(
            "number",
            message.lower()
        )


if __name__ == "__main__":
    unittest.main()
