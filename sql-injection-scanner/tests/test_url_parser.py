"""
===========================================================
test_url_parser.py
Tests for URL parsing
===========================================================
"""

import unittest

from modules.url_parser import URLParser


class TestURLParser(unittest.TestCase):
    """Test URLParser functionality."""

    def setUp(self):
        self.url = (
            "http://example.com/"
            "?id=10&category=books"
        )

    def test_parameter_extraction(self):
        """Query parameters should be extracted correctly."""

        parameters = URLParser.get_parameters(
            self.url
        )

        self.assertEqual(
            parameters,
            [
                ("id", "10"),
                ("category", "books")
            ]
        )

    def test_parse_url(self):
        """URL should be parsed into structured data."""

        result = URLParser.parse(
            self.url
        )

        self.assertEqual(
            result["hostname"],
            "example.com"
        )

        self.assertEqual(
            len(result["parameters"]),
            2
        )

    def test_replace_parameter(self):
        """A selected parameter should be replaceable."""

        result = URLParser.replace_parameter(
            self.url,
            "id",
            "20"
        )

        parameters = URLParser.get_parameters(
            result
        )

        self.assertIn(
            ("id", "20"),
            parameters
        )

        self.assertIn(
            ("category", "books"),
            parameters
        )

    def test_build_url(self):
        """URL should be correctly rebuilt."""

        result = URLParser.build_url(
            "http://example.com/",
            [
                ("id", "50"),
                ("page", "2")
            ]
        )

        self.assertEqual(
            result,
            "http://example.com/?id=50&page=2"
        )

    def test_empty_query(self):
        """URL without parameters should return empty list."""

        parameters = URLParser.get_parameters(
            "http://example.com/"
        )

        self.assertEqual(
            parameters,
            []
        )


if __name__ == "__main__":
    unittest.main()
