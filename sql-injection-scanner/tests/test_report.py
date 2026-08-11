"""
===========================================================
test_reporter.py
Tests for JSON report generation
===========================================================
"""

import json
import os
import tempfile
import unittest

from modules.reporter import ScanReporter


class TestScanReporter(unittest.TestCase):
    """Test ScanReporter functionality."""

    def setUp(self):

        self.temp_directory = tempfile.TemporaryDirectory()

        self.reporter = ScanReporter(
            reports_directory=self.temp_directory.name
        )

    def tearDown(self):

        self.temp_directory.cleanup()

    def test_build_report(self):
        """Report should contain expected sections."""

        parameters = [
            ("id", "10"),
            ("category", "books")
        ]

        baseline = {
            "status_code": 200,
            "body": b"Hello",
            "response_time": 0.5,
            "url": "http://example.com/"
        }

        report = self.reporter.build_report(
            target="http://example.com/?id=10",
            parameters=parameters,
            requests_sent=10,
            findings=[],
            scan_duration=2.5,
            baseline=baseline
        )

        self.assertIn(
            "scanner",
            report
        )

        self.assertIn(
            "scan",
            report
        )

        self.assertIn(
            "target",
            report
        )

        self.assertIn(
            "statistics",
            report
        )

        self.assertEqual(
            report["statistics"]["requests_sent"],
            10
        )

    def test_save_report(self):
        """Report should be saved as valid JSON."""

        report = {
            "test": True
        }

        path = self.reporter.save_report(
            report,
            filename="test_report.json"
        )

        self.assertTrue(
            os.path.exists(path)
        )

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            loaded = json.load(file)

        self.assertEqual(
            loaded["test"],
            True
        )


if __name__ == "__main__":
    unittest.main()
