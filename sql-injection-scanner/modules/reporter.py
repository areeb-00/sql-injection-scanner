"""
===========================================================
reporter.py
JSON report generation for SQL Injection Vulnerability
Scanner
===========================================================
"""

import json
import os
from datetime import datetime


class ScanReporter:
    """Generate and save structured SQLi scan reports."""

    def __init__(self, reports_directory="reports"):
        self.reports_directory = reports_directory

        os.makedirs(
            self.reports_directory,
            exist_ok=True
        )

    @staticmethod
    def create_timestamp():
        """Return the current timestamp."""

        return datetime.now().isoformat(
            timespec="seconds"
        )

    def build_report(
        self,
        target,
        parameters,
        requests_sent,
        findings,
        scan_duration,
        baseline
    ):
        """
        Build the complete scan report.
        """

        risk_summary = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0
        }

        for finding in findings:

            risk = finding.get(
                "analysis",
                {}
            ).get(
                "risk",
                {}
            )

            severity = risk.get(
                "severity",
                "none"
            ).lower()

            if severity in risk_summary:
                risk_summary[severity] += 1

        report = {
            "scanner": {
                "name": (
                    "SQL Injection Vulnerability Scanner"
                ),
                "version": "1.0.0"
            },
            "scan": {
                "timestamp": self.create_timestamp(),
                "duration_seconds": round(
                    scan_duration,
                    4
                )
            },
            "target": {
                "url": target,
                "parameters": [
                    {
                        "name": name,
                        "value": value
                    }
                    for name, value in parameters
                ]
            },
            "baseline": {
                "status_code": baseline.get(
                    "status_code"
                ),
                "response_size": len(
                    baseline.get(
                        "body",
                        b""
                    )
                ),
                "response_time": round(
                    baseline.get(
                        "response_time",
                        0.0
                    ),
                    4
                ),
                "final_url": baseline.get(
                    "url"
                )
            },
            "statistics": {
                "parameters_tested": len(
                    parameters
                ),
                "requests_sent": requests_sent,
                "findings_count": len(
                    findings
                ),
                "risk_summary": risk_summary
            },
            "findings": findings
        }

        return report

    def save_report(
        self,
        report,
        filename=None
    ):
        """Save report as JSON."""

        if filename is None:

            timestamp = datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )

            filename = (
                f"scan_{timestamp}.json"
            )

        filepath = os.path.join(
            self.reports_directory,
            filename
        )

        with open(
            filepath,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        return filepath
