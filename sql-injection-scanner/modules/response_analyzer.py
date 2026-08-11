"""
===========================================================
response_analyzer.py
HTTP response analysis for SQL Injection Vulnerability
Scanner
===========================================================
"""


class ResponseAnalyzer:
    """Analyze and fingerprint HTTP responses."""

    @staticmethod
    def create_fingerprint(response):
        """
        Create a basic fingerprint of an HTTP response.

        The fingerprint will later be used to compare
        normal and modified responses.
        """

        body = response.get("body", b"")

        if isinstance(body, bytes):
            body_length = len(body)

            try:
                body_text = body.decode(
                    "utf-8",
                    errors="ignore"
                )

            except Exception:
                body_text = ""

        else:
            body_text = str(body)
            body_length = len(body_text)

        return {
            "status_code": response.get("status_code"),
            "body_length": body_length,
            "content_type": (
                response
                .get("headers", {})
                .get("Content-Type", "")
            ),
            "final_url": response.get("url"),
            "success": response.get("success", False),
            "body_preview": body_text[:200]
        }

    @staticmethod
    def compare(baseline, current):
        """
        Compare two response fingerprints.

        Returns:
            dict: Response differences.
        """

        differences = {}

        if baseline.get("status_code") != current.get(
            "status_code"
        ):
            differences["status_code"] = {
                "baseline": baseline.get("status_code"),
                "current": current.get("status_code")
            }

        if baseline.get("body_length") != current.get(
            "body_length"
        ):
            differences["body_length"] = {
                "baseline": baseline.get("body_length"),
                "current": current.get("body_length")
            }

        if baseline.get("content_type") != current.get(
            "content_type"
        ):
            differences["content_type"] = {
                "baseline": baseline.get("content_type"),
                "current": current.get("content_type")
            }

        return {
            "identical": len(differences) == 0,
            "differences": differences
        }
