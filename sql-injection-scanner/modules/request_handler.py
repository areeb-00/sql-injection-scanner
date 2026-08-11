"""
===========================================================
request_handler.py
HTTP request handling for SQL Injection Vulnerability
Scanner
===========================================================
"""

import time
import urllib.error
import urllib.request


class RequestHandler:
    """Handle HTTP/HTTPS requests."""

    def __init__(
        self,
        timeout=10,
        user_agent="SQLi-Scanner/1.0"
    ):
        self.timeout = timeout
        self.user_agent = user_agent

    def get(self, url):
        """
        Send an HTTP GET request and measure response time.

        Args:
            url (str): Target URL.

        Returns:
            dict: Structured response information.
        """

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent
            },
            method="GET"
        )

        start_time = time.perf_counter()

        try:

            with urllib.request.urlopen(
                request,
                timeout=self.timeout
            ) as response:

                body = response.read()

                elapsed_time = (
                    time.perf_counter()
                    - start_time
                )

                return {
                    "success": True,
                    "status_code": response.status,
                    "headers": dict(
                        response.headers
                    ),
                    "body": body,
                    "url": response.geturl(),
                    "response_time": elapsed_time,
                    "error": None
                }

        except urllib.error.HTTPError as error:

            body = error.read()

            elapsed_time = (
                time.perf_counter()
                - start_time
            )

            return {
                "success": False,
                "status_code": error.code,
                "headers": dict(
                    error.headers
                ),
                "body": body,
                "url": url,
                "response_time": elapsed_time,
                "error": str(error)
            }

        except urllib.error.URLError as error:

            elapsed_time = (
                time.perf_counter()
                - start_time
            )

            return {
                "success": False,
                "status_code": None,
                "headers": {},
                "body": b"",
                "url": url,
                "response_time": elapsed_time,
                "error": str(error.reason)
            }

        except TimeoutError:

            elapsed_time = (
                time.perf_counter()
                - start_time
            )

            return {
                "success": False,
                "status_code": None,
                "headers": {},
                "body": b"",
                "url": url,
                "response_time": elapsed_time,
                "error": "Request timed out."
            }

        except Exception as error:

            elapsed_time = (
                time.perf_counter()
                - start_time
            )

            return {
                "success": False,
                "status_code": None,
                "headers": {},
                "body": b"",
                "url": url,
                "response_time": elapsed_time,
                "error": str(error)
            }
