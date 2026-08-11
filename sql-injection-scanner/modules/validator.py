"""
===========================================================
validator.py
Input and URL validation for SQL Injection Vulnerability
Scanner
===========================================================
"""

from urllib.parse import urlparse


class Validator:
    """Validate scanner input and target URLs."""

    @staticmethod
    def validate_url(url):
        """
        Validate whether the supplied target is a usable
        HTTP/HTTPS URL.
        """

        if not url:

            return False, "URL cannot be empty."

        if not isinstance(url, str):

            return False, "URL must be a string."

        # Check the original input BEFORE stripping whitespace.
        # This prevents control characters from being silently
        # normalized away.
        if any(
            character in url
            for character in (
                "\n",
                "\r",
                "\t"
            )
        ):

            return False, (
                "URL contains invalid whitespace."
            )

        url = url.strip()

        if not url:

            return False, "URL cannot be empty."

        if " " in url:

            return False, (
                "URL must not contain spaces."
            )

        if url.startswith("[") or "](" in url:

            return False, (
                "URL appears to contain Markdown "
                "formatting."
            )

        try:

            parsed = urlparse(url)

        except ValueError:

            return False, "Invalid URL format."

        if parsed.scheme not in (
            "http",
            "https"
        ):

            return False, (
                "URL must use HTTP or HTTPS."
            )

        if not parsed.netloc:

            return False, (
                "URL must contain a valid hostname."
            )

        if parsed.hostname is None:

            return False, (
                "Unable to determine hostname."
            )

        return True, parsed

    @staticmethod
    def validate_timeout(timeout):
        """Validate HTTP timeout value."""

        if not isinstance(
            timeout,
            (int, float)
        ):

            return False, (
                "Timeout must be a number."
            )

        if timeout <= 0:

            return False, (
                "Timeout must be greater than zero."
            )

        return True, timeout
