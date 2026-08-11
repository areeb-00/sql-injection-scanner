"""
===========================================================
url_parser.py
URL and query parameter parsing for SQL Injection
Vulnerability Scanner
===========================================================
"""

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


class URLParser:
    """Parse target URLs and manage query parameters."""

    @staticmethod
    def parse(url):
        """
        Parse a target URL.

        Returns:
            dict: Structured URL information.
        """

        parsed = urlparse(url)

        parameters = parse_qsl(
            parsed.query,
            keep_blank_values=True
        )

        return {
            "scheme": parsed.scheme,
            "hostname": parsed.hostname,
            "port": parsed.port,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "base_url": urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    "",
                    ""
                )
            ),
            "parameters": parameters
        }

    @staticmethod
    def get_parameters(url):
        """
        Return query parameters as a list of tuples.

        Example:
            ?id=10&category=books

        becomes:

            [("id", "10"), ("category", "books")]
        """

        parsed = urlparse(url)

        return parse_qsl(
            parsed.query,
            keep_blank_values=True
        )

    @staticmethod
    def build_url(url, parameters):
        """
        Rebuild a URL using supplied query parameters.

        Args:
            url (str): Original URL.
            parameters (list): List of (key, value) pairs.

        Returns:
            str: Reconstructed URL.
        """

        parsed = urlparse(url)

        query = urlencode(
            parameters,
            doseq=True
        )

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                query,
                parsed.fragment
            )
        )

    @staticmethod
    def replace_parameter(url, parameter_name, new_value):
        """
        Replace one query parameter while preserving
        the remaining parameters.
        """

        parameters = URLParser.get_parameters(url)

        updated_parameters = []

        for key, value in parameters:

            if key == parameter_name:
                updated_parameters.append(
                    (key, new_value)
                )

            else:
                updated_parameters.append(
                    (key, value)
                )

        return URLParser.build_url(
            url,
            updated_parameters
        )
