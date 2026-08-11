"""
===========================================================
payloads.py
SQL injection detection payload definitions
===========================================================
"""


class PayloadManager:
    """Provide controlled SQL injection test payloads."""

    ERROR_BASED = [
        "'",
        '"',
        "';",
        '";'
    ]

    BOOLEAN_PAIRS = [
        {
            "true": "' AND '1'='1",
            "false": "' AND '1'='2"
        },
        {
            "true": '" AND "1"="1"',
            "false": '" AND "1"="2"'
        }
    ]

    TIME_BASED = [
        "'",
        '"'
    ]

    @classmethod
    def get_error_payloads(cls):
        """Return error-based detection payloads."""

        return cls.ERROR_BASED.copy()

    @classmethod
    def get_boolean_pairs(cls):
        """Return paired boolean payloads."""

        return cls.BOOLEAN_PAIRS.copy()

    @classmethod
    def get_time_payloads(cls):
        """Return time-based test markers."""

        return cls.TIME_BASED.copy()

    @classmethod
    def get_all_payloads(cls):
        """Return all supported detection payloads."""

        return {
            "error_based": cls.get_error_payloads(),
            "boolean_pairs": cls.get_boolean_pairs(),
            "time_based": cls.get_time_payloads()
        }
