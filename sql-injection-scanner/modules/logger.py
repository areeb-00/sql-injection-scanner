"""
===========================================================
logger.py
Logging system for SQL Injection Vulnerability Scanner
===========================================================
"""

import logging
import os


class ScanLogger:
    """Centralized logging manager."""

    @staticmethod
    def setup(log_file="logs/scanner.log", level="INFO"):
        """
        Configure application logging.

        Args:
            log_file (str): Path to log file.
            level (str): Logging level.
        """

        log_directory = os.path.dirname(log_file)

        if log_directory:
            os.makedirs(log_directory, exist_ok=True)

        numeric_level = getattr(
            logging,
            level.upper(),
            logging.INFO
        )

        logging.basicConfig(
            level=numeric_level,
            format="%(asctime)s | %(levelname)s | %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

        return logging.getLogger("SQLiScanner")

    @staticmethod
    def get_logger():
        """Return the scanner logger."""

        return logging.getLogger("SQLiScanner")
