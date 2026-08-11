"""
===========================================================
main.py
SQL Injection Vulnerability Scanner
===========================================================
"""

import argparse
import json
import os
import sys
import time

from modules.detector import SQLiDetector
from modules.logger import ScanLogger
from modules.payloads import PayloadManager
from modules.reporter import ScanReporter
from modules.request_handler import RequestHandler
from modules.response_analyzer import ResponseAnalyzer
from modules.url_parser import URLParser
from modules.validator import Validator


CONFIG_FILE = "config/config.json"
VERSION = "1.0.0"


def load_config():
    """Load scanner configuration."""

    if not os.path.exists(CONFIG_FILE):

        print(
            f"[!] Configuration file not found: "
            f"{CONFIG_FILE}"
        )

        sys.exit(1)

    try:

        with open(
            CONFIG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError:

        print(
            "[!] Configuration file contains "
            "invalid JSON."
        )

        sys.exit(1)

    except OSError as error:

        print(
            f"[!] Unable to read configuration: "
            f"{error}"
        )

        sys.exit(1)


def create_argument_parser():
    """Create command-line argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "SQL Injection Vulnerability Scanner - "
            "authorized security testing tool"
        )
    )

    parser.add_argument(
        "-u",
        "--url",
        required=False,
        help="Target URL to scan."
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Custom JSON report filename."
    )

    parser.add_argument(
        "--version",
        action="version",
        version=(
            "SQL Injection Vulnerability Scanner "
            f"v{VERSION}"
        )
    )

    return parser


def main():
    """Application entry point."""

    scan_start = time.perf_counter()

    parser = create_argument_parser()
    args = parser.parse_args()

    if not args.url:

        parser.error(
            "the following arguments are required: "
            "-u/--url"
        )

    config = load_config()

    scanner_config = config.get(
        "scanner",
        {}
    )

    logging_config = config.get(
        "logging",
        {}
    )

    logger = ScanLogger.setup(
        log_file=logging_config.get(
            "file",
            "logs/scanner.log"
        ),
        level=logging_config.get(
            "level",
            "INFO"
        )
    )

    print("=" * 60)

    print(
        "        SQL INJECTION VULNERABILITY SCANNER"
    )

    print("=" * 60)

    logger.info(
        "Scanner started."
    )

    logger.info(
        "Target received: %s",
        args.url
    )

    # =======================================================
    # URL validation
    # =======================================================

    is_valid, result = (
        Validator.validate_url(
            args.url
        )
    )

    if not is_valid:

        logger.error(
            "Invalid target URL: %s",
            result
        )

        print(
            f"\n[!] Invalid target: {result}"
        )

        sys.exit(1)

    parsed_url = result

    print(
        f"\n[+] Target: {args.url}"
    )

    print(
        f"[+] Scheme: {parsed_url.scheme}"
    )

    print(
        f"[+] Host:   {parsed_url.hostname}"
    )

    logger.info(
        "Target URL validated successfully."
    )

    # =======================================================
    # URL parsing
    # =======================================================

    url_information = URLParser.parse(
        args.url
    )

    parameters = url_information[
        "parameters"
    ]

    print(
        "\n[*] URL analysis"
    )

    print(
        f"[+] Base URL: "
        f"{url_information['base_url']}"
    )

    if parameters:

        print(
            f"[+] Parameters discovered: "
            f"{len(parameters)}"
        )

        for name, value in parameters:

            print(
                f"    └── {name} = {value}"
            )

        logger.info(
            "Discovered %d query parameter(s).",
            len(parameters)
        )

    else:

        print(
            "[!] No query parameters found."
        )

        logger.info(
            "No query parameters found."
        )

    # =======================================================
    # HTTP configuration
    # =======================================================

    timeout = scanner_config.get(
        "timeout",
        10
    )

    user_agent = scanner_config.get(
        "user_agent",
        "SQLi-Scanner/1.0"
    )

    timing_threshold = scanner_config.get(
        "timing_threshold",
        2.0
    )

    is_valid_timeout, timeout_result = (
        Validator.validate_timeout(
            timeout
        )
    )

    if not is_valid_timeout:

        logger.error(
            "Invalid configured timeout: %s",
            timeout_result
        )

        print(
            f"\n[!] Configuration error: "
            f"{timeout_result}"
        )

        sys.exit(1)

    request_handler = RequestHandler(
        timeout=timeout,
        user_agent=user_agent
    )

    # =======================================================
    # Baseline request
    # =======================================================

    print(
        "\n[*] Sending baseline request..."
    )

    baseline_response = (
        request_handler.get(
            args.url
        )
    )

    if not baseline_response["success"]:

        print(
            "[!] Baseline request failed."
        )

        print(
            f"[!] Error: "
            f"{baseline_response['error']}"
        )

        logger.error(
            "Baseline request failed: %s",
            baseline_response["error"]
        )

        sys.exit(1)

    print(
        "[+] Request successful."
    )

    print(
        f"[+] Status Code: "
        f"{baseline_response['status_code']}"
    )

    print(
        f"[+] Response Size: "
        f"{len(baseline_response['body'])} bytes"
    )

    print(
        f"[+] Response Time: "
        f"{baseline_response['response_time']:.4f} seconds"
    )

    print(
        f"[+] Final URL: "
        f"{baseline_response['url']}"
    )

    logger.info(
        "Baseline request successful: HTTP %s",
        baseline_response["status_code"]
    )

    logger.info(
        "Baseline response time: %.4f seconds",
        baseline_response["response_time"]
    )

    # =======================================================
    # Baseline fingerprint
    # =======================================================

    fingerprint = (
        ResponseAnalyzer.create_fingerprint(
            baseline_response
        )
    )

    print(
        "\n[*] Baseline fingerprint"
    )

    print(
        f"[+] Status Code: "
        f"{fingerprint['status_code']}"
    )

    print(
        f"[+] Body Length: "
        f"{fingerprint['body_length']} bytes"
    )

    print(
        f"[+] Content Type: "
        f"{fingerprint['content_type']}"
    )

    logger.info(
        "Baseline response fingerprint created."
    )

    # =======================================================
    # Parameter check
    # =======================================================

    if not parameters:

        print(
            "\n[!] No parameters available "
            "for SQL injection testing."
        )

        logger.info(
            "Detection skipped because no parameters "
            "were discovered."
        )

        return

    # =======================================================
    # Detection initialization
    # =======================================================

    print(
        "\n[*] Starting SQL injection detection..."
    )

    payload_sets = (
        PayloadManager.get_all_payloads()
    )

    total_tests = 0
    findings = []

    # =======================================================
    # Parameter testing
    # =======================================================

    for parameter_name, original_value in parameters:

        print(
            f"\n{'=' * 60}"
        )

        print(
            f"PARAMETER: {parameter_name}"
        )

        print(
            f"ORIGINAL VALUE: {original_value}"
        )

        print(
            f"{'=' * 60}"
        )

        # ===================================================
        # Error-based tests
        # ===================================================

        print(
            "\n[ERROR-BASED TESTS]"
        )

        for payload in payload_sets[
            "error_based"
        ]:

            total_tests += 1

            test_url = URLParser.replace_parameter(
                args.url,
                parameter_name,
                payload
            )

            print(
                f"\n[>] Payload: {payload}"
            )

            test_response = (
                request_handler.get(
                    test_url
                )
            )

            if not test_response["success"]:

                print(
                    f"[!] Request failed: "
                    f"{test_response['error']}"
                )

                continue

            analysis = SQLiDetector.analyze(
                baseline_response,
                test_response
            )

            if analysis[
                "sql_error"
            ]["detected"]:

                risk = analysis[
                    "risk"
                ]

                print(
                    "[!] SQL error indicator detected"
                )

                print(
                    f"[!] Risk: "
                    f"{risk['severity']}"
                )

                print(
                    f"[!] Score: "
                    f"{risk['score']}/100"
                )

                findings.append(
                    {
                        "parameter": parameter_name,
                        "technique": "error_based",
                        "payload": payload,
                        "analysis": analysis
                    }
                )

            else:

                print(
                    "[+] No SQL error indicator"
                )

        # ===================================================
        # Boolean paired tests
        # ===================================================

        print(
            "\n[BOOLEAN-BASED PAIRED TESTS]"
        )

        for pair in payload_sets[
            "boolean_pairs"
        ]:

            true_payload = pair[
                "true"
            ]

            false_payload = pair[
                "false"
            ]

            total_tests += 2

            print(
                "\n[>] TRUE condition:"
            )

            print(
                f"    {true_payload}"
            )

            true_url = URLParser.replace_parameter(
                args.url,
                parameter_name,
                true_payload
            )

            true_response = (
                request_handler.get(
                    true_url
                )
            )

            if not true_response["success"]:

                print(
                    f"[!] TRUE request failed: "
                    f"{true_response['error']}"
                )

                continue

            print(
                f"[+] TRUE response: "
                f"{true_response['response_time']:.4f}s"
            )

            print(
                "\n[>] FALSE condition:"
            )

            print(
                f"    {false_payload}"
            )

            false_url = URLParser.replace_parameter(
                args.url,
                parameter_name,
                false_payload
            )

            false_response = (
                request_handler.get(
                    false_url
                )
            )

            if not false_response["success"]:

                print(
                    f"[!] FALSE request failed: "
                    f"{false_response['error']}"
                )

                continue

            print(
                f"[+] FALSE response: "
                f"{false_response['response_time']:.4f}s"
            )

            boolean_analysis = (
                SQLiDetector.analyze_boolean_pair(
                    true_response,
                    false_response
                )
            )

            print(
                "\n    Boolean Analysis:"
            )

            print(
                f"    TRUE status : "
                f"{boolean_analysis['true_status']}"
            )

            print(
                f"    FALSE status: "
                f"{boolean_analysis['false_status']}"
            )

            print(
                f"    Similarity  : "
                f"{boolean_analysis['similarity']}"
            )

            if boolean_analysis[
                "boolean_behavior"
            ]:

                print(
                    "    [!] Boolean behavioral "
                    "difference detected"
                )

                analysis = SQLiDetector.analyze(
                    baseline_response,
                    true_response,
                    boolean_behavior=True
                )

                findings.append(
                    {
                        "parameter": parameter_name,
                        "technique": (
                            "boolean_based_paired"
                        ),
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "analysis": {
                            "boolean": boolean_analysis,
                            "risk": analysis["risk"],
                            "recommendation": (
                                analysis[
                                    "recommendation"
                                ]
                            )
                        }
                    }
                )

            else:

                print(
                    "    [+] No significant "
                    "TRUE/FALSE difference"
                )

        # ===================================================
        # Timing analysis
        # ===================================================

        print(
            "\n[TIMING ANALYSIS]"
        )

        for payload in payload_sets[
            "time_based"
        ]:

            total_tests += 1

            test_url = URLParser.replace_parameter(
                args.url,
                parameter_name,
                payload
            )

            print(
                f"\n[>] Timing test: {payload}"
            )

            test_response = (
                request_handler.get(
                    test_url
                )
            )

            if not test_response["success"]:

                print(
                    f"[!] Request failed: "
                    f"{test_response['error']}"
                )

                continue

            timing = SQLiDetector.analyze_timing(
                baseline_response,
                test_response,
                threshold=timing_threshold
            )

            print(
                f"    Baseline: "
                f"{timing['baseline_time']:.4f}s"
            )

            print(
                f"    Test:     "
                f"{timing['test_time']:.4f}s"
            )

            print(
                f"    Difference: "
                f"{timing['difference']:.4f}s"
            )

            if timing["delayed"]:

                print(
                    "    [!] Significant timing "
                    "difference detected"
                )

                analysis = SQLiDetector.analyze(
                    baseline_response,
                    test_response,
                    timing_behavior=True
                )

                findings.append(
                    {
                        "parameter": parameter_name,
                        "technique": "timing_indicator",
                        "payload": payload,
                        "timing": timing,
                        "analysis": analysis
                    }
                )

            else:

                print(
                    "    [+] No significant "
                    "timing difference"
                )

    # =======================================================
    # Scan duration
    # =======================================================

    scan_duration = (
        time.perf_counter()
        - scan_start
    )

    # =======================================================
    # Console summary
    # =======================================================

    print(
        "\n" + "=" * 60
    )

    print(
        "DETECTION SUMMARY"
    )

    print(
        "=" * 60
    )

    print(
        f"Parameters Tested : "
        f"{len(parameters)}"
    )

    print(
        f"Requests Sent     : "
        f"{total_tests}"
    )

    print(
        f"Indicators Found  : "
        f"{len(findings)}"
    )

    print(
        f"Scan Duration     : "
        f"{scan_duration:.4f} seconds"
    )

    # =======================================================
    # Findings
    # =======================================================

    if findings:

        print(
            "\n[!] Potential SQL injection "
            "indicators found."
        )

        for index, finding in enumerate(
            findings,
            start=1
        ):

            print(
                f"\n--- Finding {index} ---"
            )

            print(
                f"Parameter : "
                f"{finding['parameter']}"
            )

            print(
                f"Technique : "
                f"{finding['technique']}"
            )

            if "payload" in finding:

                print(
                    f"Payload   : "
                    f"{finding['payload']}"
                )

            if "true_payload" in finding:

                print(
                    f"TRUE      : "
                    f"{finding['true_payload']}"
                )

                print(
                    f"FALSE     : "
                    f"{finding['false_payload']}"
                )

            risk = finding[
                "analysis"
            ]["risk"]

            print(
                f"Risk      : "
                f"{risk['severity']}"
            )

            print(
                f"Score     : "
                f"{risk['score']}/100"
            )

            if risk["evidence"]:

                print(
                    "Evidence:"
                )

                for evidence in risk[
                    "evidence"
                ]:

                    print(
                        f"  - {evidence}"
                    )

            print(
                "Recommendation:"
            )

            print(
                f"  "
                f"{finding['analysis']['recommendation']}"
            )

    else:

        print(
            "\n[+] No SQL injection indicators detected."
        )

    # =======================================================
    # Generate JSON report
    # =======================================================

    print(
        "\n[*] Generating scan report..."
    )

    reporter = ScanReporter(
        reports_directory="reports"
    )

    report = reporter.build_report(
        target=args.url,
        parameters=parameters,
        requests_sent=total_tests,
        findings=findings,
        scan_duration=scan_duration,
        baseline=baseline_response
    )

    try:

        report_path = reporter.save_report(
            report,
            filename=args.output
        )

        print(
            f"[+] Report saved: "
            f"{report_path}"
        )

        logger.info(
            "Scan report saved: %s",
            report_path
        )

    except OSError as error:

        print(
            f"[!] Unable to save report: "
            f"{error}"
        )

        logger.error(
            "Report generation failed: %s",
            error
        )

    # =======================================================
    # Completion
    # =======================================================

    print(
        "\n[*] SQL injection scan complete."
    )

    logger.info(
        "Scan completed. Tests: %d, Findings: %d",
        total_tests,
        len(findings)
    )


if __name__ == "__main__":
    main()
