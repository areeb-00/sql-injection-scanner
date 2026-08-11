  INTERN ID : CITS7986
# SQL Injection Vulnerability Scanner

A modular Python-based SQL Injection Vulnerability Scanner designed for
authorized security testing and educational purposes.

The scanner analyzes HTTP GET parameters and looks for multiple indicators
of potential SQL injection vulnerabilities using response-based detection,
boolean comparison, timing analysis, risk scoring, and structured JSON
reporting.

> **Important:** This project is intended only for systems that you own or
> have explicit permission to test.

---

## Features

- HTTP and HTTPS target validation
- URL query parameter discovery
- Baseline HTTP response fingerprinting
- Error-based SQL injection detection
- Boolean-based paired response analysis
- Response similarity comparison
- Timing-based anomaly detection
- Configurable request timeout
- Configurable timing threshold
- Risk scoring and severity classification
- Evidence-based findings
- Structured JSON scan reports
- Scan logging
- CLI version information
- Automated unit tests
- Modular project architecture
- No third-party Python dependencies

---

## Detection Techniques

### 1. Error-Based Detection

The scanner checks responses for common SQL database error signatures.

Examples include indicators associated with:

- MySQL
- PostgreSQL
- SQLite
- Oracle
- Microsoft SQL Server
- ODBC
- JDBC

A detected database error is treated as an indicator rather than automatic
proof of exploitability.

---

### 2. Boolean-Based Detection

The scanner sends paired TRUE and FALSE conditions and compares their
responses.

The comparison considers:

- HTTP status code
- Response body length
- Response content similarity
- Observable behavioral differences

A significant difference between paired responses may indicate that the
parameter is being interpreted by backend application logic.

---

### 3. Timing Analysis

The scanner records baseline response time and compares it with subsequent
test requests.

Timing analysis is treated as an indicator only.

Network latency, server load, DNS resolution, connection establishment, and
other environmental conditions can influence response time.

---

## Risk Scoring

The scanner combines multiple pieces of evidence into a risk score.

Example evidence sources include:

- SQL error signatures
- Boolean behavioral differences
- HTTP status changes
- Response content changes
- Significant timing anomalies

Severity levels include:

```text
NONE
LOW
MEDIUM
HIGH
 
_ARCHITECTURE_

                    Target URL
                        |
                        v
                 URL Validation
                        |
                        v
                Parameter Discovery
                        |
                        v
                 Baseline Request
                        |
                        v
              Response Fingerprint
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
     Error-Based   Boolean-Based   Timing
      Detection      Detection    Analysis
          |             |             |
          +-------------+-------------+
                        |
                        v
                  Risk Engine
                        |
                        v
              Evidence + Severity
                        |
                        v
                 JSON Reporter


#PROJECT STRUCTURE 
sql-injection-scanner/
│
├── config/
│   └── config.json
│
├── logs/
│   └── scanner.log
│
├── modules/
│   ├── __init__.py
│   ├── detector.py
│   ├── logger.py
│   ├── payloads.py
│   ├── reporter.py
│   ├── request_handler.py
│   ├── response_analyzer.py
│   ├── risk_engine.py
│   ├── url_parser.py
│   └── validator.py
│
├── reports/
│
├── tests/
│   ├── test_detector.py
│   ├── test_report.py
│   ├── test_risk_engine.py
│   ├── test_url_parser.py
│   └── test_validator.py
│
├── .gitignore
├── main.py
├── README.md
├── LICENSE
└── requirements.txt


# usage  #


# python main.py -u "http://example.com/?id=10"

#python main.py -u "http://example.com/?id=10&category=books"

#python main.py \
    -u "http://example.com/?id=10&category=books" \
    -o my_scan.json

#python main.py --version

#Expected output:

SQL Injection Vulnerability Scanner v1.0.0

#Run the complete test suite:

python -m unittest discover -s tests -v
