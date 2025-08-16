# astrascan_project/astrascan/analysis/error_info_disclosure_analyzer.py

import re
import json

def analyze_for_info_disclosure(response_info: dict, info_disclosure_findings: list):
    """
    Analyzes an HTTP response for various types of information disclosure.

    Args:
        response_info (dict): A dictionary containing 'url', 'method', 'status_code', 'response_text_preview'.
        info_disclosure_findings (list): A list to append any found info disclosure issues.
    """
    url = response_info['url']
    method = response_info['method']
    status_code = response_info['status_code']
    response_text = response_info['response_text_preview']

    # Shorten response text for analysis to avoid excessively large regex matching,
    # but keep enough to capture typical stack traces or error messages.
    # We'll use the full text if a match is found to extract context.
    analysis_text = response_text # For now, analyze full text up to preview limit.

    # Patterns for different types of information disclosure
    # Each tuple: (pattern_regex, issue_type, risk_level, reason_text)
    INFO_DISCLOSURE_PATTERNS = [
        # Stack Traces (generic, Python, Java, PHP, Node.js, .NET)
        (r"at (org\.apache\.|java\.lang\.|com\.|net\.|sun\.|jdk\.)", "Java Stack Trace", "High", "Java stack trace detected, revealing internal application structure."),
        (r"Traceback \(most recent call last\):", "Python Stack Trace", "High", "Python stack trace detected, revealing internal application structure and code paths."),
        (r"on line \d+ in .*(\.php|\.inc|\.html|\.css|\.js)", "PHP/Web Server Path Disclosure", "Medium", "Full file path or line number in PHP/web server error, revealing server structure."),
        (r"(\s+at\s+)(.+\.js:\d+:\d+)", "Node.js Stack Trace", "High", "Node.js stack trace detected, revealing internal application structure and code paths."),
        (r"System\.(\w+\.)*\w+Exception:", ".NET Stack Trace", "High", ".NET stack trace detected, revealing internal application structure and code paths."),
        (r"(Access denied for user|ORA-\d{5}:|SQLSTATE|PgErrorCode|MySQL|MongoDB\.Driver|db_connect|Warning: PDO::|Uncaught Error: Call to undefined method|Call to a member function .* on null)", "Database/Framework Error", "High", "Database or framework specific error message, indicating potential injection points or internal logic."),

        # Internal IP Addresses (common ranges)
        (r"(10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3})", "Internal IP Address", "Medium", "Internal IP address (10.0.0.0/8) disclosed in response."),
        (r"(172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:[0-9]{1,3}\.){2}[0-9]{1,3})", "Internal IP Address", "Medium", "Internal IP address (172.16.0.0/12) disclosed in response."),
        (r"(192\.168\.(?:[0-9]{1,3}\.){2}[0-9]{1,3})", "Internal IP Address", "Medium", "Internal IP address (192.168.0.0/16) disclosed in response."),
        (r"(127\.0\.0\.1|localhost)", "Localhost Disclosure", "Low", "Localhost address disclosed, might indicate internal service exposure."),

        # Full Paths / Directory Listings
        (r"(\/[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.]+\/([a-zA-Z0-9_\-\.]+\/?)*\.(php|js|css|html|xml|json|conf|ini|log))", "File Path Disclosure", "Medium", "Full file path exposed, revealing server structure."),
        (r"(\b(?:C:|D:)?\\(?:[a-zA-Z0-9_\-\.\x20]+\\)*[a-zA-Z0-9_\-\.\x20]+\.(php|js|css|html|xml|json|conf|ini|log|dll|exe))", "Windows Path Disclosure", "Medium", "Windows file path exposed, revealing server structure."),
        (r"Index of /", "Directory Listing", "High", "Directory listing enabled, exposing file and directory structure."),

        # Sensitive Environment Variables (examples)
        (r"(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS)", "Environment Variable Disclosure", "High", "Sensitive cloud provider environment variable found."),
        (r"(STRIPE_SECRET_KEY|PAYPAL_API_SECRET)", "Payment Gateway Key Disclosure", "High", "Payment gateway API secret key found."),
        (r"(DB_USERNAME|DB_PASSWORD|SQL_USER|SQL_PASS)", "Database Credential Key Disclosure", "High", "Potential database credentials found."),

        # Version Numbers (generic, focus on commonly vulnerable software)
        (r"(Apache Tomcat\/(\d+\.\d+))", "Software Version Disclosure", "Low", "Apache Tomcat version detected."),
        (r"(nginx\/(\d+\.\d+))", "Software Version Disclosure", "Low", "Nginx version detected."),
        (r"(Microsoft-IIS\/(\d+\.\d+))", "Software Version Disclosure", "Low", "Microsoft IIS version detected."),
        (r"(Express\/(\d+\.\d+))", "Software Version Disclosure", "Low", "Express.js framework version detected."),
        (r"(PHP\/(\d+\.\d+))", "Software Version Disclosure", "Low", "PHP version detected."),
        (r"(Node\.js v(\d+\.\d+))", "Software Version Disclosure", "Low", "Node.js version detected."),
    ]

    for pattern, issue_type, risk_level, reason_text in INFO_DISCLOSURE_PATTERNS:
        for match in re.finditer(pattern, analysis_text, re.IGNORECASE):
            matched_value = match.group(0)
            # Ensure findings are unique for this response to avoid duplicates from same pattern
            finding_id = f"{url}-{method}-{status_code}-{issue_type}-{matched_value}"
            if finding_id not in [f"{f['url']}-{f['method']}-{f['status_code']}-{f['type']}-{f['matched_value_preview']}" for f in info_disclosure_findings]:
                # Extract a context snippet around the match
                start_index = max(0, match.start() - 100)
                end_index = min(len(response_text), match.end() + 100)
                context_preview = response_text[start_index:end_index]

                info_disclosure_findings.append({
                    "url": url,
                    "method": method,
                    "status_code": status_code,
                    "type": issue_type,
                    "reason": reason_text,
                    "risk": risk_level,
                    "matched_value_preview": matched_value,
                    "context_preview": context_preview
                })
