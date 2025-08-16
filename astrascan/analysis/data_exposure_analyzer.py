# astrascan_project/astrascan/analysis/data_exposure_analyzer.py

import re
import json

# Define common regex patterns for sensitive data
# These are examples and can be expanded based on specific needs.
# WARNING: Regex can have false positives. Manual review is always required.
SENSITIVE_DATA_PATTERNS = {
    "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "API Key/Token (Generic)": r"(api_key|token|auth_token|bearer_token|access_token|secret)[:=\s\"']?([a-zA-Z0-9\-_]{20,})",
    "Internal IP Address (RFC1918)": r"(?:10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"([^A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}([^A-Za-z0-9/+=])", # More generic, can be false positive
    "Credit Card Number (Generic)": r"(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})",
    "Social Security Number (US)": r"\b\d{3}-\d{2}-\d{4}\b",
    "Private Key (SSH/PGP)": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    "SQL Connection String": r"(?:Server|Data Source|Host|User ID|Uid|Password|Pwd|Initial Catalog|Database)=(?:[^;\"']+(?:;|$))",
    "JWT (Generic, just looks like a JWT)": r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
}

def analyze_for_sensitive_data(response_info, sensitive_data_findings):
    """
    Analyzes an HTTP response for known sensitive data patterns in its body.
    
    Args:
        response_info (dict): Dictionary containing details of the HTTP response,
                              including 'url', 'method', 'status_code', 'response_text_preview'.
        sensitive_data_findings (list): A list to append any found sensitive data issues.
    """
    response_text = response_info.get("response_text_preview", "")
    full_url = response_info.get("url")
    method = response_info.get("method")
    status_code = response_info.get("status_code")

    if not response_text:
        return

    for data_type, pattern in SENSITIVE_DATA_PATTERNS.items():
        # For API Key/Token, handle the capturing group to avoid false positives on just "token"
        if data_type == "API Key/Token (Generic)":
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                # Ensure a value is actually captured, not just the keyword
                if match.group(2): # group(2) is the actual token value from the regex
                    sensitive_data_findings.append({
                        "url": full_url,
                        "method": method,
                        "status_code": status_code,
                        "type": data_type,
                        "reason": f"Potentially exposed {data_type} detected.",
                        "matched_value_preview": match.group(2)[:50] + "..." if len(match.group(2)) > 50 else match.group(2),
                        "context_preview": response_text[max(0, match.start() - 100):min(len(response_text), match.end() + 100)]
                    })
        else:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                sensitive_data_findings.append({
                    "url": full_url,
                    "method": method,
                    "status_code": status_code,
                    "type": data_type,
                    "reason": f"Potentially exposed {data_type} detected.",
                    "matched_value_preview": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0),
                    "context_preview": response_text[max(0, match.start() - 100):min(len(response_text), match.end() + 100)]
                })
