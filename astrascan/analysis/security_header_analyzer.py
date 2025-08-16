# astrascan_project/astrascan/analysis/security_header_analyzer.py
import re

def analyze_security_headers(response, security_header_findings):
    """
    Analyzes an HTTP response for common security header misconfigurations.

    Args:
        response (httpx.Response): The HTTPX response object.
        security_header_findings (list): A list to append any found header issues.
    """
    url = str(response.url)
    method = response.request.method
    status_code = response.status_code
    headers = {k.lower(): v for k, v in response.headers.items()} # Convert to lowercase for case-insensitive check

    # List of security headers to check
    # Each tuple: (header_name, recommended_value_regex, recommendation_text, risk_level)
    # If recommended_value_regex is None, it checks for presence.
    # If it's a regex, it checks if the header's value matches the regex.
    SECURITY_HEADERS_CHECKS = [
        ("strict-transport-security", r"^max-age=[0-9]+;?\s*includeSubDomains;?\s*preload$",
         "Missing or misconfigured HSTS header. HSTS forces HTTPS, preventing downgrade attacks. Recommended: max-age=31536000; includeSubDomains; preload",
         "High"),
        ("x-frame-options", r"^(DENY|SAMEORIGIN)$",
         "Missing or misconfigured X-Frame-Options header. This prevents clickjacking attacks. Recommended: DENY or SAMEORIGIN",
         "Medium"),
        ("x-content-type-options", r"^nosniff$",
         "Missing or misconfigured X-Content-Type-Options header. This prevents MIME-sniffing attacks. Recommended: nosniff",
         "Medium"),
        ("content-security-policy", r".+", # Checks for presence, full validation is complex
         "Missing Content-Security-Policy header. CSP helps prevent XSS and data injection attacks by controlling resources the browser can load. Highly recommended.",
         "Low"), # CSP is complex, so presence is a low-risk finding, misconfig is higher
        ("permissions-policy", r".+", # Checks for presence, formerly Feature-Policy
         "Missing Permissions-Policy header. This allows you to selectively enable/disable browser features (e.g., camera, microphone). Recommended for modern apps.",
         "Low"),
        ("referrer-policy", r"^(no-referrer|no-referrer-when-downgrade|same-origin|strict-origin|strict-origin-when-cross-origin)$",
         "Missing or misconfigured Referrer-Policy header. Controls how much referrer information is sent with requests. Recommended: no-referrer-when-downgrade or strict-origin-when-cross-origin.",
         "Low"),
    ]

    for header_name, recommended_pattern, recommendation_text, risk_level in SECURITY_HEADERS_CHECKS:
        if header_name not in headers:
            security_header_findings.append({
                "url": url,
                "method": method,
                "status_code": status_code,
                "header_name": header_name,
                "reason": f"Missing security header: {header_name}. {recommendation_text}",
                "risk": risk_level,
                "current_value": "N/A"
            })
        else:
            current_value = headers[header_name]
            if recommended_pattern:
                if not re.match(recommended_pattern, current_value, re.IGNORECASE):
                    # Special case for CSP: if present, it's info. If empty, that's bad.
                    if header_name == "content-security-policy" and current_value.strip() == "":
                         security_header_findings.append({
                            "url": url,
                            "method": method,
                            "status_code": status_code,
                            "header_name": header_name,
                            "reason": f"Misconfigured security header: {header_name} is present but empty. {recommendation_text}",
                            "risk": "Medium",
                            "current_value": current_value
                        })
                    else:
                        security_header_findings.append({
                            "url": url,
                            "method": method,
                            "status_code": status_code,
                            "header_name": header_name,
                            "reason": f"Misconfigured security header: {header_name} value '{current_value}' does not match recommendation. {recommendation_text}",
                            "risk": risk_level,
                            "current_value": current_value
                        })
            # If recommended_pattern is None, only presence is checked, which is already done by 'if header_name not in headers'
