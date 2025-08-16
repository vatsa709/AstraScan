# astrascan_project/astrascan/analysis/misconfig_analyzer.py

import re
from urllib.parse import urlparse

def analyze_response_for_misconfigs(response, url, misconfigurations_list, token_provided):
    """Analyzes an HTTP response for common API misconfigurations.
    
    Args:
        response (httpx.Response): The HTTP response object.
        url (str): The URL that was probed.
        misconfigurations_list (list): A list to append detected misconfigurations to.
        token_provided (bool): True if an auth token was used for the request.
    """
    risk_level = "Low"
    reason = []

    # Check for Open CORS
    if "Access-Control-Allow-Origin" in response.headers and response.headers["Access-Control-Allow-Origin"] == "*":
        reason.append("Open CORS detected (Access-Control-Allow-Origin: *).")
        risk_level = "High" 

    # Check for HTTP (missing HTTPS)
    if urlparse(url).scheme == "http":
        if "Location" in response.headers and response.status_code >= 300 and response.status_code < 400:
            if urlparse(response.headers["Location"]).scheme == "https":
                if risk_level == "Low":
                    risk_level = "Low" 
            else:
                reason.append("Endpoint redirects to another HTTP URL.")
                if risk_level != "High":
                    risk_level = "Medium"
        elif 200 <= response.status_code < 400:
            reason.append("Endpoint serves content over plain HTTP (not redirecting to HTTPS).")
            risk_level = "High"

    # Error leakage (stack traces, internal IPs, DB info)
    error_patterns = [
        re.compile(r'stack trace|exception in|internal server error|db error|sql error|server error|at \w+\.\w+\(', re.IGNORECASE),
        re.compile(r'\b(?:10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b')
    ]
    for pattern in error_patterns:
        if pattern.search(response.text):
            reason.append(f"Error leakage detected (e.g., stack trace, internal IP, DB error).")
            risk_level = "High"
            break

    # Debug/test flags or verbose server info in content/headers
    if re.search(r'debug_mode_enabled|test_endpoint|dev_version|/debug|/test|x-debug-token|server: .*tomcat|x-powered-by: asp.net', response.text + str(response.headers), re.IGNORECASE):
        reason.append("Risky debug/test pattern or verbose server info in content/headers.")
        if risk_level == "Low":
            risk_level = "Medium"

    # Rate-limit headers (check for absence of Retry-After on 429)
    if response.status_code == 429 and "Retry-After" not in response.headers:
        reason.append("Rate limit hit (429), but 'Retry-After' header is missing.")
        if risk_level == "Low":
            risk_level = "Medium"

    # Exposed GraphQL introspection (simplified check - now also performed by dedicated function)
    if 'graphql' in url.lower() and ('data":{"__schema":' in response.text or '{"data":{"__schema":' in response.text):
        reason.append("GraphQL introspection appears to be enabled.")
        if risk_level == "Low":
            risk_level = "Medium"

    # Flags unauthenticated or overly verbose endpoints (based on content detection)
    # This check is sensitive to false positives and needs refinement for real use cases.
    # It checks if NO token was provided AND the endpoint returns a 2xx OK status
    # AND the content suggests sensitive data (e.g., 'user_id', 'email', 'password')
    sensitive_data_patterns = [
        re.compile(r'"email"\s*:\s*"[^"]+"', re.IGNORECASE),
        re.compile(r'"username"\s*:\s*"[^"]+"', re.IGNORECASE),
        re.compile(r'"password"\s*:\s*"[^"]+"', re.IGNORECASE),
        re.compile(r'"user_id"\s*:\s*\d+', re.IGNORECASE),
        re.compile(r'"api_key"\s*:\s*"[^"]+"', re.IGNORECASE),
        re.compile(r'\b(SSN|credit card|social security number|dob)\b', re.IGNORECASE)
    ]

    # This specific check is now handled by auth_analyzer.py for clarity.
    # We keep the misconfig checks that are independent of authentication status.
    # The 'token_provided' parameter can still be used for other misconfigs if needed.

    if reason:
        misconfigurations_list.append({
            "path": urlparse(url).path,
            "risk": risk_level,
            "reason": "; ".join(reason),
            "status_code": response.status_code,
            "response_preview": response.text[:500]
        })
