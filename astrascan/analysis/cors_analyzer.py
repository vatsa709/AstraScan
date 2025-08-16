# astrascan_project/astrascan/analysis/cors_analyzer.py

import httpx
from urllib.parse import urlparse

def analyze_cors(client: httpx.Client, url: str, method: str, cors_findings: list):
    """
    Analyzes an API endpoint for common CORS (Cross-Origin Resource Sharing) misconfigurations.

    Args:
        client (httpx.Client): The HTTPX client to use for requests.
        url (str): The URL of the API endpoint to check.
        method (str): The HTTP method (e.g., "GET", "POST").
        cors_findings (list): A list to append any found CORS issues.
    """
    test_origin = "http://malicious.com" # A typical malicious origin
    expected_allowed_method = "GET" # A method we expect to be allowed for preflight

    # 1. Check for Wildcard Origin or Reflective Origin
    try:
        # We perform a GET request with a custom Origin header.
        # This is often enough to trigger CORS headers if simple reflection/wildcard is in place.
        response = client.request(
            method,
            url,
            headers={"Origin": test_origin, "Access-Control-Request-Method": expected_allowed_method},
            follow_redirects=True # Follow redirects to ensure we get final headers
        )

        acao = response.headers.get("access-control-allow-origin", None)
        acac = response.headers.get("access-control-allow-credentials", None)

        if acao == "*":
            cors_findings.append({
                "url": url,
                "method": method,
                "status_code": response.status_code,
                "type": "Wildcard Origin (Access-Control-Allow-Origin: *)",
                "reason": f"API allows '*' as Access-Control-Allow-Origin, potentially exposing data to any domain. If Access-Control-Allow-Credentials is also true, this is critical.",
                "risk": "High" if acac else "Medium",
                "acao_value": acao,
                "acac_value": acac,
                "tested_origin": test_origin
            })
        elif acao and acao.lower() == test_origin.lower():
            # Check for reflection where origin is simply reflected back
            # This is a vulnerability if the reflected origin is not properly validated against a whitelist
            parsed_url = urlparse(url)
            # Only report if the test_origin is NOT the same as the target's base origin
            if urlparse(acao).netloc.lower() != parsed_url.netloc.lower():
                cors_findings.append({
                    "url": url,
                    "method": method,
                    "status_code": response.status_code,
                    "type": "Reflective Origin (Origin header reflected)",
                    "reason": f"API reflects the Origin header '{test_origin}' back in Access-Control-Allow-Origin. This can be abused if the reflection allows arbitrary origins.",
                    "risk": "High" if acac else "Medium",
                    "acao_value": acao,
                    "acac_value": acac,
                    "tested_origin": test_origin
                })

        # 2. Check for Access-Control-Allow-Credentials with non-safe ACAO
        if acac and acac.lower() == "true":
            if acao == "*" or (acao and urlparse(acao).netloc.lower() != urlparse(url).netloc.lower() and acao.lower() == test_origin.lower()):
                # This means credentials can be sent from any origin (wildcard) or a reflected malicious origin
                cors_findings.append({
                    "url": url,
                    "method": method,
                    "status_code": response.status_code,
                    "type": "Access-Control-Allow-Credentials with Weak Origin",
                    "reason": f"Access-Control-Allow-Credentials is 'true' while Access-Control-Allow-Origin is '{acao}'. This can allow attackers to perform authenticated requests from any domain if the origin is not strictly whitelisted.",
                    "risk": "High",
                    "acao_value": acao,
                    "acac_value": acac,
                    "tested_origin": test_origin
                })
    except httpx.RequestError as e:
        # Handle network errors, timeouts etc. gracefully without crashing the scan
        # print(f"  CORS Analysis Error for {url} ({method}): {e}")
        pass
    except Exception as e:
        # print(f"  Unexpected CORS Analysis Error for {url} ({method}): {e}")
        pass
