# astrascan_project/astrascan/analysis/parameter_fuzzer.py

import httpx
import click
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import json # Will be useful for JSON body fuzzing later

# Define a set of common fuzzing payloads for various vulnerability types
FUZZING_PAYLOADS = [
    # Basic fuzzing / Special Characters
    "'", '"', '`', '<', '>', '&', '|', ';', '$', '*', '!', '%', '--', '#',
    '\\', '/', '(', ')', '[', ']', '{', '}',
    # SQL Injection payloads (basic)
    "SLEEP(5)", "WAITFOR DELAY '0:0:5'", "1 OR 1=1", "admin'--", "or 1=1--", "UNION SELECT NULL,NULL--",
    # XSS payloads (basic)
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
    # Path Traversal payloads (basic)
    "../../../../etc/passwd", "../../../../../windows/win.ini",
    # Command Injection payloads (basic)
    "&& ls", "| ls", "; ls",
    # Integer Overflow/Underflow (for numerical parameters)
    "0", "1", "-1", "9999999999", "-9999999999", "2147483647", "-2147483648", # Max/Min int values
    # Empty/Null/Boolean variations (for various types)
    "", "null", "true", "false",
    # Large string to test buffer overflows / performance
    "A" * 2000,
]

def fuzz_parameters(client: httpx.Client, base_url: str, discovered_endpoints: list):
    """
    Performs automated parameter fuzzing on discovered API endpoints.
    Initially focuses on query parameters.
    """
    click.echo("\n--- Starting Parameter Fuzzing ---")
    fuzzing_findings = []
    total_fuzzed_requests = 0

    for endpoint in discovered_endpoints:
        url = endpoint['url']
        method = endpoint['method']
        # For now, we only fuzz GET requests as query parameters are most common here.
        # We will expand to POST/PUT with body fuzzing later.
        if method != "GET":
            continue

        parsed_url = urlparse(url)
        current_query_params = parse_qs(parsed_url.query)

        # Skip if no query parameters are present to fuzz
        if not current_query_params:
            continue

        click.echo(f"  Fuzzing query parameters for: {url} [{method}]")

        # Iterate through each existing query parameter
        for param_name, param_values in current_query_params.items():
            original_param_value = param_values[0] # Take the first value if multiple

            for payload in FUZZING_PAYLOADS:
                fuzzed_params = current_query_params.copy()
                fuzzed_params[param_name] = payload # Replace parameter value with payload

                # Reconstruct the fuzzed URL
                fuzzed_query = urlencode(fuzzed_params, doseq=True)
                fuzzed_url = urlunparse(parsed_url._replace(query=fuzzed_query))

                try:
                    click.echo(f"    Testing {param_name}={payload} at {fuzzed_url}...")
                    response = client.request(method, fuzzed_url)
                    total_fuzzed_requests += 1

                    # Analyze the response for signs of vulnerability
                    # This is a very basic analysis and needs to be expanded significantly
                    if response.status_code >= 500:
                        finding = {
                            "type": "Server Error during Parameter Fuzzing",
                            "url": fuzzed_url,
                            "method": method,
                            "parameter": param_name,
                            "payload": payload,
                            "status_code": response.status_code,
                            "response_body_snippet": response.text[:200] # Capture first 200 chars
                        }
                        fuzzing_findings.append(finding)
                        click.echo(f"      [!] Potential Issue: Server error {response.status_code} with payload '{payload}'")
                    elif payload in response.text and payload != original_param_value:
                        # Simple reflection check (potential XSS/Injection)
                        finding = {
                            "type": "Payload Reflection during Parameter Fuzzing",
                            "url": fuzzed_url,
                            "method": method,
                            "parameter": param_name,
                            "payload": payload,
                            "status_code": response.status_code,
                            "response_body_snippet": response.text[:200]
                        }
                        fuzzing_findings.append(finding)
                        click.echo(f"      [!] Potential Issue: Payload '{payload}' reflected in response.")
                    # Add more advanced checks here (e.g., specific error messages, time-based detection)

                except httpx.RequestError as exc:
                    click.echo(f"      [E] Request failed for {fuzzed_url}: {exc}")
                except Exception as exc:
                    click.echo(f"      [E] An unexpected error occurred: {exc}")

    click.echo(f"--- Parameter Fuzzing Complete. Total fuzzed requests: {total_fuzzed_requests} ---")
    return fuzzing_findings
