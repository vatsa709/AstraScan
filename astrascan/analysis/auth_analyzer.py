# astrascan_project/astrascan/analysis/auth_analyzer.py

import httpx
import click
import re
from urllib.parse import urlparse

def check_unauthenticated_access(auth_response, unauth_client, full_url, method, unauthenticated_access_findings):
    """
    Checks if an endpoint that responded positively with authentication is also accessible without it.
    
    Args:
        auth_response (httpx.Response): The response from the authenticated probe.
        unauth_client (httpx.Client): An httpx client configured without authentication.
        full_url (str): The full URL of the endpoint.
        method (str): The HTTP method used.
        unauthenticated_access_findings (list): List to append findings to.
    """
    # Only relevant for endpoints that are NOT expected to be public/404/405
    # and if the authenticated response was not already an auth error (401/403)
    if auth_response.status_code not in [404, 405, 500, 501, 401, 403]:
        try:
            unauth_response = unauth_client.request(method, full_url)
            
            # If we get 200 OK without auth, or a redirect to sensitive area
            # And the content is not trivial (e.g., empty 200 or generic homepage)
            # Use a more robust check for "non-trivial" content, e.g., JSON, or significant length
            is_json = 'application/json' in unauth_response.headers.get('Content-Type', '')
            is_non_trivial_content = len(unauth_response.content) > 50 or is_json # Arbitrary threshold

            if (unauth_response.status_code == 200 and is_non_trivial_content) or \
               (unauth_response.status_code >= 300 and unauth_response.status_code < 400 and urlparse(unauth_response.headers.get('Location', '')).path != '/login'):
                
                unauthenticated_access_findings.append({
                    "path": urlparse(full_url).path,
                    "method": method,
                    "expected_status": "401/403 (or similar denial)",
                    "actual_status": unauth_response.status_code,
                    "reason": f"Endpoint accessible without authentication, returned {unauth_response.status_code} with content.",
                    "response_preview": unauth_response.text[:500]
                })
                click.echo(f"  [UA] {method} {full_url} - UNATHENTICATED ACCESS (Status: {unauth_response.status_code})")

        except httpx.RequestError as unauth_exc:
            pass # Suppress network errors for unauth checks
        except Exception as unauth_e:
            pass # Suppress other errors for unauth checks
