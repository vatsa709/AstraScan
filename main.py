# astrascan_project/main.py

import click
import httpx
from collections import deque
import os
from urllib.parse import urljoin, urlparse

# Import functions/constants from your new modules
from astrascan.config import HTTP_METHODS
from astrascan.utils.wordlist_loader import load_wordlist
from astrascan.utils.path_extractor import extract_paths_from_response
from astrascan.utils.http_clients import setup_http_clients
from astrascan.analysis.misconfig_analyzer import analyze_response_for_misconfigs
from astrascan.analysis.graphql_analyzer import perform_graphql_introspection, generate_simple_graphql_queries
from astrascan.analysis.auth_analyzer import check_unauthenticated_access
from astrascan.api_specs.openapi_parser import parse_openapi_spec
from astrascan.api_specs.openapi_generator import generate_openapi_spec
from astrascan.reporting.html_reporter import generate_report
from astrascan.analysis.parameter_fuzzer import fuzz_parameters
from astrascan.analysis.data_exposure_analyzer import analyze_for_sensitive_data
from astrascan.analysis.security_header_analyzer import analyze_security_headers
from astrascan.analysis.cors_analyzer import analyze_cors
from astrascan.analysis.error_info_disclosure_analyzer import analyze_for_info_disclosure


@click.command()
@click.option('-u', '--url', required=True, help='Base URL to scan (e.g., https://api.example.com)')
@click.option('-w', '--wordlist', default=None, help='Path to a custom wordlist file. If not provided, a built-in common list will be used.')
@click.option('--graphql', is_flag=True, help='Enable GraphQL specific checks (introspection, common endpoints).')
@click.option('--token', default=None, help='Bearer token or other auth header value (e.g., "Authorization: Bearer abc123" or "X-API-Key: xyz").')
@click.option('--ci-mode', is_flag=True, help='Run in CI/CD mode: exits with code 1 if high-risk issues found.')
@click.option('-o', '--output', default='reports/astrascan_report.html', help='Output file name for the report (JSON or HTML). Default: reports/astrascan_report.html')
@click.option('--timeout', default=15, type=int, help='Request timeout in seconds.')
@click.option('--no-verify-ssl', is_flag=True, help='Disable SSL certificate verification (use with extreme caution, only for debugging/testing).')
@click.option('--max-depth', default=2, type=int, help='Maximum depth for recursive crawling. Default is 2.')
@click.option('--documented-spec', default=None, type=click.Path(exists=True), help='Path to an OpenAPI/Swagger specification file (JSON/YAML) for zombie API detection.')
@click.option('--all', 'all_enabled', is_flag=True, help='Enable all available advanced scanning features (e.g., GraphQL, detailed analysis). This overrides individual feature flags if set.')
@click.option('--min-risk', default='info', type=click.Choice(['high', 'medium', 'low', 'info'], case_sensitive=False),
              help='Set the minimum risk level for findings to be included in the report. Default is "info".')
def astrascan_cli(url, wordlist, graphql, token, ci_mode, output, timeout, no_verify_ssl, max_depth, documented_spec, all_enabled, min_risk):
    """
    AstraScan: Intelligent API Discovery & Misconfiguration Scanner.
    """
    # --- START CORRECTED LOGO AND NAME ---
    ASTRASCAN_LOGO = r"""
    _         _           ____                  
   / \   ___| |_ _ __ __ _/ ___|  ___ __ _ _ __  
  / _ \ / __| __| '__/ _` \___ \ / __/ _` | '_ \ 
 / ___ \\__ \ |_| | | (_| |___) | (_| (_| | | | |
/_/   \_\___/\__|_|  \__,_|____/ \___\__,_|_| |_|

""" # Added 'r' before the triple quotes and fixed logo content
    click.echo(click.style(ASTRASCAN_LOGO, fg='cyan'))
    click.echo(click.style("                                    Made by - SRIVATSA", fg='green'))
    click.echo("\n") # Add a newline for spacing
    # --- END CORRECTED LOGO ---

    # Logic to enable all features if --all is used
    if all_enabled:
        graphql = True

    click.echo(f"--- Starting AstraScan for: {url} ---")
    click.echo(f"GraphQL scan enabled: {graphql}")
    click.echo(f"Auth Token provided: {'Yes' if token else 'No'}")
    click.echo(f"Request timeout: {timeout} seconds")
    click.echo(f"SSL verification: {'Disabled' if no_verify_ssl else 'Enabled'}")
    click.echo(f"Maximum recursion depth: {max_depth}")
    click.echo(f"Documented spec provided: {'Yes' if documented_spec else 'No'}")
    click.echo(f"All features enabled via --all: {'Yes' if all_enabled else 'No'}")
    click.echo(f"Minimum risk for report: {min_risk.capitalize()}")

    # ... rest of the main.py code remains unchanged ...

    # Setup HTTP clients (authenticated and unauthenticated)
    auth_client, unauth_client, token_provided = setup_http_clients(timeout, no_verify_ssl, token)

    initial_paths = load_wordlist(wordlist)

    scan_queue = deque([(path, 0) for path in initial_paths])
    visited_probes = set()
    discovered_paths_set = set(initial_paths)

    discovered_endpoints = []
    misconfigurations = []
    zombie_apis = []
    unauthenticated_access_findings = []
    parameter_fuzzing_findings = []
    sensitive_data_findings = []
    security_header_findings = []
    cors_findings = []
    info_disclosure_findings = []

    live_probed_endpoints = set()

    graphql_findings = {
        "introspection_enabled": False,
        "endpoint_url": None,
        "schema": None,
        "sample_queries_results": []
    }

    documented_endpoints_from_spec = set()
    if documented_spec:
        click.echo(f"Parsing documented OpenAPI spec from {documented_spec}...")
        documented_endpoints_from_spec = parse_openapi_spec(documented_spec, url)
        click.echo(f"Found {len(documented_endpoints_from_spec)} documented paths in spec.")


    click.echo(f"Loaded {len(initial_paths)} initial endpoints for fuzzing.")
    click.echo("\n--- Probing Endpoints ---")

    try:
        while scan_queue:
            current_path, current_depth = scan_queue.popleft()

            normalized_current_path = current_path.strip('/')

            if current_depth > max_depth:
                continue

            is_graphql_candidate = graphql and normalized_current_path.lower() in ["graphql", "api/graphql"]

            for method in HTTP_METHODS:
                full_url = urljoin(url, normalized_current_path)
                probe_id = (full_url, method)

                if probe_id in visited_probes:
                    continue

                visited_probes.add(probe_id)

                if is_graphql_candidate:
                    if method not in ["POST", "GET"]:
                        continue

                try:
                    response = auth_client.request(method, full_url)

                    response_info = {
                        "url": full_url,
                        "method": method,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "redirected_to": str(response.url) if response.url != full_url else None,
                        "response_text_preview": response.text
                    }
                    discovered_endpoints.append(response_info)

                    live_probed_endpoints.add((normalized_current_path, method.upper(), response.status_code))

                    analyze_response_for_misconfigs(response, full_url, misconfigurations, token_provided=token_provided)

                    # --- Unauthenticated Access Check ---
                    if token_provided:
                        check_unauthenticated_access(response, unauth_client, full_url, method, unauthenticated_access_findings)

                    # --- Sensitive Data Exposure Check ---
                    analyze_for_sensitive_data(response_info, sensitive_data_findings)
                    
                    # --- Security Header Analysis ---
                    analyze_security_headers(response, security_header_findings)

                    # --- CORS Analysis ---
                    if method in ["GET", "POST"]:
                        analyze_cors(auth_client, full_url, method, cors_findings)

                    # --- Error Handling & Information Disclosure Analysis ---
                    analyze_for_info_disclosure(response_info, info_disclosure_findings)


                    # --- GraphQL Introspection & Query Generation ---
                    if is_graphql_candidate and not graphql_findings["introspection_enabled"]:
                        if method in ["POST"]:
                            graphql_schema = perform_graphql_introspection(auth_client, full_url)
                            if graphql_schema:
                                graphql_findings["introspection_enabled"] = True
                                graphql_findings["endpoint_url"] = full_url
                                graphql_findings["schema"] = graphql_schema
                                click.echo(f"  Attempting to generate and test sample GraphQL queries...")
                                sample_queries = generate_simple_graphql_queries(graphql_schema)
                                for query in sample_queries:
                                    try:
                                        query_response = auth_client.post(full_url, json={"query": query}, headers={"Content-Type": "application/json"})
                                        if query_response.status_code == 200 and 'data' in query_response.json():
                                            graphql_findings["sample_queries_results"].append({
                                                "query": query,
                                                "status_code": query_response.status_code,
                                                "response_data_preview": query_response.json()['data'],
                                                "success": True
                                            })
                                        else:
                                             graphql_findings["sample_queries_results"].append({
                                                "query": query,
                                                "status_code": query_response.status_code,
                                                "response_errors_preview": query_response.json().get('errors', 'No errors found'),
                                                "success": False
                                            })
                                    except Exception as q_exc:
                                        graphql_findings["sample_queries_results"].append({
                                            "query": query,
                                            "status_code": "Error",
                                            "response_errors_preview": str(q_exc),
                                            "success": False
                                        })
                            else:
                                click.echo("  GraphQL introspection failed for schema generation.")

                    # --- Recursive Crawling ---
                    if current_depth < max_depth:
                        if 200 <= response.status_code < 300 and response.text:
                            newly_found_paths = extract_paths_from_response(url, response.text, discovered_paths_set)
                            for new_path in newly_found_paths:
                                if new_path not in discovered_paths_set:
                                    discovered_paths_set.add(new_path)
                                    scan_queue.append((new_path, current_depth + 1))

                except httpx.RequestError as exc:
                    error_status = 503
                    if isinstance(exc, httpx.ConnectError):
                        error_status = 503
                    elif isinstance(exc, httpx.TimeoutException):
                        error_status = 408

                    live_probed_endpoints.add((normalized_current_path, method.upper(), error_status))
                    pass
                except Exception as e:
                    click.echo(f"  An unexpected error occurred during probe of {full_url}: {e}")
                    live_probed_endpoints.add((normalized_current_path, method.upper(), 500))

    finally:
        auth_client.close()
        unauth_client.close()

    # --- Zombie API Detection Logic (After all probing is done) ---
    if documented_spec and documented_endpoints_from_spec:
        click.echo("\n--- Detecting Zombie APIs ---")
        for doc_path, doc_method in documented_endpoints_from_spec:
            found_live_and_ok = False
            for live_path, live_method, live_status in live_probed_endpoints:
                if doc_path == live_path and doc_method == live_method:
                    found_live_and_ok = True
                    if (live_status >= 400 and live_status != 401 and live_status != 403):
                        zombie_apis.append({
                            "path": f"/{doc_path}",
                            "method": doc_method,
                            "reason": f"Documented endpoint found but responded with a problematic status code ({live_status}). It might be deprecated, broken, or misconfigured.",
                            "status_code": live_status
                        })
                    break

            if not found_live_and_ok:
                zombie_apis.append({
                    "path": f"/{doc_path}",
                    "method": doc_method,
                    "reason": "Documented endpoint not found/reachable during scan (likely 404, 405, or network error). This might be a Zombie API.",
                    "status_code": "Not Found/Error"
                })
        click.echo(f"Found {len(zombie_apis)} potential Zombie APIs.")

    # Call Parameter Fuzzing after initial endpoint discovery is complete
    # Ensure discovered_endpoints has unique entries before proceeding to fuzzing
    if discovered_endpoints:
        click.echo("\n--- Starting Parameter Fuzzing ---")
        parameter_fuzzing_findings = fuzz_parameters(auth_client, url, discovered_endpoints)
        click.echo(f"Found {len(parameter_fuzzing_findings)} potential issues from parameter fuzzing.")
    else:
        click.echo("No endpoints discovered to perform parameter fuzzing on.")


    click.echo(f"\n--- Scan Summary ---")
    click.echo(f"Total endpoints probed: {len(discovered_endpoints)}")
    click.echo(f"Found {len(misconfigurations)} potential misconfigurations.")
    click.echo(f"Found {len(zombie_apis)} potential Zombie APIs.")
    click.echo(f"Found {len(unauthenticated_access_findings)} potential Unauthenticated Access Issues.")
    if graphql_findings["introspection_enabled"]:
        click.echo(f"GraphQL Introspection: Enabled. Sample queries tested: {len(graphql_findings['sample_queries_results'])}.")
    click.echo(f"Found {len(parameter_fuzzing_findings)} potential parameter fuzzing issues.")
    click.echo(f"Found {len(sensitive_data_findings)} potential sensitive data exposure issues.")
    click.echo(f"Found {len(security_header_findings)} potential security header issues.")
    click.echo(f"Found {len(cors_findings)} potential CORS misconfiguration issues.")
    click.echo(f"Found {len(info_disclosure_findings)} potential information disclosure issues.")

    openapi_spec = generate_openapi_spec(discovered_endpoints)

    generate_report(output, url, discovered_endpoints, misconfigurations, openapi_spec, ci_mode, zombie_apis, graphql_findings, unauthenticated_access_findings, parameter_fuzzing_findings, sensitive_data_findings, security_header_findings, cors_findings, info_disclosure_findings, min_risk)


if __name__ == '__main__':
    astrascan_cli()