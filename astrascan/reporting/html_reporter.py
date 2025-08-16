# astrascan_project/astrascan/reporting/html_reporter.py

import os
import json
from datetime import datetime
import click
from jinja2 import Environment, FileSystemLoader

# Define risk level hierarchy for filtering
RISK_LEVELS = {
    'high': 3,
    'medium': 2,
    'low': 1,
    'info': 0
}

# MODIFIED: Added 'info_disclosure_findings' to function arguments
def generate_report(output_file, base_url, discovered_endpoints, misconfigurations, openapi_spec, ci_mode, zombie_apis, graphql_findings, unauthenticated_access_findings, parameter_fuzzing_findings, sensitive_data_findings, security_header_findings, cors_findings, info_disclosure_findings, min_risk='info'):
    """
    Generates and saves the scan report in JSON, HTML, or Markdown format.
    
    Args:
        output_file (str): Path to the output report file.
        base_url (str): The base URL that was scanned.
        discovered_endpoints (list): List of discovered API endpoints.
        misconfigurations (list): List of API misconfiguration findings.
        openapi_spec (dict): Inferred OpenAPI specification.
        ci_mode (bool): Flag for CI/CD mode.
        zombie_apis (list): List of potential zombie API findings.
        graphql_findings (dict): Findings related to GraphQL introspection.
        unauthenticated_access_findings (list): Unauthenticated access findings.
        parameter_fuzzing_findings (list): Parameter fuzzing findings.
        sensitive_data_findings (list): Sensitive data exposure findings.
        security_header_findings (list): Security header findings.
        cors_findings (list): CORS misconfiguration findings.
        info_disclosure_findings (list): Information disclosure findings.
        min_risk (str): The minimum risk level to include in the report ('high', 'medium', 'low', 'info').
    """

    # NEW: Filter findings based on min_risk level
    min_risk_level = RISK_LEVELS.get(min_risk.lower(), 0)

    def filter_findings(findings_list, risk_key='risk', default_risk_level='info'):
        return [
            f for f in findings_list
            if RISK_LEVELS.get(f.get(risk_key, default_risk_level).lower(), 0) >= min_risk_level
        ]

    # Assign risk levels to specific finding types for filtering
    # These are assumptions based on the criticality of these issues
    filtered_misconfigurations = filter_findings(misconfigurations)
    filtered_unauthenticated_access = filter_findings(unauthenticated_access_findings, default_risk_level='high')
    filtered_parameter_fuzzing = filter_findings(parameter_fuzzing_findings, default_risk_level='high')
    filtered_sensitive_data = filter_findings(sensitive_data_findings, default_risk_level='high')
    filtered_security_headers = filter_findings(security_header_findings)
    filtered_cors = filter_findings(cors_findings)
    filtered_info_disclosure = filter_findings(info_disclosure_findings)
    filtered_zombie_apis = filter_findings(zombie_apis, default_risk_level='info')
    
    # GraphQL findings are a special case, they're not a list of findings with risk levels
    # We'll just show them if min_risk is 'info' or 'low'
    show_graphql_findings = min_risk_level <= RISK_LEVELS.get('low', 1)
    
    report_data = {
        "scan_summary": {
            "total_endpoints_probed": len(discovered_endpoints),
            "total_misconfigurations_found": len(filtered_misconfigurations),
            "high_risk_issues": sum(1 for mc in filtered_misconfigurations if mc['risk'] == 'High'),
            "total_zombie_apis_found": len(filtered_zombie_apis),
            "graphql_introspection_enabled": graphql_findings["introspection_enabled"] if show_graphql_findings else False,
            "total_unauthenticated_access_issues": len(filtered_unauthenticated_access),
            "total_parameter_fuzzing_issues": len(filtered_parameter_fuzzing),
            "total_sensitive_data_issues": len(filtered_sensitive_data),
            "total_security_header_issues": len(filtered_security_headers),
            "total_cors_issues": len(filtered_cors),
            "total_info_disclosure_issues": len(filtered_info_disclosure)
        },
        "base_url": base_url,
        "discovered_endpoints": discovered_endpoints, # This list is not filtered, as it's an inventory
        "misconfigurations": filtered_misconfigurations,
        "inferred_openapi_spec": openapi_spec,
        "zombie_apis": filtered_zombie_apis,
        "graphql_findings": graphql_findings,
        "unauthenticated_access_findings": filtered_unauthenticated_access,
        "parameter_fuzzing_findings": filtered_parameter_fuzzing,
        "sensitive_data_findings": filtered_sensitive_data,
        "security_header_findings": filtered_security_headers,
        "cors_findings": filtered_cors,
        "info_disclosure_findings": filtered_info_disclosure
    }

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    if output_file.endswith('.json'):
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        click.echo(f"Report saved to {output_file}")
    elif output_file.endswith('.html'):
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AstraScan Report</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; line-height: 1.6; color: #333; }
                h1, h2, h3 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; margin-top: 30px; }
                .section { margin-bottom: 30px; background-color: #f9f9f9; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .risk-high { color: #e74c3c; font-weight: bold; } /* Red */
                .risk-medium { color: #f39c12; font-weight: bold; } /* Orange */
                .risk-low { color: #2ecc71; font-weight: bold; } /* Green */
                .risk-info { color: #3498db; font-weight: bold; } /* Blue for info like zombie APIs */
                ul { list-style-type: none; padding: 0; }
                li { margin-bottom: 10px; padding: 8px; background-color: #fff; border: 1px solid #ddd; border-radius: 4px; }
                code { background-color: #eef; padding: 2px 4px; border-radius: 3px; font-family: 'Consolas', 'Monaco', monospace; }
                pre { background-color: #eee; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; font-family: 'Consolas', 'Monaco', monospace; margin-top: 10px; }
                .summary-box { display: flex; justify-content: space-around; margin-bottom: 20px; text-align: center; flex-wrap: wrap; }
                .summary-item { flex: 1; padding: 15px; margin: 10px; border: 1px solid #ccc; border-radius: 5px; background-color: #fff; min-width: 200px; }
                .summary-item h3 { margin-top: 0; color: #34495e; }
                .summary-item p { font-size: 1.2em; font-weight: bold; }
                .graphql-schema-viewer { max-height: 400px; overflow-y: scroll; border: 1px solid #ccc; background-color: #f0f0f0; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; color: #555; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                tr:hover { background-color: #f1f1f1; }
                /* NEW: Added smooth scrolling and summary link styling */
                html { scroll-behavior: smooth; }
                .summary-nav {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    gap: 10px;
                    padding: 10px;
                    background-color: #f0f0f0;
                    border-radius: 8px;
                }
                .summary-nav a {
                    text-decoration: none;
                    color: #2c3e50;
                    padding: 15px;
                    background-color: #fff;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    transition: background-color 0.2s ease;
                    font-weight: bold;
                }
                .summary-nav a:hover {
                    background-color: #e9e9e9;
                }
            </style>
        </head>
        <body>
            <h1>AstraScan Report <small>(Generated: {{ now_formatted }})</small></h1>
            <p><strong>Base URL Scanned:</strong> {{ base_url }}</p>
            <p><strong>Minimum Risk Level Shown:</strong> <span style="text-transform: capitalize;">{{ min_risk }}</span></p>

            <div class="summary-box section">
                <div class="summary-item">
                    <h3>Endpoints Probed</h3>
                    <p>{{ scan_summary.total_endpoints_probed }}</p>
                </div>
                <div class="summary-item">
                    <h3>Misconfigurations Found</h3>
                    <p>{{ scan_summary.total_misconfigurations_found }}</p>
                </div>
                <div class="summary-item">
                    <h3>High-Risk Issues</h3>
                    <p class="risk-high">{{ scan_summary.high_risk_issues }}</p>
                </div>
                <div class="summary-item">
                    <h3>Zombie APIs Found</h3>
                    <p class="risk-info">{{ scan_summary.total_zombie_apis_found }}</p>
                </div>
                <div class="summary-item">
                    <h3>GraphQL Introspection</h3>
                    <p class="{{ 'risk-info' if scan_summary.graphql_introspection_enabled else '' }}">{{ 'Enabled' if scan_summary.graphql_introspection_enabled else 'Not Enabled/Found' }}</p>
                </div>
                <div class="summary-item">
                    <h3>Unauth Access Issues</h3>
                    <p class="{{ 'risk-high' if scan_summary.total_unauthenticated_access_issues > 0 else '' }}">{{ scan_summary.total_unauthenticated_access_issues }}</p>
                </div>
                <div class="summary-item">
                    <h3>Param Fuzzing Issues</h3>
                    <p class="{{ 'risk-high' if scan_summary.total_parameter_fuzzing_issues > 0 else '' }}">{{ scan_summary.total_parameter_fuzzing_issues }}</p>
                </div>
                <div class="summary-item">
                    <h3>Sensitive Data Issues</h3>
                    <p class="{{ 'risk-high' if scan_summary.total_sensitive_data_issues > 0 else '' }}">{{ scan_summary.total_sensitive_data_issues }}</p>
                </div>
                <div class="summary-item">
                    <h3>Security Header Issues</h3>
                    <p class="{{ 'risk-medium' if scan_summary.total_security_header_issues > 0 else '' }}">{{ scan_summary.total_security_header_issues }}</p>
                </div>
                <div class="summary-item">
                    <h3>CORS Issues</h3>
                    <p class="{{ 'risk-medium' if scan_summary.total_cors_issues > 0 else '' }}">{{ scan_summary.total_cors_issues }}</p>
                </div>
                <div class="summary-item"> {# NEW: Summary item for Info Disclosure Issues #}
                    <h3>Info Disclosure Issues</h3>
                    <p class="{{ 'risk-high' if scan_summary.total_info_disclosure_issues > 0 else '' }}">{{ scan_summary.total_info_disclosure_issues }}</p>
                </div>
            </div>

            <div class="section">
                <h2>Go to Section</h2>
                <div class="summary-nav">
                    {% if misconfigurations|length > 0 or min_risk == 'info' %}
                        <a href="#misconfigurations-detected">Misconfigurations Detected ({{ misconfigurations|length }})</a>
                    {% endif %}
                    {% if unauthenticated_access_findings|length > 0 or min_risk == 'info' %}
                        <a href="#unauthenticated-access-issues">Unauthenticated Access Issues ({{ unauthenticated_access_findings|length }})</a>
                    {% endif %}
                    {% if zombie_apis|length > 0 or min_risk == 'info' %}
                        <a href="#zombie-apis">Potential Zombie APIs ({{ zombie_apis|length }})</a>
                    {% endif %}
                    {% if graphql_findings.introspection_enabled or min_risk == 'info' %}
                        <a href="#graphql-findings">GraphQL Findings</a>
                    {% endif %}
                    {% if parameter_fuzzing_findings|length > 0 or min_risk == 'info' %}
                        <a href="#parameter-fuzzing">Parameter Fuzzing Findings ({{ parameter_fuzzing_findings|length }})</a>
                    {% endif %}
                    {% if sensitive_data_findings|length > 0 or min_risk == 'info' %}
                        <a href="#sensitive-data">Sensitive Data Exposure ({{ sensitive_data_findings|length }})</a>
                    {% endif %}
                    {% if security_header_findings|length > 0 or min_risk == 'info' %}
                        <a href="#security-headers">Security Header Findings ({{ security_header_findings|length }})</a>
                    {% endif %}
                    {% if cors_findings|length > 0 or min_risk == 'info' %}
                        <a href="#cors-misconfigurations">CORS Misconfiguration ({{ cors_findings|length }})</a>
                    {% endif %}
                    {% if info_disclosure_findings|length > 0 or min_risk == 'info' %}
                        <a href="#info-disclosure">Information Disclosure ({{ info_disclosure_findings|length }})</a>
                    {% endif %}
                    <a href="#discovered-endpoints">Discovered Endpoints Inventory ({{ discovered_endpoints|length }})</a>
                    <a href="#openapi-spec">Inferred OpenAPI Specification</a>
                    <a href="#recommendations">Recommendations</a>
                </div>
            </div>

            <div class="section">
                <h2 id="misconfigurations-detected">Misconfigurations Detected ({{ misconfigurations|length }})</h2>
                {% if misconfigurations %}
                    <ul>
                    {% for mc in misconfigurations %}
                        <li>
                            <strong class="risk-{{ mc.risk|lower }}">{{ mc.risk }}</strong>: {{ mc.reason }}<br>
                            Path: <code>{{ mc.path }}</code> (Status: {{ mc.status_code }})
                            {% if mc.response_preview %}
                            <pre>Response Preview: {{ mc.response_preview }}...</pre>
                            {% endif %}
                        </li>
                    {% endfor %}
                    </ul>
                {% else %}
                    <p>No major misconfigurations detected for the scanned endpoints.</p>
                {% endif %}
            </div>
            
            <div class="section">
                <h2 id="unauthenticated-access-issues">Potential Unauthenticated Access Issues ({{ unauthenticated_access_findings|length }})</h2>
                {% if unauthenticated_access_findings %}
                    <ul>
                    {% for uaf in unauthenticated_access_findings %}
                        <li>
                            <strong class="risk-high">High</strong>: {{ uaf.reason }}<br>
                            Path: <code>{{ uaf.method }} {{ uaf.path }}</code><br>
                            Expected Status: <code>{{ uaf.expected_status }}</code>, Actual Status: <code>{{ uaf.actual_status }}</code>
                            {% if uaf.response_preview %}
                                <pre>Response Preview: {{ uaf.response_preview }}...</pre>
                            {% endif %}
                        </li>
                    {% endfor %}
                    </ul>
                {% else %}
                    <p>No potential unauthenticated access issues detected (or no token provided for comparison).</p>
                {% endif %}
            </div>

            <div class="section">
                <h2 id="zombie-apis">Potential Zombie APIs ({{ zombie_apis|length }})</h2>
                {% if zombie_apis %}
                    <ul>
                    {% for za in zombie_apis %}
                        <li>
                            <strong class="risk-info">Info</strong>: {{ za.reason }}<br>
                            Path: <code>{{ za.method }} {{ za.path }}</code> (Status: {{ za.status_code }})
                        </li>
                    {% endfor %}
                    </ul>
                {% else %}
                    <p>No potential Zombie APIs detected or no documented spec provided.</p>
                {% endif %}
            </div>

            <div class="section">
                <h2 id="graphql-findings">GraphQL Findings</h2>
                {% if graphql_findings.introspection_enabled and show_graphql_findings %}
                    <p>GraphQL Introspection is <strong>enabled</strong> for <code>{{ graphql_findings.endpoint_url }}</code>.</p>
                    <h3>Inferred Schema:</h3>
                    <div class="graphql-schema-viewer">
                        <pre>{{ graphql_findings.schema | tojson(indent=2) }}</pre>
                    </div>

                    <h3>Sample Query Results:</h3>
                    {% if graphql_findings.sample_queries_results %}
                        <ul>
                            {% for qr in graphql_findings.sample_queries_results %}
                                <li>
                                    <strong>Query:</strong> <code>{{ qr.query }}</code><br>
                                    <strong>Status:</strong> {{ qr.status_code }} {% if qr.success %}<span class="risk-low">(Success)</span>{% else %}<span class="risk-high">(Failed)</span>{% endif %}<br>
                                    {% if qr.success %}
                                        <strong>Response Data Preview:</strong> <pre>{{ qr.response_data_preview | tojson(indent=2) }}</pre>
                                    {% else %}
                                        <strong>Response Errors/Details:</strong> <pre>{{ qr.response_errors_preview | tojson(indent=2) }}</pre>
                                    {% endif %}
                                </li>
                            {% endfor %}
                        </ul>
                    {% else %}
                        <p>No sample queries were generated or tested.</p>
                    {% endif %}
                {% else %}
                    <p>GraphQL introspection was not detected or not enabled for the scan (use <code>--graphql</code> flag).</p>
                {% endif %}
            </div>

            <div class="section">
                <h2 id="parameter-fuzzing">Parameter Fuzzing Findings ({{ parameter_fuzzing_findings|length }})</h2>
                {% if parameter_fuzzing_findings %}
                <p>These findings indicate suspicious responses when injecting various payloads into URL query parameters. They might suggest potential vulnerabilities like SQL Injection, XSS, or unexpected server behavior.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>URL</th>
                            <th>Method</th>
                            <th>Parameter</th>
                            <th>Payload</th>
                            <th>Status Code</th>
                            <th>Response Snippet</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in parameter_fuzzing_findings %}
                        <tr>
                            <td>{{ finding.type }}</td>
                            <td><a href="{{ finding.url }}" target="_blank">{{ finding.url }}</a></td>
                            <td><code>{{ finding.method }}</code></td>
                            <td><code>{{ finding.parameter }}</code></td>
                            <td><code>{{ finding.payload }}</code></td>
                            <td>{{ finding.status_code }}</td>
                            <td><pre>{{ finding.response_body_snippet }}</pre></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No parameter fuzzing findings detected.</p>
                {% endif %}
            </div>

            <div class="section">
                <h2 id="sensitive-data">Sensitive Data Exposure Findings ({{ sensitive_data_findings|length }})</h2>
                {% if sensitive_data_findings %}
                <p>The scanner identified patterns in API responses that might indicate sensitive data exposure. Review these findings carefully.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>URL</th>
                            <th>Method</th>
                            <th>Status Code</th>
                            <th>Matched Value Preview</th>
                            <th>Context Preview</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in sensitive_data_findings %}
                        <tr>
                            <td><strong class="risk-high">{{ finding.type }}</strong></td>
                            <td><a href="{{ finding.url }}" target="_blank">{{ finding.url }}</a></td>
                            <td><code>{{ finding.method }}</code></td>
                            <td>{{ finding.status_code }}</td>
                            <td><code>{{ finding.matched_value_preview }}</code></td>
                            <td><pre>{{ finding.context_preview }}</pre></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No sensitive data exposure findings detected.</p>
                {% endif %}
            </div>

            <div class="section">
                <h2 id="security-headers">Security Header Findings ({{ security_header_findings|length }})</h2>
                {% if security_header_findings %}
                <p>These findings highlight missing or misconfigured HTTP security headers that could leave your API vulnerable to various client-side attacks.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>URL</th>
                            <th>Method</th>
                            <th>Status Code</th>
                            <th>Issue</th>
                            <th>Current Value</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in security_header_findings %}
                        <tr>
                            <td><code>{{ finding.header_name }}</code></td>
                            <td><a href="{{ finding.url }}" target="_blank">{{ finding.url }}</a></td>
                            <td><code>{{ finding.method }}</code></td>
                            <td>{{ finding.status_code }}</td>
                            <td>{{ finding.reason }}</td>
                            <td><code>{{ finding.current_value }}</code></td>
                            <td><strong class="risk-{{ finding.risk|lower }}">{{ finding.risk }}</strong></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No significant security header issues detected.</p>
                {% endif %}
            </div>

            <div class="section">
                <h2 id="cors-misconfigurations">CORS Misconfiguration Findings ({{ cors_findings|length }})</h2>
                {% if cors_findings %}
                <p>These findings indicate potential Cross-Origin Resource Sharing (CORS) misconfigurations, which could allow unauthorized cross-domain requests.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>URL</th>
                            <th>Method</th>
                            <th>Status Code</th>
                            <th>Tested Origin</th>
                            <th>Access-Control-Allow-Origin</th>
                            <th>Access-Control-Allow-Credentials</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in cors_findings %}
                        <tr>
                            <td><strong class="risk-{{ finding.risk|lower }}">{{ finding.type }}</strong></td>
                            <td><a href="{{ finding.url }}" target="_blank">{{ finding.url }}</a></td>
                            <td><code>{{ finding.method }}</code></td>
                            <td>{{ finding.status_code }}</td>
                            <td><code>{{ finding.tested_origin }}</code></td>
                            <td><code>{{ finding.acao_value }}</code></td>
                            <td><code>{{ finding.acac_value }}</code></td>
                            <td><strong class="risk-{{ finding.risk|lower }}">{{ finding.risk }}</strong></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No CORS misconfigurations detected.</p>
                {% endif %}
            </div>

            <div class="section">
                <h2 id="info-disclosure">Information Disclosure Findings ({{ info_disclosure_findings|length }})</h2>
                {% if info_disclosure_findings %}
                <p>These findings suggest the API or underlying server is leaking potentially sensitive information in its responses, which can aid attackers.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>URL</th>
                            <th>Method</th>
                            <th>Status Code</th>
                            <th>Matched Value Preview</th>
                            <th>Context Preview</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in info_disclosure_findings %}
                        <tr>
                            <td><strong class="risk-{{ finding.risk|lower }}">{{ finding.type }}</strong></td>
                            <td><a href="{{ finding.url }}" target="_blank">{{ finding.url }}</a></td>
                            <td><code>{{ finding.method }}</code></td>
                            <td>{{ finding.status_code }}</td>
                            <td><code>{{ finding.matched_value_preview }}</code></td>
                            <td><pre>{{ finding.context_preview }}</pre></td>
                            <td><strong class="risk-{{ finding.risk|lower }}">{{ finding.risk }}</strong></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No significant information disclosure issues detected.</p>
                {% endif %}
            </div>


            <div class="section">
                <h2 id="discovered-endpoints">Discovered Endpoints Inventory ({{ discovered_endpoints|length }})</h2>
                <p><strong>Total Discovered:</strong> {{ discovered_endpoints|length }}</p>
                <ul>
                    {% for ep in discovered_endpoints %}
                        <li><code>{{ ep.method }} {{ ep.url }}</code> (Status: {{ ep.status_code }}, Length: {{ ep.content_length }} bytes)
                            {% if ep.redirected_to %}
                                <br>Redirected to: <code>{{ ep.redirected_to }}</code>
                            {% endif %}
                        </li>
                    {% endfor %}
                </ul>
            </div>

            <div class="section">
                <h2 id="openapi-spec">Inferred OpenAPI Specification (Partial)</h2>
                <p>This is a basic, inferred schema. For a complete and accurate spec, manual review and refinement are required.</p>
                <pre>{{ inferred_openapi_spec | tojson(indent=2) }}</pre>
            </div>

            <div class="section">
                <h2 id="recommendations">Recommendations</h2>
                <ul>
                    <li>Review all "High" and "Medium" risk misconfigurations immediately.</li>
                    <li><strong>Investigate "Potential Unauthenticated Access Issues" as these represent critical security flaws.</strong></li>
                    <li>Investigate all "Potential Zombie APIs" to confirm if they are indeed deprecated or should be removed/fixed.</li>
                    <li>If GraphQL introspection is enabled, ensure it's intentional and not exposing sensitive schema details to unauthorized users.</li>
                    <li><strong>Thoroughly review "Parameter Fuzzing Findings" for potential injection vulnerabilities (SQLi, XSS, Command Injection) or unexpected server behavior.</strong></li>
                    <li><strong>URGENT: Review "Sensitive Data Exposure Findings" and ensure no confidential information is inadvertently leaked in API responses. This is often a critical security flaw.</strong></li>
                    <li><strong>Review "Security Header Findings" and implement/correct missing or misconfigured headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, etc.) to enhance client-side security.</strong></li>
                    <li><strong>URGENT: Review "CORS Misconfiguration Findings" carefully. Overly permissive CORS policies can lead to critical data leakage and cross-site attacks. Ensure `Access-Control-Allow-Origin` is strictly whitelisted and `Access-Control-Allow-Credentials` is only true when necessary and secure.</strong></li>
                    <li><strong>URGENT: Review "Information Disclosure Findings". The presence of stack traces, internal IPs, or database errors can provide attackers with invaluable insights into your application's architecture and potential vulnerabilities. Ensure verbose errors are suppressed in production.</strong></li> {# NEW Recommendation #}
                    <li>Ensure all sensitive endpoints require proper authentication and authorization.</li>
                    <li>Remove or secure debug/internal endpoints before production deployment.</li>
                    <li>Implement strict CORS policies.</li>
                    <li>Enable HTTPS for all API traffic.</li>
                    <li>Implement robust rate limiting to prevent abuse.</li>
                    <li>Thoroughly document all discovered shadow APIs.</li>
                </ul>
            </div>
        </body>
        </html>
        """
        env = Environment(loader=FileSystemLoader(os.path.dirname(__file__)))
        template = env.from_string(html_template) 
        
        formatted_current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        html_report = template.render(
            discovered_endpoints=report_data['discovered_endpoints'],
            misconfigurations=report_data['misconfigurations'],
            inferred_openapi_spec=report_data['inferred_openapi_spec'],
            scan_summary=report_data['scan_summary'],
            now_formatted=formatted_current_time,
            zombie_apis=report_data['zombie_apis'],
            graphql_findings=report_data['graphql_findings'],
            unauthenticated_access_findings=report_data['unauthenticated_access_findings'],
            parameter_fuzzing_findings=report_data['parameter_fuzzing_findings'],
            sensitive_data_findings=report_data['sensitive_data_findings'],
            security_header_findings=report_data['security_header_findings'],
            cors_findings=report_data['cors_findings'],
            info_disclosure_findings=report_data['info_disclosure_findings'],
            base_url=base_url,
            min_risk=min_risk # NEW: Pass min_risk to the template for display
        )
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        click.echo(f"HTML report saved to {output_file}")
    else:
        click.echo("Unsupported output format. Please use .json or .html")

    # NEW: Filter high-risk check for CI/CD mode based on min_risk
    high_risk_found = (
        (len(filtered_misconfigurations) > 0 and any(mc['risk'] == 'High' for mc in filtered_misconfigurations)) or
        len(filtered_unauthenticated_access) > 0 or
        len(filtered_parameter_fuzzing) > 0 or
        len(filtered_sensitive_data) > 0 or
        (len(filtered_security_headers) > 0 and any(shf['risk'] in ['High', 'Medium'] for shf in filtered_security_headers)) or
        (len(filtered_cors) > 0 and any(cf['risk'] in ['High', 'Medium'] for cf in filtered_cors)) or
        (len(filtered_info_disclosure) > 0 and any(idf['risk'] == 'High' for idf in filtered_info_disclosure))
    )
    
    if ci_mode and high_risk_found:
        click.echo("CI/CD mode: High-risk issues found. Exiting with code 1.")
        click.get_current_context().exit(1)
    elif ci_mode:
        click.echo("CI/CD mode: No high-risk issues found. Exiting with code 0.")
        click.get_current_context().exit(0)