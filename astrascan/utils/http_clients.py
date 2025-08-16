# astrascan_project/astrascan/utils/http_clients.py

import httpx

def setup_http_clients(timeout, no_verify_ssl, token):
    """
    Sets up and returns two httpx.Client instances: one with authentication (if provided)
    and one without, for unauthenticated access checks.
    """
    headers = {}
    token_provided = False

    if token:
        token_provided = True
        if ':' in token:
            header_name, header_value = token.split(':', 1)
            headers[header_name.strip()] = header_value.strip()
        else:
            headers['Authorization'] = f"Bearer {token.strip()}"
    
    # Client with authentication (or no auth if token is None)
    auth_client = httpx.Client(timeout=timeout, verify=not no_verify_ssl, headers=headers)
    
    # Client without authentication (for unauthenticated access checks)
    unauth_client = httpx.Client(timeout=timeout, verify=not no_verify_ssl)

    return auth_client, unauth_client, token_provided
