# astrascan_project/astrascan/api_specs/openapi_parser.py

import json
import yaml
import click
from astrascan.config import HTTP_METHODS # Import from new config file

def parse_openapi_spec(spec_path, base_url):
    """
    Parses an OpenAPI/Swagger specification file to extract documented paths and methods.
    Returns a set of (normalized_path, method) tuples.
    """
    documented_endpoints_set = set()
    try:
        with open(spec_path, 'r') as f:
            if spec_path.lower().endswith(('.yml', '.yaml')):
                spec = yaml.safe_load(f)
            else: # Assume JSON
                spec = json.load(f)

        if not spec or 'paths' not in spec:
            click.echo(f"Warning: No 'paths' found in the OpenAPI spec at {spec_path}")
            return documented_endpoints_set

        for path, path_item in spec['paths'].items():
            normalized_path = path.strip('/')
            
            for method, operation_object in path_item.items():
                if method.lower() in [m.lower() for m in HTTP_METHODS]:
                    documented_endpoints_set.add((normalized_path, method.upper()))
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        click.echo(f"Error parsing OpenAPI spec {spec_path}: {e}")
    except Exception as e:
        click.echo(f"An unexpected error occurred while loading OpenAPI spec {spec_path}: {e}")

    return documented_endpoints_set
