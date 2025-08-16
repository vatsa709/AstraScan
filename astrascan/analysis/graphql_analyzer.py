# astrascan_project/astrascan/analysis/graphql_analyzer.py

import httpx
import json
import click
from astrascan.config import GRAPHQL_INTROSPECTION_QUERY # Import from new config file

def perform_graphql_introspection(client, graphql_url):
    """
    Sends an introspection query to the GraphQL endpoint and returns the parsed schema.
    """
    try:
        click.echo(f"  Performing GraphQL introspection on {graphql_url}...")
        headers = {"Content-Type": "application/json"}
        if client.headers:
            headers.update(client.headers)

        response = client.post(graphql_url, json={"query": GRAPHQL_INTROSPECTION_QUERY}, headers=headers)
        
        if response.status_code == 200:
            json_data = response.json()
            if 'data' in json_data and '__schema' in json_data['data']:
                click.echo("  GraphQL introspection successful.")
                return json_data['data']['__schema']
            elif 'errors' in json_data:
                click.echo(f"  GraphQL introspection failed (errors in response): {json_data['errors']}")
            else:
                click.echo(f"  GraphQL introspection response invalid or missing data: {response.text[:200]}...")
        else:
            click.echo(f"  GraphQL introspection failed with status {response.status_code}: {response.text[:200]}...")
    except httpx.RequestError as exc:
        click.echo(f"  GraphQL introspection network error: {exc}")
    except json.JSONDecodeError:
        click.echo(f"  GraphQL introspection response was not valid JSON.")
    except Exception as e:
        click.echo(f"  An unexpected error occurred during GraphQL introspection: {e}")
    return None

def generate_simple_graphql_queries(graphql_schema):
    """
    Generates a few simple GET-equivalent GraphQL queries based on the schema.
    This is a basic attempt to find readable fields.
    """
    generated_queries = []
    
    query_type = None
    for _type in graphql_schema.get('types', []):
        if _type.get('name') == graphql_schema.get('queryType', {}).get('name'):
            query_type = _type
            break
    
    if query_type and query_type.get('fields'):
        for field in query_type['fields']:
            field_name = field['name']
            
            if field_name.startswith('__'):
                continue
            
            can_query_without_args = True
            if field.get('args'):
                for arg in field['args']:
                    if arg['type'].get('kind') == 'NON_NULL' and arg.get('defaultValue') is None:
                        can_query_without_args = False
                        break
            
            if can_query_without_args:
                target_type = field['type']
                while target_type.get('ofType'):
                    target_type = target_type['ofType']
                
                type_name = target_type.get('name')
                
                actual_type_def = None
                for _type_def in graphql_schema.get('types', []):
                    if _type_def.get('name') == type_name:
                        actual_type_def = _type_def
                        break
                
                selected_subfields = []
                if actual_type_def and actual_type_def.get('fields'):
                    for subfield in actual_type_def['fields']:
                        if subfield['type'].get('kind') in ['SCALAR', 'ENUM']:
                            selected_subfields.append(subfield['name'])
                        if len(selected_subfields) >= 3:
                            break
                
                if selected_subfields:
                    query_string = f"query {{ {field_name} {{ {' '.join(selected_subfields)} }} }}"
                    generated_queries.append(query_string)
                else:
                    generated_queries.append(f"query {{ {field_name} }}")

            if len(generated_queries) >= 5: 
                break

    return generated_queries
