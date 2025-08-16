# astrascan_project/astrascan/utils/path_extractor.py

import json
import re
from urllib.parse import urlparse

def extract_paths_from_response(base_url, response_text, discovered_paths_set):
    """
    Extracts potential new paths from a response's text content.
    Looks for JSON keys, simple URL patterns, etc.
    Filters out already discovered paths and common file extensions.
    """
    new_paths = set()
    parsed_base_url = urlparse(base_url)
    
    # 1. Look for patterns in JSON responses (e.g., common keys that might be paths)
    try:
        json_data = json.loads(response_text)
        def find_potential_paths_in_json(data):
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, str):
                        if v.startswith('/') and not v.startswith('//'):
                            new_paths.add(v.strip('/'))
                        elif v.startswith(parsed_base_url.scheme) and parsed_base_url.netloc in v:
                            if urlparse(v).path:
                                new_paths.add(urlparse(v).path.strip('/'))
                    elif isinstance(v, (dict, list)):
                        find_potential_paths_in_json(v)
            elif isinstance(data, list):
                for item in data:
                    find_potential_paths_in_json(item)
            return None
        find_potential_paths_in_json(json_data)
    except json.JSONDecodeError:
        pass

    # 2. Look for relative URLs/paths in general text
    path_regex = re.compile(r'/(?:[a-zA-Z0-9_-]+/?)+(?![a-zA-Z0-9_.-])', re.IGNORECASE)
    for match in path_regex.finditer(response_text):
        potential_path = match.group(0)
        if potential_path:
            normalized_path = potential_path.strip('/')
            if not any(normalized_path.lower().endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.html', '.htm', '.pdf', '.xml', '.txt']):
                new_paths.add(normalized_path)

    filtered_paths = {p for p in new_paths if p and p not in discovered_paths_set}
    return filtered_paths
