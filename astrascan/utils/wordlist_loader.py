# astrascan_project/astrascan/utils/wordlist_loader.py

import os
import click
from astrascan.config import COMMON_SUFFIXES # Import from new config file

def load_wordlist(wordlist_path):
    """Loads endpoints from a user-supplied wordlist or uses a built-in common list."""
    if wordlist_path and os.path.exists(wordlist_path):
        click.echo(f"Using custom wordlist: {wordlist_path}")
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    else:
        click.echo("Using built-in common wordlist.")
        return COMMON_SUFFIXES
