"""
JWT Utilities Module

This module provides utility functions for JWT operations including:
- Base64URL encoding/decoding
- JWT token parsing and pretty printing
- File operations for wordlists and tokens
"""

import base64
import json
from typing import Optional, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()

def base64url_decode(data: str) -> bytes:
    """
    Decode Base64URL data.
    
    Args:
        data: Base64URL encoded string
        
    Returns:
        Decoded bytes
    """
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    
    # Replace URL-safe characters
    data = data.replace('-', '+').replace('_', '/')
    
    return base64.b64decode(data)

def base64url_encode(data: bytes) -> str:
    """
    Encode data to Base64URL format.
    
    Args:
        data: Data to encode
        
    Returns:
        Base64URL encoded string
    """
    # Standard base64 encode
    encoded = base64.b64encode(data).decode('ascii')
    
    # Replace characters for URL-safe format and remove padding
    return encoded.replace('+', '-').replace('/', '_').rstrip('=')

def decode_jwt_header(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT header from token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded header as dictionary or None if invalid
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        header_data = base64url_decode(parts[0])
        return json.loads(header_data.decode('utf-8'))
    except Exception:
        return None

def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT payload from token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded payload as dictionary or None if invalid
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        payload_data = base64url_decode(parts[1])
        return json.loads(payload_data.decode('utf-8'))
    except Exception:
        return None

def pretty_print_jwt(token: str) -> None:
    """
    Pretty print a JWT token with syntax highlighting.
    
    Args:
        token: JWT token string
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            console.print("[red]Invalid JWT token format![/red]")
            return
        
        header = decode_jwt_header(token)
        payload = decode_jwt_payload(token)
        
        if not header or not payload:
            console.print("[red]Failed to decode JWT token![/red]")
            return
        
        # Create table for token parts
        table = Table(title="JWT Token Analysis", show_header=True, header_style="bold magenta")
        table.add_column("Part", style="cyan", width=12)
        table.add_column("Content", style="white")
        
        # Add header
        header_json = json.dumps(header, indent=2)
        table.add_row("Header", Syntax(header_json, "json", theme="monokai", line_numbers=False))
        
        # Add payload
        payload_json = json.dumps(payload, indent=2)
        table.add_row("Payload", Syntax(payload_json, "json", theme="monokai", line_numbers=False))
        
        # Add signature info
        signature_info = f"Signature: {parts[2][:20]}..." if len(parts[2]) > 20 else f"Signature: {parts[2]}"
        table.add_row("Signature", signature_info)
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error parsing JWT token: {str(e)}[/red]")

def read_wordlist(filepath: str) -> list[str]:
    """
    Read wordlist from file.
    
    Args:
        filepath: Path to wordlist file
        
    Returns:
        List of words from file
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]Wordlist file not found: {filepath}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error reading wordlist: {str(e)}[/red]")
        return []

def read_token_file(filepath: str) -> Optional[str]:
    """
    Read JWT token from file.
    
    Args:
        filepath: Path to token file
        
    Returns:
        JWT token string or None if error
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except FileNotFoundError:
        console.print(f"[red]Token file not found: {filepath}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Error reading token file: {str(e)}[/red]")
        return None

def validate_jwt_format(token: str) -> bool:
    """
    Validate JWT token format.
    
    Args:
        token: JWT token string
        
    Returns:
        True if valid format, False otherwise
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Try to decode header and payload
        header = decode_jwt_header(token)
        payload = decode_jwt_payload(token)
        
        return header is not None and payload is not None
    except Exception:
        return False

def format_time_duration(seconds: float) -> str:
    """
    Format time duration in human-readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted time string
    """
    if seconds < 1:
        return f"{seconds*1000:.2f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.2f}s"
