"""
JWT Forging Module

This module provides functionality to create custom JWT tokens with user-defined
headers, payloads, and signing secrets.
"""

import jwt
import json
from typing import Optional, Dict, Any
from rich.console import Console
from rich.panel import Panel

from .utils import pretty_print_jwt

console = Console()

def forge_jwt(payload: str, secret: str, algorithm: str = 'HS256', 
              custom_header: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Create a custom JWT token with specified payload and secret.
    
    Args:
        payload: JWT payload as JSON string
        secret: Secret key for signing
        algorithm: Signing algorithm (default: HS256)
        custom_header: Optional custom header dictionary
        
    Returns:
        JWT token string or None if error
    """
    try:
        # Parse payload JSON
        payload_dict = json.loads(payload)
        
        # Create header
        header = custom_header or {}
        if 'alg' not in header:
            header['alg'] = algorithm
        if 'typ' not in header:
            header['typ'] = 'JWT'
        
        # Create token
        token = jwt.encode(
            payload_dict,
            secret,
            algorithm=algorithm,
            headers=header
        )
        
        console.print(f"[green]✅ JWT token forged successfully![/green]")
        console.print(f"[dim]Algorithm: {algorithm}[/dim]")
        console.print(f"[dim]Secret: {secret}[/dim]")
        
        return token
        
    except json.JSONDecodeError as e:
        console.print(f"[red]❌ Invalid JSON payload: {str(e)}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]❌ Error forging JWT: {str(e)}[/red]")
        return None

def forge_jwt_with_claims(user_id: str, role: str = "user", 
                         secret: str = "secret", 
                         algorithm: str = 'HS256',
                         expires_in: Optional[int] = None) -> Optional[str]:
    """
    Create a JWT token with common claims.
    
    Args:
        user_id: User identifier
        role: User role (default: "user")
        secret: Secret key for signing
        algorithm: Signing algorithm (default: HS256)
        expires_in: Token expiration in seconds (optional)
        
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
        
        # Add expiration if specified
        if expires_in:
            payload["exp"] = int(time.time()) + expires_in
        
        # Create token
        token = jwt.encode(
            payload,
            secret,
            algorithm=algorithm
        )
        
        console.print(f"[green]✅ JWT token with claims created![/green]")
        console.print(f"[dim]User ID: {user_id}[/dim]")
        console.print(f"[dim]Role: {role}[/dim]")
        console.print(f"[dim]Algorithm: {algorithm}[/dim]")
        
        return token
        
    except Exception as e:
        console.print(f"[red]❌ Error creating JWT with claims: {str(e)}[/red]")
        return None

def forge_admin_jwt(secret: str = "secret", algorithm: str = 'HS256') -> Optional[str]:
    """
    Create an admin JWT token for testing.
    
    Args:
        secret: Secret key for signing
        algorithm: Signing algorithm (default: HS256)
        
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
        
        token = jwt.encode(
            admin_payload,
            secret,
            algorithm=algorithm
        )
        
        console.print(f"[green]✅ Admin JWT token created![/green]")
        console.print(f"[bold red]⚠️ This is a privileged token for testing only![/bold red]")
        
        return token
        
    except Exception as e:
        console.print(f"[red]❌ Error creating admin JWT: {str(e)}[/red]")
        return None

def forge_jwt_with_custom_algorithm(payload: str, secret: str, algorithm: str) -> Optional[str]:
    """
    Create a JWT token with a custom algorithm.
    
    Args:
        payload: JWT payload as JSON string
        secret: Secret key for signing
        algorithm: Custom signing algorithm
        
    Returns:
        JWT token string or None if error
    """
    supported_algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']
    
    if algorithm not in supported_algorithms:
        console.print(f"[red]❌ Unsupported algorithm: {algorithm}[/red]")
        console.print(f"[dim]Supported algorithms: {', '.join(supported_algorithms)}[/dim]")
        return None
    
    return forge_jwt(payload, secret, algorithm)

def forge_jwt_batch(payloads: list[str], secrets: list[str], algorithm: str = 'HS256') -> list[Optional[str]]:
    """
    Create multiple JWT tokens with different payloads and secrets.
    
    Args:
        payloads: List of JWT payloads as JSON strings
        secrets: List of secret keys for signing
        algorithm: Signing algorithm (default: HS256)
        
    Returns:
        List of JWT token strings (or None for errors)
    """
    tokens = []
    
    console.print(f"[blue]🔨 Forging {len(payloads)} JWT tokens...[/blue]")
    console.print()
    
    for i, (payload, secret) in enumerate(zip(payloads, secrets), 1):
        console.print(f"[bold blue]Token {i}/{len(payloads)}:[/bold blue]")
        token = forge_jwt(payload, secret, algorithm)
        tokens.append(token)
        console.print()
    
    successful_tokens = sum(1 for token in tokens if token is not None)
    console.print(f"[bold green]✅ Successfully forged {successful_tokens}/{len(payloads)} tokens[/bold green]")
    
    return tokens

def save_forged_tokens(tokens: list[str], filepath: str) -> None:
    """
    Save forged JWT tokens to a file.
    
    Args:
        tokens: List of JWT token strings
        filepath: Path to save tokens
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for i, token in enumerate(tokens, 1):
                if token:
                    f.write(f"# Token {i}\n")
                    f.write(f"{token}\n\n")
        
        valid_tokens = sum(1 for token in tokens if token is not None)
        console.print(f"[green]✅ Saved {valid_tokens} tokens to: {filepath}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Error saving tokens: {str(e)}[/red]")

def demonstrate_forge_vulnerabilities():
    """
    Demonstrate common JWT forging vulnerabilities for educational purposes.
    """
    console.print(Panel(
        "[bold red]⚠️ JWT Forging Vulnerabilities Demo[/bold red]\n\n"
        "This demonstrates common vulnerabilities in JWT implementations:\n\n"
        "1. [bold]Weak Secrets[/bold]: Easy to brute-force\n"
        "2. [bold]Predictable Secrets[/bold]: Default or common secrets\n"
        "3. [bold]No Secret Validation[/bold]: Accepting any secret\n"
        "4. [bold]Algorithm Confusion[/bold]: Accepting different algorithms\n\n"
        "[dim]For educational purposes only![/dim]",
        title="Educational Demo",
        border_style="red"
    ))
    
    # Demo tokens with weak secrets
    weak_secrets = ["secret", "password", "123456", "admin"]
    demo_payload = '{"user": "demo", "role": "user"}'
    
    console.print("\n[bold blue]Demo Tokens with Weak Secrets:[/bold blue]")
    for secret in weak_secrets:
        token = forge_jwt(demo_payload, secret)
        if token:
            console.print(f"[dim]Secret '{secret}': {token[:50]}...[/dim]")
