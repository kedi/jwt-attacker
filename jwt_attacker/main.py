"""
JWT Attacker Tool - Main CLI Interface

This module provides the command-line interface for the JWT Attacker Tool.
"""

import argparse
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from .crack import crack_jwt
from .forge import forge_jwt
from .alg_none import create_alg_none_jwt
from .utils import pretty_print_jwt

console = Console()

def print_banner():
    """Print the tool banner."""
    banner = Text()
    banner.append("🔐 JWT Attacker Tool v0.1.0", style="bold red")
    banner.append("\n")
    banner.append("Educational JWT Security Testing Toolkit", style="dim")
    
    panel = Panel(
        banner,
        title="Welcome",
        border_style="red",
        padding=(1, 2)
    )
    console.print(panel)
    console.print()

def cmd_crack(args):
    """Handle the crack command."""
    console.print(f"[bold blue]🔓 Starting JWT Crack Attack...[/bold blue]")
    console.print(f"[dim]Token: {args.token[:50]}...[/dim]")
    console.print(f"[dim]Wordlist: {args.wordlist}[/dim]")
    console.print()
    
    result = crack_jwt(args.token, args.wordlist)
    
    if result:
        console.print(f"[bold green]✅ SUCCESS! Secret found: {result}[/bold green]")
    else:
        console.print(f"[bold red]❌ FAILED! No secret found in wordlist.[/bold red]")

def cmd_forge(args):
    """Handle the forge command."""
    console.print(f"[bold blue]✍️ Forging JWT Token...[/bold blue]")
    console.print(f"[dim]Payload: {args.payload}[/dim]")
    console.print(f"[dim]Secret: {args.secret}[/dim]")
    console.print()
    
    result = forge_jwt(args.payload, args.secret, args.algorithm)
    
    if result:
        console.print(f"[bold green]✅ Token forged successfully![/bold green]")
        console.print(f"[bold white]Token:[/bold white] {result}")
        console.print()
        
        # Pretty print the token
        pretty_print_jwt(result)
    else:
        console.print(f"[bold red]❌ Failed to forge token![/bold red]")

def cmd_alg_none(args):
    """Handle the alg-none command."""
    console.print(f"[bold blue]🚫 Creating alg:none JWT Token...[/bold blue]")
    console.print(f"[dim]Payload: {args.payload}[/dim]")
    console.print()
    
    result = create_alg_none_jwt(args.payload)
    
    if result:
        console.print(f"[bold green]✅ alg:none token created successfully![/bold green]")
        console.print(f"[bold white]Token:[/bold white] {result}")
        console.print()
        
        # Pretty print the token
        pretty_print_jwt(result)
    else:
        console.print(f"[bold red]❌ Failed to create alg:none token![/bold red]")

def create_parser():
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        description="JWT Attacker Tool - Educational JWT Security Testing Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s crack --token "eyJ0eXAiOi..." --wordlist wordlist.txt
  %(prog)s forge --payload '{"user":"admin"}' --secret "mysecret"
  %(prog)s alg-none --payload '{"user":"admin"}'
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Crack command
    crack_parser = subparsers.add_parser('crack', help='Brute-force attack on HS256 tokens')
    crack_parser.add_argument('--token', '-t', required=True, help='JWT token to crack')
    crack_parser.add_argument('--wordlist', '-w', required=True, help='Path to wordlist file')
    
    # Forge command
    forge_parser = subparsers.add_parser('forge', help='Create custom signed JWT tokens')
    forge_parser.add_argument('--payload', '-p', required=True, help='JWT payload as JSON string')
    forge_parser.add_argument('--secret', '-s', required=True, help='Secret key for signing')
    forge_parser.add_argument('--algorithm', '-a', default='HS256', help='Signing algorithm (default: HS256)')
    
    # alg-none command
    alg_none_parser = subparsers.add_parser('alg-none', help='Create unsigned JWT tokens')
    alg_none_parser.add_argument('--payload', '-p', required=True, help='JWT payload as JSON string')
    
    return parser

def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    print_banner()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'crack':
            cmd_crack(args)
        elif args.command == 'forge':
            cmd_forge(args)
        elif args.command == 'alg-none':
            cmd_alg_none(args)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        console.print("\n[bold red]⚠️ Operation cancelled by user.[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]❌ Error: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
