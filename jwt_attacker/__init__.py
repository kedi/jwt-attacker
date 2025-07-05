"""
JWT Attacker Tool - A Python-based toolkit for testing JWT security vulnerabilities.

This package provides tools for:
- Brute-force attacks on HS256 tokens
- JWT token forging
- alg:none attacks
- JWT token analysis

For educational and authorized testing purposes only.
"""

__version__ = "0.1.0"
__author__ = "JWT Attacker Tool"
__email__ = "furkan@wearehackerone.com"

from .crack import crack_jwt
from .forge import forge_jwt
from .alg_none import create_alg_none_jwt
from .utils import decode_jwt_header, decode_jwt_payload, pretty_print_jwt

__all__ = [
    "crack_jwt",
    "forge_jwt", 
    "create_alg_none_jwt",
    "decode_jwt_header",
    "decode_jwt_payload",
    "pretty_print_jwt"
]
