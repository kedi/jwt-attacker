"""
Unit Tests for JWT Forging Module

This module contains unit tests for the JWT forging functionality,
including tests for token creation, custom claims, and edge cases.
"""

import unittest
import json
import jwt
import sys
import os

# Add the parent directory to the path to import jwt_attacker
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jwt_attacker.forge import forge_jwt, forge_admin_jwt, forge_jwt_with_claims
from jwt_attacker.utils import decode_jwt_header, decode_jwt_payload
from unittest.mock import patch


class TestJWTForging(unittest.TestCase):
    """Test cases for JWT forging functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_secret = "test_secret"
        self.test_payload = '{"user": "testuser", "role": "admin"}'
        self.test_algorithm = "HS256"
    
    def test_forge_jwt_success(self):
        """Test successful JWT forging."""
        with patch('jwt_attacker.forge.console'):
            token = forge_jwt(self.test_payload, self.test_secret, self.test_algorithm)
        
        self.assertIsNotNone(token)
        
        # Verify the token can be decoded
        decoded = jwt.decode(token, self.test_secret, algorithms=[self.test_algorithm])
        self.assertEqual(decoded['user'], 'testuser')
        self.assertEqual(decoded['role'], 'admin')
    
    def test_forge_jwt_invalid_json(self):
        """Test JWT forging with invalid JSON payload."""
        invalid_payload = '{"user": "testuser", "role": invalid}'
        
        with patch('jwt_attacker.forge.console'):
            token = forge_jwt(invalid_payload, self.test_secret, self.test_algorithm)
        
        self.assertIsNone(token)
    
    def test_forge_jwt_with_custom_header(self):
        """Test JWT forging with custom header."""
        custom_header = {"kid": "key123", "custom": "value"}
        
        with patch('jwt_attacker.forge.console'):
            token = forge_jwt(self.test_payload, self.test_secret, self.test_algorithm, custom_header)
        
        self.assertIsNotNone(token)
        
        # Verify custom header fields
        header = decode_jwt_header(token)
        self.assertEqual(header['kid'], 'key123')
        self.assertEqual(header['custom'], 'value')
        self.assertEqual(header['alg'], self.test_algorithm)
    
    def test_forge_admin_jwt(self):
        """Test forging admin JWT token."""
        with patch('jwt_attacker.forge.console'):
            token = forge_admin_jwt(self.test_secret, self.test_algorithm)
        
        self.assertIsNotNone(token)
        
        # Verify admin claims
        decoded = jwt.decode(token, self.test_secret, algorithms=[self.test_algorithm])
        self.assertEqual(decoded['sub'], 'admin')
        self.assertEqual(decoded['role'], 'administrator')
        self.assertTrue(decoded['admin'])
        self.assertIn('permissions', decoded)
        self.assertIn('admin', decoded['permissions'])
    
    def test_forge_jwt_with_claims(self):
        """Test forging JWT with standard claims."""
        user_id = "user123"
        role = "manager"
        
        with patch('jwt_attacker.forge.console'):
            token = forge_jwt_with_claims(user_id, role, self.test_secret, self.test_algorithm)
        
        self.assertIsNotNone(token)
        
        # Verify claims
        decoded = jwt.decode(token, self.test_secret, algorithms=[self.test_algorithm])
        self.assertEqual(decoded['sub'], user_id)
        self.assertEqual(decoded['role'], role)
        self.assertEqual(decoded['user_id'], user_id)
        self.assertIn('iat', decoded)
    
    def test_forge_jwt_with_expiration(self):
        """Test forging JWT with expiration."""
        user_id = "user123"
        expires_in = 3600  # 1 hour
        
        with patch('jwt_attacker.forge.console'):
            token = forge_jwt_with_claims(user_id, expires_in=expires_in, secret=self.test_secret)
        
        self.assertIsNotNone(token)
        
        # Verify expiration
        decoded = jwt.decode(token, self.test_secret, algorithms=[self.test_algorithm])
        self.assertIn('exp', decoded)
        self.assertGreater(decoded['exp'], decoded['iat'])
    
    def test_forge_jwt_different_algorithms(self):
        """Test forging JWT with different algorithms."""
        algorithms = ['HS256', 'HS384', 'HS512']
        
        for alg in algorithms:
            with self.subTest(algorithm=alg):
                with patch('jwt_attacker.forge.console'):
                    token = forge_jwt(self.test_payload, self.test_secret, alg)
                
                self.assertIsNotNone(token)
                
                # Verify algorithm in header
                header = decode_jwt_header(token)
                self.assertEqual(header['alg'], alg)
                
                # Verify token can be decoded
                decoded = jwt.decode(token, self.test_secret, algorithms=[alg])
                self.assertEqual(decoded['user'], 'testuser')


class TestJWTForgingEdgeCases(unittest.TestCase):
    """Test edge cases for JWT forging."""
    
    def test_forge_jwt_empty_payload(self):
        """Test forging JWT with empty payload."""
        empty_payload = '{}'
        
        with patch('jwt_attacker.forge.console'):
            token = forge_jwt(empty_payload, "secret", "HS256")
        
        self.assertIsNotNone(token)
        
        # Verify empty payload
        decoded = jwt.decode(token, "secret", algorithms=["HS256"])
        self.assertEqual(len(decoded), 0)
    
    def test_forge_jwt_complex_payload(self):
        """Test forging JWT with complex payload structure."""
        complex_payload = json.dumps({
            "user": "testuser",
            "permissions": ["read", "write", "delete"],
            "metadata": {
                "created": "2025-01-01",
                "source": "api"
            },
            "numbers": [1, 2, 3, 4, 5],
            "boolean": True,
            "null_value": None
        })
        
        with patch('jwt_attacker.forge.console'):
            token = forge_jwt(complex_payload, "secret", "HS256")
        
        self.assertIsNotNone(token)
        
        # Verify complex payload
        decoded = jwt.decode(token, "secret", algorithms=["HS256"])
        self.assertEqual(decoded['user'], 'testuser')
        self.assertEqual(len(decoded['permissions']), 3)
        self.assertIn('read', decoded['permissions'])
        self.assertEqual(decoded['metadata']['created'], '2025-01-01')
        self.assertEqual(decoded['numbers'], [1, 2, 3, 4, 5])
        self.assertTrue(decoded['boolean'])
        self.assertIsNone(decoded['null_value'])
    
    def test_forge_jwt_unicode_payload(self):
        """Test forging JWT with Unicode characters in payload."""
        unicode_payload = json.dumps({
            "user": "用户123",  # Chinese characters
            "name": "José María",  # Spanish accents
            "emoji": "🔐🚀✨"  # Emojis
        })
        
        with patch('jwt_attacker.forge.console'):
            token = forge_jwt(unicode_payload, "secret", "HS256")
        
        self.assertIsNotNone(token)
        
        # Verify Unicode handling
        decoded = jwt.decode(token, "secret", algorithms=["HS256"])
        self.assertEqual(decoded['user'], '用户123')
        self.assertEqual(decoded['name'], 'José María')
        self.assertEqual(decoded['emoji'], '🔐🚀✨')
    
    def test_forge_jwt_long_secret(self):
        """Test forging JWT with very long secret."""
        long_secret = "a" * 1000  # 1000 character secret
        
        with patch('jwt_attacker.forge.console'):
            token = forge_jwt(self.test_payload, long_secret, "HS256")
        
        self.assertIsNotNone(token)
        
        # Verify token can be decoded with long secret
        decoded = jwt.decode(token, long_secret, algorithms=["HS256"])
        self.assertEqual(decoded['user'], 'testuser')


if __name__ == '__main__':
    unittest.main(verbosity=2)
