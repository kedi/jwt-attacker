"""
Unit Tests for JWT alg:none Attack Module

This module contains unit tests for the alg:none attack functionality,
including tests for token creation, privilege escalation, and edge cases.
"""

import unittest
import json
import sys
import os

# Add the parent directory to the path to import jwt_attacker
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jwt_attacker.alg_none import create_alg_none_jwt, create_admin_alg_none_jwt, create_custom_alg_none_jwt, verify_alg_none_vulnerability
from jwt_attacker.utils import decode_jwt_header, decode_jwt_payload
from unittest.mock import patch


class TestAlgNoneAttack(unittest.TestCase):
    """Test cases for alg:none attack functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_payload = '{"user": "testuser", "role": "admin"}'
    
    def test_create_alg_none_jwt_success(self):
        """Test successful alg:none JWT creation."""
        with patch('jwt_attacker.alg_none.console'):
            token = create_alg_none_jwt(self.test_payload)
        
        self.assertIsNotNone(token)
        
        # Verify token format (should have 3 parts with empty signature)
        parts = token.split('.')
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[2], '')  # Empty signature
        
        # Verify header
        header = decode_jwt_header(token)
        self.assertEqual(header['alg'], 'none')
        self.assertEqual(header['typ'], 'JWT')
        
        # Verify payload
        payload = decode_jwt_payload(token)
        self.assertEqual(payload['user'], 'testuser')
        self.assertEqual(payload['role'], 'admin')
    
    def test_create_alg_none_jwt_invalid_json(self):
        """Test alg:none JWT creation with invalid JSON payload."""
        invalid_payload = '{"user": "testuser", "role": invalid}'
        
        with patch('jwt_attacker.alg_none.console'):
            token = create_alg_none_jwt(invalid_payload)
        
        self.assertIsNone(token)
    
    def test_create_alg_none_jwt_with_custom_header(self):
        """Test alg:none JWT creation with custom header."""
        custom_header = {"kid": "key123", "custom": "value"}
        
        with patch('jwt_attacker.alg_none.console'):
            token = create_alg_none_jwt(self.test_payload, custom_header)
        
        self.assertIsNotNone(token)
        
        # Verify custom header fields (alg should be overridden to 'none')
        header = decode_jwt_header(token)
        self.assertEqual(header['alg'], 'none')  # Should be 'none' regardless of custom header
        self.assertEqual(header['kid'], 'key123')
        self.assertEqual(header['custom'], 'value')
        self.assertEqual(header['typ'], 'JWT')
    
    def test_create_admin_alg_none_jwt(self):
        """Test creating admin alg:none JWT token."""
        with patch('jwt_attacker.alg_none.console'):
            token = create_admin_alg_none_jwt()
        
        self.assertIsNotNone(token)
        
        # Verify admin claims
        payload = decode_jwt_payload(token)
        self.assertEqual(payload['sub'], 'admin')
        self.assertEqual(payload['role'], 'administrator')
        self.assertTrue(payload['admin'])
        self.assertIn('permissions', payload)
        self.assertIn('admin', payload['permissions'])
        
        # Verify it's alg:none
        header = decode_jwt_header(token)
        self.assertEqual(header['alg'], 'none')
    
    def test_create_custom_alg_none_jwt(self):
        """Test creating custom alg:none JWT with specified claims."""
        user_id = "user123"
        role = "manager"
        extra_claims = {"department": "engineering", "level": 5}
        
        with patch('jwt_attacker.alg_none.console'):
            token = create_custom_alg_none_jwt(user_id, role, extra_claims)
        
        self.assertIsNotNone(token)
        
        # Verify claims
        payload = decode_jwt_payload(token)
        self.assertEqual(payload['sub'], user_id)
        self.assertEqual(payload['role'], role)
        self.assertEqual(payload['user_id'], user_id)
        self.assertEqual(payload['department'], 'engineering')
        self.assertEqual(payload['level'], 5)
        self.assertIn('iat', payload)
        
        # Verify it's alg:none
        header = decode_jwt_header(token)
        self.assertEqual(header['alg'], 'none')
    
    def test_verify_alg_none_vulnerability(self):
        """Test verification of alg:none vulnerability."""
        # Create alg:none token
        with patch('jwt_attacker.alg_none.console'):
            alg_none_token = create_alg_none_jwt(self.test_payload)
        
        # Create regular signed token for comparison
        import jwt
        signed_token = jwt.encode({"user": "test"}, "secret", algorithm="HS256")
        
        # Verify detection
        self.assertTrue(verify_alg_none_vulnerability(alg_none_token))
        self.assertFalse(verify_alg_none_vulnerability(signed_token))
        
        # Test with invalid token
        self.assertFalse(verify_alg_none_vulnerability("invalid.token"))
    
    def test_create_alg_none_jwt_empty_payload(self):
        """Test creating alg:none JWT with empty payload."""
        empty_payload = '{}'
        
        with patch('jwt_attacker.alg_none.console'):
            token = create_alg_none_jwt(empty_payload)
        
        self.assertIsNotNone(token)
        
        # Verify empty payload
        payload = decode_jwt_payload(token)
        self.assertEqual(len(payload), 0)
        
        # Verify it's still alg:none
        header = decode_jwt_header(token)
        self.assertEqual(header['alg'], 'none')
    
    def test_create_alg_none_jwt_complex_payload(self):
        """Test creating alg:none JWT with complex payload structure."""
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
        
        with patch('jwt_attacker.alg_none.console'):
            token = create_alg_none_jwt(complex_payload)
        
        self.assertIsNotNone(token)
        
        # Verify complex payload
        payload = decode_jwt_payload(token)
        self.assertEqual(payload['user'], 'testuser')
        self.assertEqual(len(payload['permissions']), 3)
        self.assertIn('read', payload['permissions'])
        self.assertEqual(payload['metadata']['created'], '2025-01-01')
        self.assertEqual(payload['numbers'], [1, 2, 3, 4, 5])
        self.assertTrue(payload['boolean'])
        self.assertIsNone(payload['null_value'])


class TestAlgNoneEdgeCases(unittest.TestCase):
    """Test edge cases for alg:none attack."""
    
    def test_create_alg_none_jwt_unicode_payload(self):
        """Test creating alg:none JWT with Unicode characters in payload."""
        unicode_payload = json.dumps({
            "user": "用户123",  # Chinese characters
            "name": "José María",  # Spanish accents
            "emoji": "🔐🚀✨"  # Emojis
        })
        
        with patch('jwt_attacker.alg_none.console'):
            token = create_alg_none_jwt(unicode_payload)
        
        self.assertIsNotNone(token)
        
        # Verify Unicode handling
        payload = decode_jwt_payload(token)
        self.assertEqual(payload['user'], '用户123')
        self.assertEqual(payload['name'], 'José María')
        self.assertEqual(payload['emoji'], '🔐🚀✨')
    
    def test_create_alg_none_jwt_privilege_escalation(self):
        """Test privilege escalation scenarios with alg:none."""
        # Start with regular user
        user_payload = '{"user": "regularuser", "role": "user"}'
        
        with patch('jwt_attacker.alg_none.console'):
            user_token = create_alg_none_jwt(user_payload)
        
        # Escalate to admin
        admin_payload = '{"user": "regularuser", "role": "admin", "admin": true}'
        
        with patch('jwt_attacker.alg_none.console'):
            admin_token = create_alg_none_jwt(admin_payload)
        
        # Verify both tokens are valid alg:none
        self.assertTrue(verify_alg_none_vulnerability(user_token))
        self.assertTrue(verify_alg_none_vulnerability(admin_token))
        
        # Verify privilege escalation
        user_payload_decoded = decode_jwt_payload(user_token)
        admin_payload_decoded = decode_jwt_payload(admin_token)
        
        self.assertEqual(user_payload_decoded['role'], 'user')
        self.assertEqual(admin_payload_decoded['role'], 'admin')
        self.assertTrue(admin_payload_decoded['admin'])
    
    def test_create_alg_none_jwt_malformed_header_override(self):
        """Test that alg is always overridden to 'none' even with malformed custom header."""
        malformed_header = {"alg": "HS256", "typ": "JWT"}  # Try to set alg to HS256
        
        with patch('jwt_attacker.alg_none.console'):
            token = create_alg_none_jwt(self.test_payload, malformed_header)
        
        self.assertIsNotNone(token)
        
        # Verify alg is overridden to 'none'
        header = decode_jwt_header(token)
        self.assertEqual(header['alg'], 'none')  # Should be 'none', not 'HS256'


if __name__ == '__main__':
    unittest.main(verbosity=2)
