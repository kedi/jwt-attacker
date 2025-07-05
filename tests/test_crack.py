"""
Unit Tests for JWT Cracking Module

This module contains unit tests for the JWT cracking functionality,
including tests for successful cracks, failed attempts, and edge cases.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, mock_open
import jwt

# Add the parent directory to the path to import jwt_attacker
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jwt_attacker.crack import crack_jwt, generate_common_secrets
from jwt_attacker.utils import base64url_encode, base64url_decode, validate_jwt_format


class TestJWTCracking(unittest.TestCase):
    """Test cases for JWT cracking functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_secret = "secret"
        self.test_payload = {"user": "testuser", "role": "admin"}
        self.test_token = jwt.encode(self.test_payload, self.test_secret, algorithm="HS256")
        
        # Create a temporary wordlist file
        self.wordlist_content = ["wrong1", "wrong2", "secret", "wrong3"]
        self.temp_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False)
        for word in self.wordlist_content:
            self.temp_wordlist.write(f"{word}\n")
        self.temp_wordlist.close()
    
    def tearDown(self):
        """Clean up test fixtures."""
        os.unlink(self.temp_wordlist.name)
    
    def test_successful_crack(self):
        """Test successful JWT cracking with correct secret in wordlist."""
        # Mock console output to suppress prints during testing
        with patch('jwt_attacker.crack.console'):
            result = crack_jwt(self.test_token, self.temp_wordlist.name)
        
        self.assertEqual(result, self.test_secret)
    
    def test_failed_crack_no_secret(self):
        """Test failed JWT cracking when secret is not in wordlist."""
        # Create wordlist without the correct secret
        wrong_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False)
        wrong_secrets = ["wrong1", "wrong2", "wrong3"]
        for secret in wrong_secrets:
            wrong_wordlist.write(f"{secret}\n")
        wrong_wordlist.close()
        
        try:
            with patch('jwt_attacker.crack.console'):
                result = crack_jwt(self.test_token, wrong_wordlist.name)
            
            self.assertIsNone(result)
        finally:
            os.unlink(wrong_wordlist.name)
    
    def test_invalid_token_format(self):
        """Test cracking with invalid JWT token format."""
        invalid_token = "invalid.token.format"
        
        with patch('jwt_attacker.crack.console'):
            result = crack_jwt(invalid_token, self.temp_wordlist.name)
        
        self.assertIsNone(result)
    
    def test_empty_wordlist(self):
        """Test cracking with empty wordlist."""
        empty_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False)
        empty_wordlist.close()
        
        try:
            with patch('jwt_attacker.crack.console'):
                result = crack_jwt(self.test_token, empty_wordlist.name)
            
            self.assertIsNone(result)
        finally:
            os.unlink(empty_wordlist.name)
    
    def test_nonexistent_wordlist(self):
        """Test cracking with non-existent wordlist file."""
        nonexistent_file = "/path/to/nonexistent/wordlist.txt"
        
        with patch('jwt_attacker.crack.console'):
            result = crack_jwt(self.test_token, nonexistent_file)
        
        self.assertIsNone(result)
    
    def test_expired_token_crack(self):
        """Test cracking an expired JWT token."""
        import time
        
        # Create an expired token
        expired_payload = {
            "user": "testuser",
            "exp": int(time.time()) - 3600  # Expired 1 hour ago
        }
        expired_token = jwt.encode(expired_payload, self.test_secret, algorithm="HS256")
        
        with patch('jwt_attacker.crack.console'):
            result = crack_jwt(expired_token, self.temp_wordlist.name)
        
        self.assertEqual(result, self.test_secret)
    
    def test_generate_common_secrets(self):
        """Test generation of common secrets list."""
        secrets = generate_common_secrets()
        
        self.assertIsInstance(secrets, list)
        self.assertGreater(len(secrets), 0)
        self.assertIn("secret", secrets)
        self.assertIn("password", secrets)
        self.assertIn("admin", secrets)
    
    def test_crack_with_special_characters(self):
        """Test cracking with secrets containing special characters."""
        special_secret = "p@ssw0rd!"
        special_payload = {"user": "testuser"}
        special_token = jwt.encode(special_payload, special_secret, algorithm="HS256")
        
        # Create wordlist with special character secret
        special_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False)
        special_wordlist.write(f"{special_secret}\n")
        special_wordlist.close()
        
        try:
            with patch('jwt_attacker.crack.console'):
                result = crack_jwt(special_token, special_wordlist.name)
            
            self.assertEqual(result, special_secret)
        finally:
            os.unlink(special_wordlist.name)


class TestJWTUtils(unittest.TestCase):
    """Test cases for JWT utility functions."""
    
    def test_base64url_encode_decode(self):
        """Test Base64URL encoding and decoding."""
        test_data = b"Hello, World!"
        encoded = base64url_encode(test_data)
        decoded = base64url_decode(encoded)
        
        self.assertEqual(decoded, test_data)
    
    def test_base64url_padding(self):
        """Test Base64URL decoding with missing padding."""
        # Test string that requires padding
        test_string = "SGVsbG8"  # "Hello" in base64url without padding
        decoded = base64url_decode(test_string)
        
        self.assertEqual(decoded, b"Hello")
    
    def test_validate_jwt_format_valid(self):
        """Test JWT format validation with valid token."""
        valid_token = jwt.encode({"user": "test"}, "secret", algorithm="HS256")
        
        self.assertTrue(validate_jwt_format(valid_token))
    
    def test_validate_jwt_format_invalid(self):
        """Test JWT format validation with invalid tokens."""
        invalid_tokens = [
            "invalid",
            "invalid.token",
            "invalid.token.format.extra",
            "",
            "...",
            "invalid..token"
        ]
        
        for token in invalid_tokens:
            with self.subTest(token=token):
                self.assertFalse(validate_jwt_format(token))


class TestJWTCrackingEdgeCases(unittest.TestCase):
    """Test edge cases for JWT cracking."""
    
    def test_crack_with_unicode_secret(self):
        """Test cracking with Unicode characters in secret."""
        unicode_secret = "密码123"  # Chinese characters + numbers
        unicode_payload = {"user": "testuser"}
        unicode_token = jwt.encode(unicode_payload, unicode_secret, algorithm="HS256")
        
        # Create wordlist with Unicode secret
        unicode_wordlist = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False)
        unicode_wordlist.write(f"{unicode_secret}\n")
        unicode_wordlist.close()
        
        try:
            with patch('jwt_attacker.crack.console'):
                result = crack_jwt(unicode_token, unicode_wordlist.name)
            
            self.assertEqual(result, unicode_secret)
        finally:
            os.unlink(unicode_wordlist.name)
    
    def test_crack_with_empty_lines_in_wordlist(self):
        """Test cracking with wordlist containing empty lines."""
        secret = "correct_secret"
        token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        
        # Create wordlist with empty lines
        wordlist_with_empty = tempfile.NamedTemporaryFile(mode='w', delete=False)
        wordlist_content = ["wrong1", "", "wrong2", "", secret, "", "wrong3"]
        for line in wordlist_content:
            wordlist_with_empty.write(f"{line}\n")
        wordlist_with_empty.close()
        
        try:
            with patch('jwt_attacker.crack.console'):
                result = crack_jwt(token, wordlist_with_empty.name)
            
            self.assertEqual(result, secret)
        finally:
            os.unlink(wordlist_with_empty.name)
    
    def test_crack_with_whitespace_secret(self):
        """Test cracking with secrets containing whitespace."""
        whitespace_secret = "  secret with spaces  "
        whitespace_payload = {"user": "testuser"}
        whitespace_token = jwt.encode(whitespace_payload, whitespace_secret, algorithm="HS256")
        
        # Create wordlist with whitespace secret
        whitespace_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False)
        whitespace_wordlist.write(f"{whitespace_secret}\n")
        whitespace_wordlist.close()
        
        try:
            with patch('jwt_attacker.crack.console'):
                result = crack_jwt(whitespace_token, whitespace_wordlist.name)
            
            self.assertEqual(result, whitespace_secret.strip())  # read_wordlist strips whitespace
        finally:
            os.unlink(whitespace_wordlist.name)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)
