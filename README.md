# JWT Attacker Tool

A Python-based toolkit for testing the security of JWT implementations. This tool helps researchers, developers, and bug bounty hunters identify common JWT misconfigurations and vulnerabilities.

## Features

- **HS256 Secret Cracker**: Brute-force weak signing keys
- **JWT Forger**: Sign your own payloads with custom headers
- **alg: none Attack**: Generate unsigned tokens
- **Rich CLI Interface**: Beautiful terminal output with colors

## Disclaimer

**This tool is for educational and authorized testing purposes only. Do not use it against systems you don't have permission to test. The authors are not responsible for any misuse of this tool.**

## Installation

### Option 1: Clone and Install

```bash
git clone https://github.com/kedi/jwt-attacker
cd jwt-attacker
pip install -r requirements.txt
```

### Option 2: Install as Package

```bash
pip install -e .
```

## Usage

### Basic Command Structure

```bash
python -m jwt_attacker <command> [options]
```

### 1. Crack HS256 Tokens

Brute-force attack on HS256 signed tokens:

```bash
python -m jwt_attacker crack --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." --wordlist examples/wordlist.txt
```

### 2. Forge JWT Tokens

Create custom signed JWT tokens:

```bash
python -m jwt_attacker forge --payload '{"user": "admin", "role": "administrator"}' --secret "mysecret"
```

### 3. Generate alg:none Tokens

Create unsigned tokens (alg:none attack):

```bash
python -m jwt_attacker alg-none --payload '{"user": "admin", "role": "administrator"}'
```

### Windows PowerShell Usage

For Windows PowerShell users, use escaped double quotes:

```powershell
# alg:none attack
python -m jwt_attacker alg-none --payload '{\"user\":\"admin\",\"role\":\"administrator\"}'

# Forge JWT token
python -m jwt_attacker forge --payload '{\"user\":\"admin\"}' --secret "mysecret"

# Crack JWT token
python -m jwt_attacker crack --token "eyJ0eXAiOi..." --wordlist examples/wordlist.txt
```

**PowerShell Tips:**

- Use single quotes around the entire JSON payload
- Escape double quotes inside JSON with backslash: `\"`
- Example: `--payload '{\"key\":\"value\"}'`

For an interactive PowerShell example script, run:

```powershell
powershell -ExecutionPolicy Bypass -File examples/windows_examples.ps1
```

## Project Structure

```
jwt-attacker/
├── README.md
├── LICENSE
├── requirements.txt
├── setup.py
├── .gitignore
├── jwt_attacker/
│   ├── __init__.py
│   ├── main.py
│   ├── forge.py
│   ├── crack.py
│   ├── alg_none.py
│   └── utils.py
├── examples/
│   ├── token_example.txt
│   └── wordlist.txt
└── tests/
    └── test_crack.py
```

## Testing

Run the test suite:

```bash
python -m pytest tests/
```

## Examples

### Example 1: Crack a Weak Token

```bash
python -m jwt_attacker crack --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Njc1NzI0NTQsImlhdCI6MTc1MTY3NDg1NCwibmJmIjoxNzUxNjc0ODU0LCJpc3MiOiJ0ZXN0LmNvbSIsInN1YiI6InlvdXItc3ViamVjdCIsImF1ZCI6InlvdXItYXVkaWVuY2UiLCJqdGkiOiJ5b3VyLWluZGVudGlmaWVyIn0.AU3QiW8J1kN6pzjpe8T3ikX5UK7ensTGEa8RZDb9qL4" --wordlist examples/wordlist.txt
```

### Example 2: Forge Admin Token

```bash
python -m jwt_attacker forge --payload '{"user": "admin", "admin": true}' --secret "secret123"
```

### Example 3: Generate Unsigned Token

```bash
python -m jwt_attacker alg-none --payload '{"user": "admin", "admin": true}'
```

### Windows PowerShell Examples

```powershell
# Example 1: Crack a weak token
python -m jwt_attacker crack --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --wordlist examples/wordlist.txt

# Example 2: Forge admin token
python -m jwt_attacker forge --payload '{\"user\":\"admin\",\"admin\":true}' --secret "secret123"

# Example 3: Generate unsigned token
python -m jwt_attacker alg-none --payload '{\"user\":\"admin\",\"admin\":true}'
```

### Example 3: Generate Unsigned Token

```bash
python -m jwt_attacker alg-none --payload '{"user": "admin", "admin": true}'
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Resources

- [JWT.io](https://jwt.io/) - JWT Debugger
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Common JWT Vulnerabilities](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
