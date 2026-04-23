# Roger IDOR 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Insecure Direct Object Reference (IDOR) scanner for bug bounty hunting.**

Tests for authorization bypass vulnerabilities by extracting and manipulating object IDs in URLs to access unauthorized resources.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

## Why IDOR?

IDOR is a critical access control vulnerability:
- Access other users' data
- View private information
- Modify other users' resources
- Escalate privileges

## Features

- Extracts IDs from URLs
- Generates ID variations for testing
- Tests numeric and UUID-based IDs
- Supports cookie/authentication
- Compares responses to detect bypasses

## Installation

```bash
git clone https://github.com/jrabbit00/roger-idor.git
cd roger-idor
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 idor.py https://target.com/user/123/profile

# With cookies
python3 idor.py "https://target.com/api/user/456" -c "session=abc123"

# With basic auth
python3 idor.py "https://target.com/dashboard/789" -a "user:pass"

# Save results
python3 idor.py target.com -o findings.txt
```

## What It Tests

- Path-based IDs (/user/123)
- Query parameter IDs (?id=456)
- UUID-based identifiers
- ID enumeration (increment/decrement)
- Authorization bypass

## Important Notes

- Requires authentication for most tests
- IDs must be present in URL
- Manual verification needed
- Check bug bounty scope first

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger IDOR helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)