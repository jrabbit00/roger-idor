# Roger IDOR 🐰

Insecure Direct Object Reference scanner for bug bounty hunting. Tests for authorization bypass vulnerabilities.

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

## License

MIT License