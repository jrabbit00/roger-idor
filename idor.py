#!/usr/bin/env python3
"""
Roger IDOR - Insecure Direct Object Reference scanner for bug bounty hunting.
"""

import argparse
import requests
import urllib3
import re
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RogerIDOR:
    def __init__(self, target, cookie=None, auth=None, threads=5, quiet=False, output=None, timeout=15):
        self.target = target.rstrip('/')
        self.cookie = cookie
        self.auth = auth
        self.threads = threads
        self.quiet = quiet
        self.output = output
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        
        # Add auth if provided
        if self.auth:
            self.session.auth = self.auth
        
        # Add cookies if provided
        if self.cookie:
            for cookie_str in self.cookie.split(';'):
                if '=' in cookie_str:
                    name, value = cookie_str.strip().split('=', 1)
                    self.session.cookies.set(name, value)
        
    def extract_ids(self, url):
        """Extract potential ID parameters from URL."""
        ids = []
        
        # Check path for IDs
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        
        for part in path_parts:
            if part.isdigit():
                ids.append(("path", part))
            elif re.match(r'^[a-f0-9]{8,32}$', part):
                ids.append(("path_uuid", part))
        
        # Check query parameters
        query = parse_qs(parsed.query)
        for param, values in query.items():
            value = values[0]
            if value.isdigit():
                ids.append(("param", param, value))
            elif re.match(r'^[a-f0-9]{8,32}$', value):
                ids.append(("param_uuid", param, value))
        
        return ids
    
    def generate_variations(self, id_value):
        """Generate ID variations for testing."""
        variations = []
        
        try:
            # Numeric variations
            num_id = int(id_value)
            variations.append(str(num_id - 1))  # Decrement
            variations.append(str(num_id + 1))  # Increment
            variations.append(str(num_id * 2))  # Multiply
            variations.append("0")
            variations.append("1")
            variations.append("999999")
            
            # String variations (for UUIDs)
            if re.match(r'^[a-f0-9]{8,32}$', id_value):
                variations.append("00000000" + "0" * 24)
                variations.append("f" * len(id_value))
                
        except ValueError:
            pass
        
        return variations
    
    def test_idor(self, url, original_id, test_id, id_type="path"):
        """Test for IDOR by changing the ID."""
        try:
            parsed = urlparse(url)
            
            if id_type == "path":
                # Replace in path
                new_path = parsed.path.replace(original_id, test_id)
                new_url = parsed._replace(path=new_path).geturl()
            else:
                # Replace in query
                query = parse_qs(parsed.query)
                for param, values in query.items():
                    if original_id in values:
                        query[param] = [v.replace(original_id, test_id) for v in values]
                new_query = urlencode(query, doseq=True)
                new_url = parsed._replace(query=new_query).geturl()
            
            # Make request
            response1 = self.session.get(url, timeout=self.timeout, verify=False)
            response2 = self.session.get(new_url, timeout=self.timeout, verify=False)
            
            # Compare responses
            if response1.status_code == response2.status_code:
                # Check if we got different data
                if response1.text != response2.text:
                    # Check if test_id response indicates success
                    if response2.status_code == 200 and len(response2.text) > 100:
                        return {
                            "original_url": url,
                            "test_url": new_url,
                            "original_id": original_id,
                            "test_id": test_id,
                            "status": response2.status_code,
                            "different_content": True,
                            "severity": "HIGH"
                        }
            
            return None
            
        except Exception as e:
            if not self.quiet:
                print(f"[!] Error: {e}")
            return None
    
    def test_authorization(self, url):
        """Test if accessing resource without auth works."""
        try:
            # Try without session
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code in [200, 201, 204]:
                return {
                    "url": url,
                    "status": response.status_code,
                    "type": "no_auth_required",
                    "severity": "MEDIUM"
                }
            
            return None
        except:
            return None
    
    def scan(self):
        """Run the IDOR scanner."""
        print(f"[*] Starting IDOR scan on: {self.target}")
        print("=" * 60)
        
        # First, get the page and extract IDs
        print("[*] Extracting IDs from URL...")
        
        ids = self.extract_ids(self.target)
        
        if not ids:
            print("[*] No IDs found in URL, trying to find them in response...")
            # Try to get some IDs from the response
            try:
                response = self.session.get(self.target, timeout=self.timeout, verify=False)
                
                # Look for common ID patterns in HTML/JS
                patterns = [
                    r'/users/(\d+)',
                    r'/id=(\d+)',
                    r'"id":(\d+)',
                    r'data-id="(\d+)"',
                    r'/posts/(\d+)',
                    r'/orders/(\d+)',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, response.text)
                    for match in matches[:5]:
                        ids.append(("response", match))
                        
            except Exception as e:
                print(f"[!] Error fetching page: {e}")
        
        if not ids:
            print("[!] No IDs found to test")
            print("[*] Try providing a URL with IDs like:")
            print("    https://target.com/user/123/profile")
            return []
        
        print(f"[*] Found {len(ids)} IDs to test")
        
        # Test each ID
        print("[*] Testing for IDOR vulnerabilities...")
        
        for id_info in ids:
            if len(id_info) >= 2:
                id_value = id_info[-1]
                id_type = id_info[0]
                
                if not self.quiet:
                    print(f"[*] Testing ID: {id_value} (type: {id_type})")
                
                # Generate variations
                variations = self.generate_variations(id_value)
                
                # Test each variation
                for test_id in variations[:3]:  # Test first 3
                    result = self.test_idor(self.target, id_value, test_id, id_type)
                    
                    if result:
                        print(f"[!] POTENTIAL IDOR FOUND!")
                        print(f"    Original: {result['original_url']}")
                        print(f"    Test: {result['test_url']}")
                        print(f"    Severity: {result['severity']}")
                        print()
                        
                        self.findings.append(result)
        
        # Summary
        print("=" * 60)
        
        if self.findings:
            print(f"[!] Found {len(self.findings)} potential IDOR vulnerabilities")
        else:
            print("[*] No IDOR vulnerabilities found")
            print("[*] Note: IDOR often requires manual testing with valid credentials")
        
        # Save results
        if self.output and self.findings:
            with open(self.output, 'w') as f:
                f.write(f"# IDOR Scan Results for {self.target}\n\n")
                for finding in self.findings:
                    f.write(f"Original URL: {finding['original_url']}\n")
                    f.write(f"Test URL: {finding['test_url']}\n")
                    f.write(f"Severity: {finding['severity']}\n\n")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger IDOR - Insecure Direct Object Reference scanner for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL with ID parameter")
    parser.add_argument("-c", "--cookie", help="Cookies (name=value;name=value)")
    parser.add_argument("-a", "--auth", help="Basic auth (username:password)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout")
    
    args = parser.parse_args()
    
    # Parse auth if provided
    auth = None
    if args.auth and ':' in args.auth:
        username, password = args.auth.split(':', 1)
        auth = (username, password)
    
    scanner = RogerIDOR(
        target=args.target,
        cookie=args.cookie,
        auth=auth,
        threads=args.threads,
        quiet=args.quiet,
        output=args.output,
        timeout=args.timeout
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()