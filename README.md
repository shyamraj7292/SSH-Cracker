# SSH-Cracker

An educational SSH brute-force tool project that demonstrates SSH security vulnerabilities, brute-force techniques, multi-threading, and password list attacks.

## ⚠️ Disclaimer

This tool is for **educational purposes only**. Unauthorized access to computer systems is illegal. Only use this tool on systems you own or have explicit written permission to test. The authors are not responsible for any misuse of this software.

## Project Overview

This project consists of two Python scripts:

1. **`ssh_brute.py`** – A simple SSH brute-forcing script that accepts a single username and a password list.
2. **`advance_ssh_brute.py`** – An advanced SSH brute-forcing script that supports username lists, password lists, password generation, multi-threading, and retry mechanisms.

## Features

### ssh_brute.py (Simple Version)
- Single username testing
- Password list support
- Sequential password testing
- Retry mechanism for failed connections
- Credential saving to file

### advance_ssh_brute.py (Advanced Version)
- Multiple username support (username lists)
- Multiple password support (password lists)
- Dynamic password generation:
  - Numeric passwords
  - Alphanumeric passwords
  - Pattern-based passwords
- Multi-threading for faster attacks
- Retry mechanism with configurable delays
- Progress tracking
- Credential saving to file

## Installation

1. Clone or download this repository
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### ssh_brute.py - Simple SSH Brute-Force Tool

Basic usage with a single username and password list:

```bash
python ssh_brute.py -H 192.168.1.100 -u admin -P passwords.txt
```

**Options:**
- `-H, --host`: Target SSH hostname or IP address (required)
- `-u, --username`: SSH username to test (required)
- `-P, --passwords`: Path to password list file (required)
- `-p, --port`: SSH port (default: 22)
- `-t, --timeout`: Connection timeout in seconds (default: 10)
- `-r, --retries`: Maximum retry attempts (default: 3)
- `-d, --delay`: Retry delay in seconds (default: 2)
- `-o, --output`: Output file for found credentials (default: found_credentials.txt)

**Example:**
```bash
python ssh_brute.py -H example.com -u root -P wordlist.txt -p 2222 -o results.txt
```

### advance_ssh_brute.py - Advanced SSH Brute-Force Tool

#### Using Username and Password Lists

```bash
python advance_ssh_brute.py -H 192.168.1.100 -U usernames.txt -P passwords.txt
```

#### Using Single Username with Password List

```bash
python advance_ssh_brute.py -H example.com -u admin -P wordlist.txt -T 10
```

#### Generating Numeric Passwords

Generate 4-digit numeric passwords (0000-9999):

```bash
python advance_ssh_brute.py -H 192.168.1.100 -u root --numeric --numeric-length 4
```

Generate numeric passwords with range:

```bash
python advance_ssh_brute.py -H 192.168.1.100 -u admin --numeric --numeric-length 4 --numeric-start 1000 --numeric-end 9999
```

#### Generating Alphanumeric Passwords

```bash
python advance_ssh_brute.py -H 192.168.1.100 -U users.txt --alphanumeric --alphanumeric-length 3
```

#### Using Pattern-Based Password Generation

```bash
python advance_ssh_brute.py -H 192.168.1.100 -u admin --pattern "pass%d%d"
```

**Options:**
- `-H, --host`: Target SSH hostname or IP address (required)
- `-u, --username`: Single username to test (mutually exclusive with `-U`)
- `-U, --usernames`: Path to username list file (mutually exclusive with `-u`)
- `-P, --passwords`: Path to password list file
- `-p, --port`: SSH port (default: 22)
- `-t, --timeout`: Connection timeout in seconds (default: 10)
- `-r, --retries`: Maximum retry attempts (default: 3)
- `-d, --delay`: Retry delay in seconds (default: 2)
- `-T, --threads`: Number of threads to use (default: 5)
- `-o, --output`: Output file for found credentials (default: found_credentials.txt)

**Password Generation Options:**
- `--numeric`: Generate numeric passwords
- `--numeric-length`: Length of numeric passwords (default: 4)
- `--numeric-start`: Starting number (default: 0)
- `--numeric-end`: Ending number (default: unlimited)
- `--numeric-limit`: Limit number of numeric passwords (default: 10000)
- `--alphanumeric`: Generate alphanumeric passwords
- `--alphanumeric-length`: Length of alphanumeric passwords (default: 4)
- `--alphanumeric-limit`: Limit number of alphanumeric passwords (default: 1000)
- `--pattern`: Generate passwords from pattern (e.g., "pass%d%d")
- `--pattern-limit`: Limit number of pattern passwords (default: 10000)

## File Format

### Username List Format
Create a text file with one username per line:
```
admin
root
user
test
```

### Password List Format
Create a text file with one password per line:
```
password
123456
admin
root
letmein
```

## How It Works

1. **User Input**: The script accepts inputs such as hostname, username(s), password(s), and optional parameters like password generation settings.

2. **Connection Attempt**: The tool uses the `paramiko` library to connect to the SSH server with the given credentials.

3. **Authentication Handling**: If authentication fails, it moves to the next combination. If successful, it stores the credentials.

4. **Retry Mechanism**: In case of SSH errors or rate limits, the tool implements retry logic with configurable delays.

5. **Multi-threading (Advanced Version)**: The `advance_ssh_brute.py` script uses multiple threads to speed up brute-force attempts by testing multiple combinations simultaneously.

## Key Concepts Covered

- Understanding SSH authentication and security vulnerabilities
- Implementing brute-force and dictionary attacks
- Using Python libraries (paramiko, argparse, queue, threading)
- Handling network timeouts and authentication errors
- Optimizing performance with multi-threading
- Password generation techniques
- Retry mechanisms and error handling

## Output

When valid credentials are found, they are:
1. Displayed on the console
2. Saved to the output file (default: `found_credentials.txt`) in the format:
   ```
   username:password
   ```

## Security Notes

- **Always use strong passwords** to protect your SSH servers
- **Disable password authentication** and use SSH keys instead when possible
- **Implement rate limiting** and fail2ban to prevent brute-force attacks
- **Use non-standard SSH ports** to reduce automated attacks
- **Monitor SSH logs** for suspicious activity

## Troubleshooting

### Connection Timeouts
- Increase the timeout value with `-t` option
- Check if the host is reachable
- Verify the SSH port is correct

### Rate Limiting
- Reduce the number of threads with `-T` option
- Increase delays between attempts
- The tool automatically retries on connection errors

### Authentication Errors
- Verify username and password list formats
- Check if the SSH server allows password authentication
- Ensure the target system is accessible

## License

This project is for educational purposes only. Use responsibly and only on systems you own or have permission to test.

## Contributing

This is an educational project. Feel free to study the code and learn from it, but remember to use it ethically and legally.
