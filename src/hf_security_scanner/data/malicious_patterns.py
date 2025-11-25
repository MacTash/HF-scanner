"""Security patterns for malicious file detection."""

# Suspicious file extensions that should be flagged
SUSPICIOUS_EXTENSIONS = [
    "exe", "dll", "so", "dylib", "bin", "app",
    "sh", "bat", "cmd", "ps1", "vbs", "scr",
    "jar", "class", "apk", "deb", "rpm",
    "msi", "dmg", "pkg", "run", "com"
]

# Code execution extensions (medium risk)
CODE_EXECUTION_EXTENSIONS = [
    "py", "js", "ts", "rb", "php", "pl", "sh", "bash",
    "lua", "r", "ps1", "bat", "cmd", "vbs", "wsh"
]

# Archive extensions (check contents)
ARCHIVE_EXTENSIONS = [
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
    "tgz", "tbz2", "txz", "cab", "iso"
]

# Malicious filename patterns
MALICIOUS_FILENAME_PATTERNS = [
    r'\.\./',  # Path traversal
    r'exploit',
    r'malware',
    r'backdoor',
    r'rootkit',
    r'keylog',
    r'trojan',
    r'virus',
    r'ransomware',
    r'cryptominer',
    r'botnet',
    r'payload',
    r'shellcode',
]

# Suspicious filenames (exact matches, case-insensitive)
SUSPICIOUS_FILENAMES = [
    '.env',
    '.secret',
    '.password',
    '.token',
    'id_rsa',
    'id_dsa',
    'id_ecdsa',
    'id_ed25519',
    '.ssh/config',
    'shadow',
    'passwd',
    '.aws/credentials',
    '.npmrc',
    '.pypirc',
]

# Known malicious file hashes (SHA256) - examples
KNOWN_MALICIOUS_HASHES = {
    # Add known malicious hashes here
    # "hash": "description"
}

# Risk levels for different extensions
EXTENSION_RISK_LEVELS = {
    "exe": "critical",
    "dll": "critical",
    "so": "high",
    "dylib": "high",
    "scr": "critical",
    "bat": "medium",
    "sh": "medium",
    "ps1": "medium",
    "py": "low",
    "js": "low",
    "vbs": "high",
    "jar": "medium",
}
