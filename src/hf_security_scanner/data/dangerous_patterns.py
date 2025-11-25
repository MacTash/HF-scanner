"""Dangerous keywords and code patterns."""

# Dangerous function calls and imports
DANGEROUS_KEYWORDS = [
    # System execution
    "eval(", "exec(", "compile(", "__import__",
    "os.system", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "commands.getoutput",
    
    # File operations
    "os.remove", "os.rmdir", "shutil.rmtree",
    "os.chmod", "os.chown",
    
    # Network operations
    "socket.socket", "urllib.request", "requests.get",
    "requests.post", "http.client",
    
    # Pickle (unsafe deserialization)
    "pickle.loads", "pickle.load", "cPickle.loads",
    "_pickle.loads",
    
    # Code generation/modification
    "ctypes", "cffi", "ctypes.CDLL",
    
    # Environment manipulation
    "os.environ", "putenv", "setenv",
]

# Suspicious patterns in code
SUSPICIOUS_CODE_PATTERNS = [
    r"base64\.b64decode",  # Encoded payloads
    r"__import__\s*\(['\"]os['\"]",  # Dynamic OS import
    r"exec\s*\(",  # Code execution
    r"eval\s*\(",  # Expression evaluation
    r"\.decode\s*\(['\"]hex['\"]",  # Hex decoding
    r"\.decode\s*\(['\"]base64['\"]",  # Base64 decoding
    r"\\x[0-9a-fA-F]{2}",  # Hex escape sequences (shellcode)
    r"subprocess\.Popen.*shell\s*=\s*True",  # Shell injection risk
    r"os\.system",  # System command execution
    r"__builtins__",  # Builtins manipulation
]

# Cryptocurrency mining indicators
CRYPTO_MINING_INDICATORS = [
    "xmrig", "cryptonight", "monero", "stratum",
    "mining pool", "hashrate", "nonce",
]

# Data exfiltration patterns
DATA_EXFILTRATION_PATTERNS = [
    r"requests\.post.*json\s*=",  # Posting data
    r"urllib.*urlopen.*POST",
    r"socket\.send",
    r"smtp\.sendmail",
]

# Obfuscation indicators
OBFUSCATION_INDICATORS = [
    "base64", "rot13", "caesar",
    "\\x", "\\u00", "chr(", "ord(",
    "hex(", "unhexlify",
]
