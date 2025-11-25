"""
File utility functions.
Handles file operations, type detection, and pattern matching.
"""

import os
import hashlib
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from .logger import get_logger

logger = get_logger(__name__)


def get_file_extension(filename: str) -> str:
    """
    Get file extension from filename.
    
    Args:
        filename: File name or path
        
    Returns:
        File extension (lowercase, without dot)
    """
    ext = Path(filename).suffix.lower()
    return ext[1:] if ext else ""


def is_executable_extension(filename: str) -> bool:
    """
    Check if file has an executable extension.
    
    Args:
        filename: File name or path
        
    Returns:
        True if executable extension
    """
    executable_exts = {
        'exe', 'dll', 'so', 'dylib', 'bin', 'app',
        'sh', 'bat', 'cmd', 'ps1', 'vbs',
        'jar', 'class', 'apk', 'deb', 'rpm',
        'msi', 'dmg', 'pkg'
    }
    
    ext = get_file_extension(filename)
    return ext in executable_exts


def is_script_extension(filename: str) -> bool:
    """
    Check if file has a script extension.
    
    Args:
        filename: File name or path
        
    Returns:
        True if script extension
    """
    script_exts = {
        'py', 'js', 'ts', 'jsx', 'tsx', 'rb', 'php',
        'pl', 'sh', 'bash', 'zsh', 'lua', 'r',
        'ps1', 'bat', 'cmd', 'vbs'
    }
    
    ext = get_file_extension(filename)
    return ext in script_exts


def is_model_file(filename: str) -> bool:
    """
    Check if file is a model file.
    
    Args:
        filename: File name or path
        
    Returns:
        True if model file
    """
    model_exts = {
        'bin', 'pt', 'pth', 'ckpt', 'h5', 'pb',
        'onnx', 'tflite', 'safetensors', 'msgpack',
        'pkl', 'pickle', 'joblib', 'npz'
    }
    
    ext = get_file_extension(filename)
    return ext in model_exts


def is_suspicious_filename(filename: str) -> bool:
    """
    Check if filename matches suspicious patterns.
    
    Args:
        filename: File name or path
        
    Returns:
        True if filename is suspicious
    """
    suspicious_patterns = [
        r'\.\./',  # Path traversal
        r'__pycache__',
        r'\.git/',
        r'\.env',
        r'\.secret',
        r'\.password',
        r'\.key',
        r'\.token',
        r'id_rsa',
        r'\.ssh/',
        r'exploit',
        r'malware',
        r'backdoor',
        r'rootkit',
        r'keylog',
        r'trojan',
        r'virus',
    ]
    
    filename_lower = filename.lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, filename_lower):
            return True
    
    return False


def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """
    Calculate hash of a file.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hex digest of file hash or None on error
    """
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return None


def match_patterns(text: str, patterns: List[str]) -> List[str]:
    """
    Match text against a list of regex patterns.
    
    Args:
        text: Text to search
        patterns: List of regex patterns
        
    Returns:
        List of matched patterns
    """
    matches = []
    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{pattern}': {e}")
    
    return matches


def get_file_size_mb(filename: str) -> float:
    """
    Get file size in megabytes (for display purposes).
    
    Args:
        filename: File name
        
    Returns:
        Size in MB (returns 0 for remote files)
    """
    # This is a placeholder - for remote files we'd need to check headers
    # For now, return 0 to indicate unknown
    return 0.0


def categorize_files(files: List[str]) -> Dict[str, List[str]]:
    """
    Categorize files by type.
    
    Args:
        files: List of file paths
        
    Returns:
        Dictionary mapping categories to file lists
    """
    categories = {
        'model_files': [],
        'config_files': [],
        'code_files': [],
        'data_files': [],
        'documentation': [],
        'executables': [],
        'other': []
    }
    
    for file in files:
        ext = get_file_extension(file)
        
        if is_model_file(file):
            categories['model_files'].append(file)
        elif ext in ['json', 'yaml', 'yml', 'toml', 'cfg', 'ini', 'xml']:
            categories['config_files'].append(file)
        elif is_script_extension(file) or ext in ['ipynb', 'c', 'cpp', 'h', 'java']:
            categories['code_files'].append(file)
        elif ext in ['csv', 'tsv', 'parquet', 'arrow', 'txt', 'jsonl']:
            categories['data_files'].append(file)
        elif ext in ['md', 'rst', 'pdf', 'html']:
            categories['documentation'].append(file)
        elif is_executable_extension(file):
            categories['executables'].append(file)
        else:
            categories['other'].append(file)
    
    return categories
