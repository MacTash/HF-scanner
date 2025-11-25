"""
Code Analyzer - Static analysis for Python files.
Basic pattern matching with future Bandit integration.
"""

from typing import List, Dict, Any, Set
import re

from ..utils.logger import get_logger
from ..utils.security_utils import create_security_issue

logger = get_logger(__name__)


# Unsafe patterns to detect in Python code
UNSAFE_PATTERNS = {
    'pickle_load': {
        'patterns': [r'pickle\.load', r'pickle\.Unpickler', r'joblib\.load', r'dill\.load'],
        'severity': 'high',
        'title': 'Unsafe deserialization',
        'description': 'pickle.load() can execute arbitrary code'
    },
    'eval_exec': {
        'patterns': [r'\beval\(', r'\bexec\(', r'\bcompile\(', r'execfile\('],
        'severity': 'critical',
        'title': 'Code execution',
        'description': 'eval()/exec()/compile() can execute arbitrary code'
    },
    'dangerous_imports': {
        'patterns': [r'__import__\(', r'importlib\.import_module', r'from\s+ctypes\s+import'],
        'severity': 'high',
        'title': 'Dynamic imports',
        'description': 'Dynamic imports can load malicious code'
    },
    'os_system': {
        'patterns': [r'os\.system', r'subprocess\.call', r'subprocess\.run', r'subprocess\.Popen', 
                     r'os\.popen', r'commands\.', r'os\.spawn'],
        'severity': 'high',
        'title': 'Shell command execution',
        'description': 'System command execution can be exploited'
    },
    'file_operations': {
        'patterns': [r'open\([^)]*[\'"]w[\'"]', r'open\([^)]*[\'"]a[\'"]', r'shutil\.rmtree',
                     r'os\.remove', r'os\.unlink', r'pathlib\.Path\([^)]*\)\.unlink'],
        'severity': 'medium',
        'title': 'File system modifications',
        'description': 'File write/delete operations detected'
    },
    'network_operations': {
        'patterns': [r'urllib\.request', r'requests\.get', r'requests\.post', 
                     r'socket\.socket', r'http\.client', r'urllib3\.'],
        'severity': 'medium',
        'title': 'Network operations',
        'description': 'Network requests detected - potential data exfiltration'
    },
    'torch_load': {
        'patterns': [r'torch\.load'],
        'severity': 'medium',
        'title': 'PyTorch unsafe load',
        'description': 'torch.load() uses pickle internally - potential RCE'
    },
    'reduce_setstate': {
        'patterns': [r'def __reduce__', r'def __setstate__', r'def __reduce_ex__'],
        'severity': 'high',
        'title': 'Custom pickle behavior',
        'description': 'Custom __reduce__/__setstate__ can execute code during unpickling'
    },
    'base64_encoding': {
        'patterns': [r'base64\.b64decode', r'base64\.decode'],
        'severity': 'low',
        'title': 'Base64 decoding',
        'description': 'Base64 decoding may indicate obfuscation'
    },
}


def analyze_python_code(code: str, filename: str) -> List[Dict[str, Any]]:
    """
    Analyze Python code for unsafe patterns.
    
    Args:
        code: Python source code
        filename: File name for reference
        
    Returns:
        List of security issues found
    """
    issues = []
    
    for pattern_name, pattern_info in UNSAFE_PATTERNS.items():
        for pattern in pattern_info['patterns']:
            matches = re.finditer(pattern, code)
            match_list = list(matches)
            
            if match_list:
                # Get line numbers
                lines = []
                for match in match_list[:3]:  # Limit to first 3 matches
                    line_num = code[:match.start()].count('\n') + 1
                    lines.append(line_num)
                
                issues.append(create_security_issue(
                    severity=pattern_info['severity'],
                    category='code',
                    title=f"{pattern_info['title']} in {filename}",
                    description=f"{pattern_info['description']} (found at lines: {', '.join(map(str, lines))})",
                    recommendation=f"Review code at lines {', '.join(map(str, lines))} for security implications",
                    details={'pattern': pattern_name, 'matches': len(match_list), 'lines': lines}
                ))
                break  # Only report once per pattern type
    
    return issues


def analyze_python_file_list(files: List[str]) -> List[Dict[str, Any]]:
    """
    Analyze a list of Python files (file paths only, no content).
    Creates warnings for .py files that should be reviewed.
    
    Args:
        files: List of file paths
        
    Returns:
        List of security issues
    """
    issues = []
    python_files = [f for f in files if f.endswith('.py')]
    
    if not python_files:
        return issues
    
    # Create issue for each Python file found
    if len(python_files) <= 5:
        for py_file in python_files:
            issues.append(create_security_issue(
                severity='low',
                category='code',
                title=f'Python code detected',
                description=f'File {py_file} contains Python code that should be reviewed',
                recommendation='Review Python files for unsafe patterns (pickle.load, eval, exec, os.system)'
            ))
    else:
        # Too many files, create summary issue
        issues.append(create_security_issue(
            severity='medium',
            category='code',
            title=f'{len(python_files)} Python files detected',
            description=f'Repository contains {len(python_files)} Python files that should be reviewed',
            recommendation='Review all Python files for unsafe patterns before executing'
        ))
    
    return issues


# Future enhancement: Bandit integration
def run_bandit_if_available(files: List[str]) -> List[Dict[str, Any]]:
    """
    Run Bandit security linter if available.
    
    Args:
        files: List of Python file paths
        
    Returns:
        List of security issues from Bandit
    """
    try:
        import bandit
        from bandit.core import manager as bandit_manager
        
        logger.info("Bandit is available, running security analysis...")
        # TODO: Implement Bandit integration
        # This would involve:
        # 1. Download Python files
        # 2. Run Bandit on them
        # 3. Parse results
        # 4. Convert to our security issue format
        
        return []
    except ImportError:
        logger.debug("Bandit not installed, using basic pattern matching")
        return []
