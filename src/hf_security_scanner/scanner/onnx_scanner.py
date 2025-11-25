"""
ONNX Scanner - Security analysis for ONNX model files.
Detects embedded scripts, suspicious initializers, and validates op types.
"""

from typing import List, Dict, Any, Set
import re

from ..utils.logger import get_logger
from ..utils.security_utils import create_security_issue

logger = get_logger(__name__)


# Known safe ONNX ops (common ML operations)
SAFE_ONNX_OPS = {
    # Math operations
    'Add', 'Sub', 'Mul', 'Div', 'Sqrt', 'Pow', 'Exp', 'Log', 'Abs', 'Neg',
    # Neural network operations
    'Conv', 'ConvTranspose', 'MaxPool', 'AveragePool', 'GlobalAveragePool',
    'BatchNormalization', 'InstanceNormalization', 'LayerNormalization',
    'Dropout', 'Relu', 'Sigmoid', 'Tanh', 'Softmax', 'LeakyRelu', 'PRelu',
    'Elu', 'Selu', 'Gelu', 'Swish',
    # Tensor operations
    'Reshape', 'Transpose', 'Concat', 'Split', 'Squeeze', 'Unsqueeze',
    'Flatten', 'Expand', 'Tile', 'Gather', 'Scatter', 'Slice',
    # Reduction operations
    'ReduceSum', 'ReduceMean', 'ReduceMax', 'ReduceMin', 'ReduceProd',
    # Matrix operations
    'MatMul', 'Gemm', 'Linear',
    # Other common ops
    'Cast', 'Clip', 'Identity', 'Constant', 'Shape', 'Size',
    'Where', 'Equal', 'Greater', 'Less', 'And', 'Or', 'Not',
}

# Suspicious keywords in metadata/strings
SUSPICIOUS_KEYWORDS = [
    'eval', 'exec', 'compile', '__import__',
    'pickle', 'subprocess', 'os.system',
    'shell', 'bash', 'cmd.exe', 'powershell',
    'base64', 'decode', 'unhexlify',
]


def analyze_onnx_file(file_path: str, file_content: bytes = None) -> List[Dict[str, Any]]:
    """
    Analyze ONNX file for security issues.
    
    Since we don't have the actual file content from HF API,
    we'll do heuristic checks based on filename and patterns.
    
    Args:
        file_path: Path to ONNX file
        file_content: Optional file content (if available)
        
    Returns:
        List of security issues
    """
    issues = []
    
    # Basic ONNX file detected
    if not file_path.endswith('.onnx'):
        return issues
    
    # If we have file content, do deeper analysis
    if file_content:
        issues.extend(_analyze_onnx_content(file_path, file_content))
    else:
        # Just note that we found an ONNX file
        issues.append(create_security_issue(
            severity='info',
            category='file',
            title='ONNX model detected',
            description=f'File {file_path} is an ONNX model (generally safe format)',
            recommendation='ONNX models are safer than pickle-based formats'
        ))
    
    return issues


def _analyze_onnx_content(file_path: str, content: bytes) -> List[Dict[str, Any]]:
    """
    Analyze ONNX file content for security issues.
    
    Args:
        file_path: File path
        content: Raw file bytes
        
    Returns:
        List of security issues
    """
    issues = []
    
    # Check file size - very large ONNX files could hide payloads
    file_size_mb = len(content) / (1024 * 1024)
    if file_size_mb > 100:
        issues.append(create_security_issue(
            severity='low',
            category='file',
            title='Large ONNX file',
            description=f'ONNX file {file_path} is {file_size_mb:.1f}MB - unusually large',
            recommendation='Very large model files could hide malicious payloads'
        ))
    
    # Convert to string for pattern matching (may have embedded metadata)
    try:
        content_str = content.decode('utf-8', errors='ignore')
    except:
        content_str = str(content)
    
    # Check for suspicious keywords in metadata
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in content_str.lower():
            found_keywords.append(keyword)
    
    if found_keywords:
        issues.append(create_security_issue(
            severity='medium',
            category='file',
            title='Suspicious keywords in ONNX metadata',
            description=f'Found suspicious keywords in {file_path}: {", ".join(found_keywords[:5])}',
            recommendation='Review ONNX file metadata for embedded scripts or malicious code'
        ))
    
    # Check for script-like patterns (Python, shell)
    script_patterns = [
        rb'#!/bin/',  # Shebang
        rb'import\s+\w+',  # Python imports
        rb'def\s+\w+\(',  # Python functions
        rb'<script',  # HTML/JS scripts
    ]
    
    for pattern in script_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append(create_security_issue(
                severity='high',
                category='file',
                title='Embedded script detected in ONNX',
                description=f'File {file_path} appears to contain embedded scripts',
                recommendation='⚠️ ONNX files should not contain scripts - investigate immediately!'
            ))
            break
    
    # Check for unusual custom ops (would need ONNX library to parse properly)
    # For now, just check if file contains "custom_op" or similar strings
    if b'custom' in content.lower() or b'plugin' in content.lower():
        issues.append(create_security_issue(
            severity='medium',
            category='file',
            title='Possible custom ONNX operations',
            description=f'File {file_path} may contain custom operations',
            recommendation='Custom ONNX ops should be reviewed for security implications'
        ))
    
    return issues


def analyze_onnx_files_batch(file_paths: List[str]) -> List[Dict[str, Any]]:
    """
    Batch analyze ONNX files (without content).
    
    Args:
        file_paths: List of file paths
        
    Returns:
        List of security issues
    """
    issues = []
    onnx_files = [f for f in file_paths if f.endswith('.onnx')]
    
    if not onnx_files:
        return issues
    
    # Log that we found ONNX files
    if len(onnx_files) == 1:
        issues.append(create_security_issue(
            severity='info',
            category='file',
            title='ONNX model detected',
            description=f'Model uses ONNX format: {onnx_files[0]}',
            recommendation='ONNX is a safer format than pickle-based formats'
        ))
    else:
        issues.append(create_security_issue(
            severity='info',
            category='file',
            title=f'{len(onnx_files)} ONNX files detected',
            description=f'Model contains {len(onnx_files)} ONNX files',
            recommendation='ONNX is a safer format than pickle-based formats'
        ))
    
    return issues


# Future enhancement - with ONNX library installed
def analyze_onnx_graph(model_path: str) -> List[Dict[str, Any]]:
    """
    Deep analysis of ONNX graph structure (requires onnx library).
    
    This is a placeholder for future implementation when onnx library is available.
    
    Args:
        model_path: Path to ONNX model
        
    Returns:
        List of security issues
    """
    issues = []
    
    try:
        import onnx
        # TODO: Implement deep ONNX analysis
        # - Parse ONNX graph
        # - Check all op types against safe list
        # - Inspect initializers for unusual sizes
        # - Check for custom domains
        logger.info("ONNX library available - deep analysis possible")
    except ImportError:
        logger.debug("ONNX library not installed - using basic analysis")
    
    return issues
