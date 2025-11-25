"""
Model format detection utilities.
Detects PyTorch, ONNX, SafeTensors, and other ML model formats.
"""

from typing import Optional, Dict, Any


# Magic numbers / file signatures for model formats
MODEL_SIGNATURES = {
    # PyTorch (starts with magic number)
    'pytorch': {
        'signatures': [
            b'PK\x03\x04',  # ZIP format (PyTorch uses ZIP)
            b'\x80\x02',     # Pickle protocol 2
            b'\x80\x03',     # Pickle protocol 3
            b'\x80\x04',     # Pickle protocol 4
        ],
        'extensions': ['.bin', '.pt', '.pth', '.ckpt'],
        'risk': 'medium',  # Pickle can be unsafe
        'description': 'PyTorch model file'
    },
    # ONNX
    'onnx': {
  'signatures': [
            b'\x08',  # ONNX protobuf starts with 0x08
        ],
        'extensions': ['.onnx'],
        'risk': 'low',
        'description': 'ONNX model (safe inference format)'
    },
    # SafeTensors
    'safetensors': {
        'signatures': [
            b'{\x00\x00\x00',  # JSON header for safetensors
        ],
        'extensions': ['.safetensors'],
        'risk': 'low',
        'description': 'SafeTensors (safe format, no code execution)'
    },
    # PyTorch (standalone files)
    'pytorch_file': {
        'signatures': [
            b'PK\x03\x04',  # ZIP format (PyTorch uses ZIP)
        ],
        'extensions': ['.pt', '.pth'],
        'risk': 'medium',  # PyTorch uses pickle but wrapped
        'description': 'PyTorch checkpoint file (uses pickle - potential RCE risk)'
    },
    # Pickle (standalone) - HIGHEST RISK
    'pickle': {
        'signatures': [
            b'\x80\x02',
            b'\x80\x03',
            b'\x80\x04',
            b'\x80\x05',
        ],
        'extensions': ['.pkl', '.pickle'],
        'risk': 'critical',  # Pickle is extremely unsafe
        'description': 'Raw pickle file (CRITICAL: arbitrary code execution risk!)'
    },
}


def detect_model_format(filename: str, file_header: bytes = None) -> Dict[str, Any]:
    """
    Detect ML model format from filename and optional file header.
    
    Args:
        filename: File name or path
        file_header: First few bytes of file (for signature matching)
        
    Returns:
        Dictionary with format info, risk level, and description
    """
    filename_lower = filename.lower()
    
    # Check by extension first
    for format_name, format_info in MODEL_SIGNATURES.items():
        for ext in format_info['extensions']:
            if filename_lower.endswith(ext):
                result = {
                    'format': format_name,
                    'risk': format_info['risk'],
                    'description': format_info['description'],
                    'detected_by': 'extension'
                }
                
                # If we have file header, verify signature
                if file_header and format_info['signatures']:
                    for sig in format_info['signatures']:
                        if file_header.startswith(sig):
                            result['signature_verified'] = True
                            break
                    else:
                        result['signature_verified'] = False
                        result['warning'] = 'Extension doesn\'t match file signature'
                
                return result
    
    # Unknown format
    return {
        'format': 'unknown',
        'risk': 'high',  # Unknown binaries are suspicious
        'description': 'Unknown binary format',
        'detected_by': 'unknown'
    }


def is_safe_model_format(filename: str) -> bool:
    """
    Quick check if a file is a known-safe model format.
    
    Args:
        filename: File name or path
        
    Returns:
        True if format is known to be safe
    """
    detection = detect_model_format(filename)
    return detection['risk'] == 'low'


def is_pytorch_model(filename: str) -> bool:
    """Check if file is a PyTorch model."""
    detection = detect_model_format(filename)
    return detection['format'] == 'pytorch'


def is_onnx_model(filename: str) -> bool:
    """Check if file is an ONNX model."""
    detection = detect_model_format(filename)
    return detection['format'] == 'onnx'


def is_safetensors_model(filename: str) -> bool:
    """Check if file is a SafeTensors model."""
    detection = detect_model_format(filename)
    return detection['format'] == 'safetensors'


def classify_binary_risk(filename: str) -> str:
    """
    Classify the risk level of a binary file.
    
    Args:
        filename: File name or path
        
    Returns:
        Risk level: 'low', 'medium', 'high', 'critical'
    """
    detection = detect_model_format(filename)
    
    # Map format risk to severity levels
    risk_map = {
        'low': 'low',
        'medium': 'medium',
        'high': 'high',
        'critical': 'critical'
    }
    
    return risk_map.get(detection['risk'], 'high')
