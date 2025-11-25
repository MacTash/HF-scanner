"""
File Analyzer - Scans model files for suspicious patterns and malicious content.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..utils.logger import get_logger
from ..utils.file_utils import (
    get_file_extension,
    is_executable_extension,
    is_script_extension,
    is_suspicious_filename,
    categorize_files,
)
from ..utils.security_utils import create_security_issue
from ..data import (
    SUSPICIOUS_EXTENSIONS,
    CODE_EXECUTION_EXTENSIONS,
    MALICIOUS_FILENAME_PATTERNS,
    SUSPICIOUS_FILENAMES,
    EXTENSION_RISK_LEVELS,
)

logger = get_logger(__name__)


@dataclass
class FileAnalysisResult:
    """Result of file analysis."""
    total_files: int
    suspicious_files: List[Dict[str, Any]]
    file_categories: Dict[str, List[str]]
    security_issues: List[Dict[str, Any]]
    risk_score: float


class FileAnalyzer:
    """Analyzes model files for security threats."""
    
    def __init__(self):
        """Initialize the file analyzer."""
        self.suspicious_extensions = set(SUSPICIOUS_EXTENSIONS)
        self.code_extensions = set(CODE_EXECUTION_EXTENSIONS)
        logger.debug("FileAnalyzer initialized")
    
    def analyze_files(self, files: List[str]) -> FileAnalysisResult:
        """
        Analyze a list of files for security issues.
        
        Args:
            files: List of file paths from model repository
            
        Returns:
            FileAnalysisResult with analysis details
        """
        logger.info(f"Analyzing {len(files)} files")
        
        suspicious_files = []
        security_issues = []
        
        # Categorize files
        file_categories = categorize_files(files)
        
        # Analyze each file
        for file_path in files:
            file_issues = self._analyze_single_file(file_path)
            if file_issues:
                suspicious_files.append({
                    "path": file_path,
                    "issues": file_issues
                })
                security_issues.extend(file_issues)
        
        # Calculate risk score
        risk_score = self._calculate_file_risk_score(security_issues, file_categories)
        
        # Add category-based issues
        category_issues = self._analyze_file_categories(file_categories)
        security_issues.extend(category_issues)
        
        result = FileAnalysisResult(
            total_files=len(files),
            suspicious_files=suspicious_files,
            file_categories=file_categories,
            security_issues=security_issues,
            risk_score=risk_score
        )
        
        logger.info(f"File analysis complete: {len(suspicious_files)} suspicious files, "
                   f"risk score: {risk_score}")
        
        return result
    
    def _analyze_single_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze a single file for security issues.
        
        Args:
            file_path: Path to file
            
        Returns:
            List of security issues found
        """
        from ..utils.model_format import detect_model_format, is_safe_model_format
        
        issues = []
        ext = get_file_extension(file_path)
        filename_lower = file_path.lower()
        
        # Smart binary file classification
        if ext in ['bin', 'pt', 'pth', 'onnx', 'pkl', 'pickle', 'safetensors', 'pb']:
            format_info = detect_model_format(file_path)
            
            if format_info['format'] == 'safetensors':
                # SafeTensors is safe, just log it
                issues.append(create_security_issue(
                    severity="info",
                    category="file",
                    title=f"SafeTensors model detected",
                    description=f"File '{file_path}' uses SafeTensors format (safe)",
                    recommendation="SafeTensors files cannot execute code - this is good!"
                ))
            elif format_info['format'] == 'onnx':
                # ONNX is safe
                issues.append(create_security_issue(
                    severity="info",
                    category="file",
                    title=f"ONNX model detected",
                    description=f"File '{file_path}' is an ONNX model (safe inference format)",
                    recommendation="ONNX models are safe for inference"
                ))
            elif format_info['format'] == 'pytorch':
                # PyTorch models use pickle - low risk for .bin, medium for .pt/.pth
                if ext == 'bin':
                    severity = "low"
                    desc = f"File '{file_path}' is a PyTorch model shard (uses pickle internally)"
                    rec = "PyTorch .bin files from trusted sources are generally safe, but can execute code when loaded"
                else:
                    severity = "low"
                    desc = f"File '{file_path}' is a PyTorch model (uses pickle internally)"
                    rec = "PyTorch models from trusted sources are generally safe, but can execute code when loaded"
                
                issues.append(create_security_issue(
                    severity=severity,
                    category="file",
                    title=f"PyTorch model file: {ext}",
                    description=desc,
                    recommendation=rec
                ))
            elif format_info['format'] == 'pytorch_file':
                # Standalone .pt/.pth files - medium risk
                issues.append(create_security_issue(
                    severity="medium",
                    category="file",
                    title=f"PyTorch checkpoint file: {ext}",
                    description=f"File '{file_path}' is a PyTorch checkpoint using pickle (RCE risk)",
                    recommendation="⚠️ PyTorch checkpoints can execute arbitrary code - verify source before loading!"
                ))
            elif format_info['format'] == 'pickle':
                # Standalone pickle - CRITICAL risk
                issues.append(create_security_issue(
                    severity="critical",
                    category="file",
                    title=f"🚨 Raw pickle file detected: {ext}",
                    description=f"File '{file_path}' is a raw pickle file with CRITICAL arbitrary code execution risk",
                    recommendation="🚨 DANGER: Pickle files can execute malicious code! Only load from absolutely trusted sources. Consider using SafeTensors instead."
                ))
            elif format_info['format'] == 'unknown':
                # Unknown binary - high risk
                issues.append(create_security_issue(
                    severity="high",
                    category="file",
                    title=f"Unknown binary file: {ext}",
                    description=f"File '{file_path}' is an unknown binary format",
                    recommendation="Verify the purpose and contents of this file"
                ))
        
        # Check for other executable files
        elif is_executable_extension(file_path):
            severity = EXTENSION_RISK_LEVELS.get(ext, "high")
            issues.append(create_security_issue(
                severity=severity,
                category="file",
                title=f"Executable file detected: {ext}",
                description=f"File '{file_path}' has executable extension '.{ext}'",
                recommendation="Review why an executable is included in the model repository"
            ))
        
        # Check for suspicious filenames
        if is_suspicious_filename(file_path):
            issues.append(create_security_issue(
                severity="high",
                category="file",
                title="Suspicious filename pattern",
                description=f"File '{file_path}' matches suspicious pattern",
                recommendation="Investigate the purpose of this file"
            ))
        
        # Check for sensitive files
        for sensitive_name in SUSPICIOUS_FILENAMES:
            if sensitive_name in filename_lower:
                issues.append(create_security_issue(
                    severity="critical",
                    category="file",
                    title="Potential sensitive file",
                    description=f"File '{file_path}' may contain sensitive information",
                    recommendation="Verify this file doesn't contain credentials or secrets"
                ))
                break
        
        # Check for script files (lower severity, but should be reviewed)
        if is_script_extension(file_path) and ext in self.code_extensions:
            issues.append(create_security_issue(
                severity="low",
                category="file",
                title=f"Code file detected: {ext}",
                description=f"File '{file_path}' contains executable code",
                recommendation="Review code before execution"
            ))
        
        return issues
    
    def _analyze_file_categories(self, categories: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """
        Analyze file categories for suspicious patterns.
        
        Args:
            categories: Dictionary of categorized files
            
        Returns:
            List of security issues
        """
        issues = []
        
        # Flag if there are executables
        if categories.get('executables'):
            issues.append(create_security_issue(
                severity="high",
                category="file",
                title="Executable files in repository",
                description=f"Found {len(categories['executables'])} executable file(s)",
                recommendation="Executables should not be included in model repositories",
                details={"files": categories['executables'][:5]}  # Limit to first 5
            ))
        
        # Check for unusual ratio of code files
        total_files = sum(len(files) for files in categories.values())
        code_files = len(categories.get('code_files', []))
        
        if total_files > 0 and code_files / total_files > 0.5:
            issues.append(create_security_issue(
                severity="medium",
                category="file",
                title="High proportion of code files",
                description=f"Repository contains {code_files}/{total_files} code files",
                recommendation="Verify the purpose of code files in a model repository"
            ))
        
        # Warn if no model files found
        if not categories.get('model_files'):
            issues.append(create_security_issue(
                severity="medium",
                category="file",
                title="No model files detected",
                description="Repository doesn't appear to contain standard model files",
                recommendation="Verify this is actually a model repository"
            ))
        
        return issues
    
    def _calculate_file_risk_score(
        self,
        security_issues: List[Dict[str, Any]],
        categories: Dict[str, List[str]]
    ) -> float:
        """
        Calculate risk score based on file analysis.
        
        Args:
            security_issues: List of security issues
            categories: File categories
            
        Returns:
            Risk score (0-10)
        """
        score = 0.0
        
        # Base score on security issues
        severity_weights = {
            "critical": 3.0,
            "high": 2.0,
            "medium": 1.0,
            "low": 0.3
        }
        
        for issue in security_issues:
            severity = issue.get("severity", "low")
            score += severity_weights.get(severity, 0.5)
        
        # Add score for executables
        if categories.get('executables'):
            score += len(categories['executables']) * 2.0
        
        # Cap at 10.0
        return min(10.0, round(score, 2))
