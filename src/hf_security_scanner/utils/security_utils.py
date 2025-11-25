"""
Security utility functions.
Provides common security checks and risk scoring.
"""

from typing import List, Dict, Any, Set
from .logger import get_logger

logger = get_logger(__name__)


class RiskLevel:
    """Risk level constants."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def calculate_risk_score(issues: List[Dict[str, Any]]) -> float:
    """
    Calculate overall risk score based on security issues.
    
    Args:
        issues: List of security issues with severity levels
        
    Returns:
        Risk score from 0.0 (low) to 10.0 (critical)
    """
    if not issues:
        return 0.0
    
    # Count issues by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for issue in issues:
        severity = issue.get("severity", "low").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Weighted scoring with diminishing returns
    # First issue of each severity has full weight, additional ones have reduced weight
    score = 0.0
    
    # Critical issues: 5 points for first, 2 for each additional
    if severity_counts["critical"] > 0:
        score += 5.0 + min(severity_counts["critical"] - 1, 5) * 1.0
    
    # High issues: 3 points for first, 1 for each additional  
    if severity_counts["high"] > 0:
        score += 3.0 + min(severity_counts["high"] - 1, 5) * 0.6
    
    # Medium issues: 1.5 points for first, 0.5 for each additional
    if severity_counts["medium"] > 0:
        score += 1.5 + min(severity_counts["medium"] - 1, 10) * 0.3
    
    # Low issues: 0.5 points for first, 0.2 for each additional
    if severity_counts["low"] > 0:
        score += 0.5 + min(severity_counts["low"] - 1, 10) * 0.15
    
    # Info issues: minimal impact
    if severity_counts["info"] > 0:
        score += min(severity_counts["info"] * 0.1, 0.5)
    
    # Cap at 10.0
    return min(round(score, 2), 10.0)


def get_risk_level(risk_score: float) -> str:
    """
    Convert numeric risk score to risk level.
    
    Args:
        risk_score: Numeric risk score (0-10)
        
    Returns:
        Risk level string
    """
    if risk_score >= 7.0:
        return RiskLevel.CRITICAL
    elif risk_score >= 4.0:
        return RiskLevel.HIGH
    elif risk_score >= 2.0:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


def create_security_issue(
    severity: str,
    category: str,
    title: str,
    description: str,
    recommendation: str = "",
    details: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Create a standardized security issue dictionary.
    
    Args:
        severity: Issue severity (critical, high, medium, low, info)
        category: Issue category (license, file, metadata, vulnerability)
        title: Issue title
        description: Detailed description
        recommendation: Recommended action
        details: Additional details
        
    Returns:
        Security issue dictionary
    """
    return {
        "severity": severity.lower(),
        "category": category,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "details": details or {}
    }


def check_dangerous_keywords(text: str, keywords: List[str]) -> List[str]:
    """
    Check text for dangerous keywords.
    
    Args:
        text: Text to check
        keywords: List of dangerous keywords
        
    Returns:
        List of matched keywords
    """
    if not text or not keywords:
        return []
    
    text_lower = text.lower()
    matches = []
    
    for keyword in keywords:
        if keyword.lower() in text_lower:
            matches.append(keyword)
    
    return matches


def analyze_permissions(tags: List[str]) -> Dict[str, Any]:
    """
    Analyze model tags for permission-related information.
    
    Args:
        tags: List of model tags
        
    Returns:
        Dictionary with permission analysis
    """
    risky_tags = {
        'code-generation', 'code-execution', 'shell',
        'system', 'admin', 'root', 'privilege'
    }
    
    found_risky = [tag for tag in tags if any(risky in tag.lower() for risky in risky_tags)]
    
    return {
        "has_risky_tags": bool(found_risky),
        "risky_tags": found_risky,
        "total_tags": len(tags)
    }


def generate_recommendations(issues: List[Dict[str, Any]]) -> List[str]:
    """
    Generate security recommendations based on issues found.
    
    Args:
        issues: List of security issues
        
    Returns:
        List of recommendations
    """
    recommendations = []
    issue_categories = set(issue.get("category") for issue in issues)
    
    if "license" in issue_categories:
        recommendations.append("Review license compliance before commercial use")
    
    if "file" in issue_categories:
        recommendations.append("Inspect suspicious files before running the model")
    
    if "metadata" in issue_categories:
        recommendations.append("Request additional security documentation from model author")
    
    if "vulnerability" in issue_categories:
        recommendations.append("Update dependencies to patched versions")
    
    # Check severity
    has_critical = any(issue.get("severity") == "critical" for issue in issues)
    if has_critical:
        recommendations.insert(0, "⚠️  CRITICAL ISSUES FOUND - Use extreme caution")
    
    if not recommendations:
        recommendations.append("✓ No major security concerns detected")
    
    return recommendations
