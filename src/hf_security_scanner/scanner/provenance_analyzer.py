"""
Provenance Analyzer - Calculates model and account trust scores.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from ..utils.logger import get_logger
from ..utils.security_utils import create_security_issue

logger = get_logger(__name__)


@dataclass
class ProvenanceScore:
    """Model provenance and trust assessment."""
    trust_score: float  # 0-100
    account_age_days: Optional[int]
    model_count: int
    total_downloads: int
    total_likes: int
    is_organization: bool
    is_verified: bool
    risk_factors: list
    trust_factors: list


def calculate_provenance_score(model_metadata: Dict[str, Any]) -> ProvenanceScore:
    """
    Calculate provenance/trust score for a model based on account metrics.
    
    Args:
        model_metadata: Model metadata dictionary
        
    Returns:
        ProvenanceScore with trust assessment
    """
    # Extract account information
    author = model_metadata.get('author', '')
    downloads = model_metadata.get('downloads', 0)
    likes = model_metadata.get('likes', 0)
    
    # Try to get account creation date (may not be available)
    created_at = model_metadata.get('created_at')
    account_age_days = None
    if created_at:
        try:
            if isinstance(created_at, str):
                created_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            else:
                created_date = created_at
            account_age_days = (datetime.now(created_date.tzinfo) - created_date).days
        except:
            pass
    
    # Organization check (simple heuristic: no "/" in author means org)
    is_organization = '/' not in author and author and not author.startswith('user')
    
    # For now, we can't verify badges, set to False
    is_verified = False
    
    # We only have data for this one model, so model_count = 1
    # In future, could query HF API for all models by author
    model_count = 1
    
    risk_factors = []
    trust_factors = []
    
    # Base score
    score = 50.0
    
    # Account age scoring (+5 per year, max 20)
    if account_age_days:
        years = account_age_days / 365.0
        age_bonus = min(years * 5, 20)
        score += age_bonus
        
        if account_age_days < 30:
            risk_factors.append("Very new account (<30 days)")
            score -= 15
        elif account_age_days < 90:
            risk_factors.append("New account (<90 days)")
            score -= 5
        elif years >= 2:
            trust_factors.append(f"Established account ({years:.1f} years)")
    
    # Downloads scoring (+1 per 10k, max 10)
    if downloads > 0:
        download_bonus = min((downloads / 10000) * 1, 10)
        score += download_bonus
        
        if downloads >= 100000:
            trust_factors.append(f"High download count ({downloads:,})")
        elif downloads < 10:
            risk_factors.append("Very low downloads")
            score -= 5
    else:
        risk_factors.append("Zero downloads")
        score -= 10
    
    # Likes scoring (+1 per 100, max 10)
    if likes > 0:
        likes_bonus = min((likes / 100) * 1, 10)
        score += likes_bonus
        
        if likes >= 500:
            trust_factors.append(f"High community engagement ({likes} likes)")
        elif likes < 2:
            risk_factors.append("Very low community engagement")
            score -= 5
    else:
        risk_factors.append("Zero likes")
        score -= 10
    
    # Organization bonus
    if is_organization:
        score += 10
        trust_factors.append("Organization account")
    
    # Verified bonus (placeholder for future)
    if is_verified:
        score += 10
        trust_factors.append("Verified account")
    
    # Check for suspicious patterns
    if downloads < 10 and likes < 2 and account_age_days and account_age_days < 90:
        risk_factors.append("⚠️ New account with minimal engagement")
        score -= 10
    
    # Clamp score to 0-100
    score = max(0, min(100, score))
    
    return ProvenanceScore(
        trust_score=round(score, 1),
        account_age_days=account_age_days,
        model_count=model_count,
        total_downloads=downloads,
        total_likes=likes,
        is_organization=is_organization,
        is_verified=is_verified,
        risk_factors=risk_factors,
        trust_factors=trust_factors
    )


def get_provenance_trust_level(score: float) -> str:
    """
    Convert trust score to trust level.
    
    Args:
        score: Trust score 0-100
        
    Returns:
        Trust level string
    """
    if score >= 80:
        return "high"
    elif score >= 60:
        return "medium-high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    else:
        return "very-low"


def get_provenance_issues(provenance: ProvenanceScore) -> list:
    """
    Generate security issues based on provenance assessment.
    
    Args:
        provenance: ProvenanceScore result
        
    Returns:
        List of security issues
    """
    issues = []
    
    if provenance.trust_score < 30:
        issues.append(create_security_issue(
            severity="high",
            category="provenance",
            title="Low trust score",
            description=f"Model has low provenance trust score: {provenance.trust_score}/100",
            recommendation="Exercise extra caution with models from untrusted sources",
            details={'risk_factors': provenance.risk_factors}
        ))
    elif provenance.trust_score < 50:
        issues.append(create_security_issue(
            severity="medium",
            category="provenance",
            title="Medium trust score",
            description=f"Model has moderate provenance trust score: {provenance.trust_score}/100",
            recommendation="Verify model source and review risk factors",
            details={'risk_factors': provenance.risk_factors}
        ))
    
    # Specific risk factors
    if provenance.account_age_days and provenance.account_age_days < 30:
        issues.append(create_security_issue(
            severity="medium",
            category="provenance",
            title="Very new account",
            description=f"Model author's account is only {provenance.account_age_days} days old",
            recommendation="New accounts require extra scrutiny - wait for community validation"
        ))
    
    if provenance.total_downloads == 0:
        issues.append(create_security_issue(
            severity="low",
            category="provenance",
            title="No usage history",
            description="Model has zero downloads - no community validation",
            recommendation="Be the first user at your own risk"
        ))
    
    return issues
