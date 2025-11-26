"""
Model Card Analyzer - Evaluates README.md quality and completeness.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..utils.logger import get_logger
from ..utils.security_utils import create_security_issue

logger = get_logger(__name__)


# Required sections for a good model card
REQUIRED_SECTIONS = [
    "model description",
    "intended use",
    "limitations",
    "training",
    "evaluation",
]

SAFETY_KEYWORDS = [
    "safety", "risk", "bias", "ethical", "limitations",
    "intended use", "out-of-scope", "misuse"
]

RED_FLAG_KEYWORDS = [
    "state-of-the-art", "best model", "perfect",
    "no limitations", "always accurate"
]


@dataclass
class ModelCardQualityScore:
    """Model card quality assessment."""
    overall_score: float  # 0-100
    has_required_sections: Dict[str, bool]
    has_safety_disclosure: bool
    has_limitations: bool
    has_intended_use: bool
    has_evaluation_results: bool
    red_flags: List[str]
    missing_sections: List[str]
    recommendations: List[str]


def analyze_model_card(model_card_text: Optional[str]) -> ModelCardQualityScore:
    """
    Analyze model card quality and completeness.
    
    Args:
        model_card_text: README.md content
        
    Returns:
        ModelCardQualityScore with analysis
    """
    if not model_card_text:
        return ModelCardQualityScore(
            overall_score=0.0,
            has_required_sections={},
            has_safety_disclosure=False,
            has_limitations=False,
            has_intended_use=False,
            has_evaluation_results=False,
            red_flags=[],
            missing_sections=REQUIRED_SECTIONS,
            recommendations=["Add a comprehensive model card with safety disclosures"]
        )
    
    card_lower = model_card_text.lower()
    
    # Check for required sections
    section_scores = {}
    for section in REQUIRED_SECTIONS:
        section_scores[section] = section in card_lower
    
    # Check for safety disclosures
    has_safety = any(keyword in card_lower for keyword in SAFETY_KEYWORDS)
    
    # Check for limitations section
    has_limitations = "limitation" in card_lower
    
    # Check for intended use
    has_intended_use = "intended use" in card_lower or " use case" in card_lower
    
    # Check for evaluation results
    has_evaluation = "evaluation" in card_lower or "benchmark" in card_lower or "performance" in card_lower
    
    # Check for red flags
    red_flags = [flag for flag in RED_FLAG_KEYWORDS if flag in card_lower]
    
    # Check for dataset description
    has_dataset = "dataset" in card_lower or "data" in card_lower or "training data" in card_lower
    
    # Calculate overall score
    score = 0.0
    
    # Section completeness (50 points max)
    sections_found = sum(1 for present in section_scores.values() if present)
    score += (sections_found / len(REQUIRED_SECTIONS)) * 50
    
    # Safety disclosure (15 points)
    if has_safety:
        score += 15
    
    # Limitations (10 points)
    if has_limitations:
        score += 10
    
    # Evaluation results (10 points)
    if has_evaluation:
        score += 10
        
    # Dataset description (15 points)
    if has_dataset:
        score += 15
    
    # Penalty for red flags
    score -= len(red_flags) * 5
    
    # Ensure 0-100 range
    score = max(0, min(100, score))
    
    # Generate recommendations
    recommendations = []
    missing = [s for s, present in section_scores.items() if not present]
    
    if missing:
        recommendations.append(f"Add missing sections: {', '.join(missing)}")
    if not has_safety:
        recommendations.append("Include safety disclosures and risk assessment")
    if not has_limitations:
        recommendations.append("Document model limitations and failure modes")
    if not has_intended_use:
        recommendations.append("Clearly specify intended use cases")
    if not has_dataset:
        recommendations.append("Describe the training dataset")
    if red_flags:
        recommendations.append(f"Avoid exaggerated claims: {', '.join(red_flags)}")
    
    return ModelCardQualityScore(
        overall_score=round(score, 1),
        has_required_sections=section_scores,
        has_safety_disclosure=has_safety,
        has_limitations=has_limitations,
        has_intended_use=has_intended_use,
        has_evaluation_results=has_evaluation,
        red_flags=red_flags,
        missing_sections=missing,
        recommendations=recommendations
    )


def get_model_card_issues(card_score: ModelCardQualityScore) -> List[Dict[str, Any]]:
    """
    Convert model card analysis to security issues.
    
    Args:
        card_score: ModelCardQualityScore result
        
    Returns:
        List of security issues
    """
    issues = []
    
    # Overall quality
    if card_score.overall_score < 50:
        issues.append(create_security_issue(
            severity="medium",
            category="metadata",
            title="Low model card quality",
            description=f"Model card quality score: {card_score.overall_score}/100",
            recommendation="Improve documentation to meet minimum quality standards"
        ))
    
    # Missing safety disclosure
    if not card_score.has_safety_disclosure:
        issues.append(create_security_issue(
            severity="medium",
            category="metadata",
            title="No safety disclosure",
            description="Model card lacks safety and risk information",
            recommendation="Add safety disclosures, known risks, and ethical considerations"
        ))
    
    # Missing limitations
    if not card_score.has_limitations:
        issues.append(create_security_issue(
            severity="low",
            category="metadata",
            title="No limitations documented",
            description="Model card does not document limitations or failure modes",
            recommendation="Add a 'Limitations' section describing known issues"
        ))
    
    # Missing intended use
    if not card_score.has_intended_use:
        issues.append(create_security_issue(
            severity="low",
            category="metadata",
            title="Intended use not specified",
            description="Model card does not clearly specify intended use cases",
            recommendation="Add 'Intended Use' and 'Out-of-Scope Use' sections"
        ))
    
    # Red flags
    if card_score.red_flags:
        issues.append(create_security_issue(
            severity="low",
            category="metadata",
            title="Exaggerated claims detected",
            description=f"Model card contains suspicious claims: {', '.join(card_score.red_flags)}",
            recommendation="Provide evidence for claims and avoid marketing language"
        ))
    
    return issues
