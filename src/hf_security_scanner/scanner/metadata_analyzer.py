"""
Metadata Analyzer - Analyzes model metadata for security issues.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from huggingface_hub import ModelInfo

from ..utils.logger import get_logger
from ..utils.security_utils import create_security_issue, analyze_permissions, calculate_risk_score

logger = get_logger(__name__)


@dataclass
class MetadataAnalysisResult:
    """Result of metadata analysis."""
    has_model_card: bool
    has_license: bool
    tags: List[str]
    security_issues: List[Dict[str, Any]]
    risk_score: float
    completeness_score: float


class MetadataAnalyzer:
    """Analyzes model metadata for security and completeness."""
    
    def __init__(self):
        """Initialize the metadata analyzer."""
        logger.debug("MetadataAnalyzer initialized")
    
    def analyze_metadata(self, model_info: ModelInfo, model_metadata: Dict[str, Any]) -> MetadataAnalysisResult:
        """
        Analyze model metadata for security issues.
        
        Args:
            model_info: HuggingFace ModelInfo object
            model_metadata: Extracted model metadata dictionary
            
        Returns:
            MetadataAnalysisResult with analysis details
        """
        logger.info(f"Analyzing metadata for model: {model_metadata.get('model_id', 'unknown')}")
        
        security_issues = []
        
        # Check for model card with quality scoring
        has_model_card = self._check_model_card_quality(model_info, model_metadata, security_issues)
        
        # Check for license
        has_license = model_metadata.get('license') is not None
        if not has_license:
            security_issues.append(create_security_issue(
                severity="high",
                category="metadata",
                title="No license specified",
                description="Model does not specify a license",
                recommendation="Contact model author to clarify licensing terms"
            ))
        
        # Analyze tags
        tags = model_metadata.get('tags', [])
        if not tags:
            security_issues.append(create_security_issue(
                severity="low",
                category="metadata",
                title="No tags specified",
                description="Model has no tags for categorization",
                recommendation="Add relevant tags to improve discoverability"
            ))
        else:
            self._analyze_tags(tags, security_issues)
        
        # Check model activity/popularity
        self._check_model_activity(model_metadata, security_issues)
        self._check_popularity_metrics(model_metadata, security_issues)
        
        # Calculate completeness score
        completeness = self._calculate_completeness_score(has_model_card, has_license, tags, model_metadata)
        
        # Calculate risk score
        risk_score = calculate_risk_score(security_issues)
        
        return MetadataAnalysisResult(
            has_model_card=has_model_card,
            has_license=has_license,
            tags=tags,
            completeness_score=completeness,
            risk_score=risk_score,
            security_issues=security_issues
        )
    
    def _check_model_card_quality(self, model_info: ModelInfo, model_metadata: Dict[str, Any], 
                                   security_issues: List[Dict[str, Any]]) -> bool:
        """
        Check model card presence and analyze quality.
        
        Args:
            model_info: HuggingFace ModelInfo object
            model_metadata: Model metadata dictionary
            security_issues: List to append issues to
            
        Returns:
            True if model has a card
        """
        from .model_card_analyzer import analyze_model_card, get_model_card_issues
        
        # Get README content if available
        card_text = getattr(model_info, 'cardData', {}).get('text') if hasattr(model_info, 'cardData') else None
        
        if not card_text:
            # Try getting from model_metadata
            card_text = model_metadata.get('card_data', {}).get('text')
        
        has_card = card_text is not None and len(card_text.strip()) > 0
        
        if not has_card:
            security_issues.append(create_security_issue(
                severity="medium",  # Changed from high/medium to ensure it's not high alone
                category="metadata",
                title="No model card",
                description="Model does not have a README/model card",
                recommendation="Add a comprehensive model card documenting the model"
            ))
            return False
        
        # Analyze card quality
        card_score = analyze_model_card(card_text)
        card_issues = get_model_card_issues(card_score)
        security_issues.extend(card_issues)
        
        # Store quality score in metadata for reporting
        model_metadata['card_quality_score'] = card_score.overall_score
        
        logger.info(f"Model card quality score: {card_score.overall_score}/100")
        
        return True
    
    def _check_model_card(self, model_info: ModelInfo, issues: List[Dict[str, Any]]) -> bool:
        """Check if model has a proper model card."""
        has_card = hasattr(model_info, 'card_data') and model_info.card_data is not None
        
        if not has_card:
            issues.append(create_security_issue(
                severity="medium",
                category="metadata",
                title="No model card",
                description="Model does not have a model card (README)",
                recommendation="Model documentation is missing - use with caution"
            ))
        
        return has_card
    
    def _analyze_tags(self, tags: List[str], issues: List[Dict[str, Any]]):
        """Analyze model tags for security concerns."""
        if not tags:
            issues.append(create_security_issue(
                severity="low",
                category="metadata",
                title="No tags specified",
                description="Model has no tags",
                recommendation="Tags help identify model purpose and capabilities"
            ))
            return
        
        # Check for risky capabilities
        permissions_analysis = analyze_permissions(tags)
        if permissions_analysis['has_risky_tags']:
            issues.append(create_security_issue(
                severity="medium",
                category="metadata",
                title="Potentially risky capabilities",
                description=f"Model has tags indicating risky capabilities: {permissions_analysis['risky_tags']}",
                recommendation="Review model capabilities before use in production"
            ))
    
    def _check_model_activity(self, metadata: Dict[str, Any], issues: List[Dict[str, Any]]):
        """Check model activity and updates."""
        last_modified = metadata.get('last_modified')
        
        if not last_modified:
            issues.append(create_security_issue(
                severity="low",
                category="metadata",
                title="Unknown modification date",
                description="Cannot determine when model was last updated",
                recommendation="Check model freshness manually"
            ))
    
    def _check_popularity_metrics(self, metadata: Dict[str, Any], issues: List[Dict[str, Any]]):
        """Check downloads and likes as trust indicators."""
        downloads = metadata.get('downloads', 0)
        likes = metadata.get('likes', 0)
        
        # Very low engagement could be a red flag
        if downloads < 10 and likes < 2:
            issues.append(create_security_issue(
                severity="low",
                category="metadata",
                title="Low community engagement",
                description=f"Model has minimal downloads ({downloads}) and likes ({likes})",
                recommendation="New or unpopular models require extra scrutiny"
            ))
    
    def _calculate_metadata_risk_score(self, security_issues: List[Dict[str, Any]]) -> float:
        """Calculate risk score from metadata issues."""
        score = 0.0
        
        severity_weights = {
            "critical": 3.0,
            "high": 2.0,
            "medium": 1.0,
            "low": 0.3
        }
        
        for issue in security_issues:
            severity = issue.get("severity", "low")
            score += severity_weights.get(severity, 0.5)
        
        return min(10.0, round(score, 2))
    
    def _calculate_completeness_score(
        self,
        has_model_card: bool,
        has_license: bool,
        tags: List[str],
        metadata: Dict[str, Any]
    ) -> float:
        """
        Calculate how complete the model metadata is.
        
        Returns:
            Score from 0-100
        """
        score = 0.0
        
        # Model card (30 points)
        if has_model_card:
            score += 30
        
        # License (25 points)
        if has_license:
            score += 25
        
        # Tags (15 points)
        if tags:
            score += min(15, len(tags) * 3)
        
        # Author (10 points)
        if metadata.get('author'):
            score += 10
        
        # Pipeline tag (10 points)
        if metadata.get('pipeline_tag'):
            score += 10
        
        # Library specified (10 points)
        if metadata.get('library_name'):
            score += 10
        
        return min(100.0, round(score, 1))
