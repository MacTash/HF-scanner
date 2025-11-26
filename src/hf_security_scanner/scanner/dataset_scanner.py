"""
Dataset Scanner - Analyzes datasets for PII, sensitive domains, and redistribution risks.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import re

from ..utils.logger import get_logger
from ..utils.security_utils import create_security_issue

logger = get_logger(__name__)


@dataclass
class DatasetAnalysisResult:
    """Result of dataset analysis."""
    pii_found: bool
    sensitive_domains: List[str]
    redistribution_risk: str  # 'low', 'medium', 'high'
    impact_score: float  # 0-10
    security_issues: List[Dict[str, Any]]


class DatasetScanner:
    """Scans datasets for security and privacy risks."""

    def __init__(self):
        """Initialize the dataset scanner."""
        self.pii_keywords = [
            "email", "phone", "ssn", "password", "credit_card", "address",
            "passport", "social_security", "birth_date", "dob"
        ]
        self.sensitive_domains = {
            "healthcare": ["medical", "health", "patient", "clinical", "diagnosis", "hospital"],
            "minors": ["child", "student", "minor", "kid", "school", "education"],
            "biometric": ["face", "fingerprint", "voice", "iris", "biometric", "dna"],
            "finance": ["bank", "financial", "transaction", "loan", "salary"]
        }
        logger.debug("DatasetScanner initialized")

    def scan_dataset(self, dataset_metadata: Dict[str, Any], file_list: List[str]) -> DatasetAnalysisResult:
        """
        Scan a dataset for risks.

        Args:
            dataset_metadata: Metadata dictionary (from cardData or API)
            file_list: List of files in the dataset

        Returns:
            DatasetAnalysisResult
        """
        logger.info("Scanning dataset for risks...")
        
        security_issues = []
        
        # 1. PII Heuristic Detection
        pii_found = self._detect_pii_heuristics(dataset_metadata, file_list, security_issues)
        
        # 2. Sensitive Domain Categorization
        found_domains = self._categorize_domains(dataset_metadata, security_issues)
        
        # 3. Redistribution Risk
        redistribution_risk = self._assess_redistribution_risk(dataset_metadata, security_issues)
        
        # 4. Calculate Impact Score
        impact_score = self._calculate_impact_score(pii_found, found_domains, redistribution_risk)
        
        return DatasetAnalysisResult(
            pii_found=pii_found,
            sensitive_domains=found_domains,
            redistribution_risk=redistribution_risk,
            impact_score=impact_score,
            security_issues=security_issues
        )

    def _detect_pii_heuristics(self, metadata: Dict[str, Any], file_list: List[str], 
                               issues: List[Dict[str, Any]]) -> bool:
        """Detect potential PII based on metadata and filenames."""
        pii_detected = False
        
        # Check column names in metadata if available (often in cardData)
        # Assuming metadata might contain 'dataset_info' -> 'features'
        features = metadata.get('dataset_info', {}).get('features', {})
        column_names = []
        if isinstance(features, dict):
            column_names = list(features.keys())
        elif isinstance(features, list):
            # Sometimes features is a list of dicts
            column_names = [f.get('name', '') for f in features if isinstance(f, dict)]
            
        # Check description/text
        description = metadata.get('description', '') or metadata.get('text', '')
        
        # Check filenames
        all_text = " ".join(column_names + file_list + [description]).lower()
        
        found_keywords = [kw for kw in self.pii_keywords if kw in all_text]
        
        if found_keywords:
            pii_detected = True
            issues.append(create_security_issue(
                severity="high",
                category="dataset",
                title="Potential PII detected",
                description=f"Dataset metadata or files contain PII-related keywords: {', '.join(found_keywords)}",
                recommendation="Verify dataset is anonymized and does not contain personal data"
            ))
            
        return pii_detected

    def _categorize_domains(self, metadata: Dict[str, Any], issues: List[Dict[str, Any]]) -> List[str]:
        """Categorize dataset into sensitive domains."""
        found_domains = []
        
        # Combine relevant text fields
        text = (
            str(metadata.get('description', '')) + " " + 
            str(metadata.get('text', '')) + " " + 
            " ".join(metadata.get('tags', []))
        ).lower()
        
        for domain, keywords in self.sensitive_domains.items():
            if any(kw in text for kw in keywords):
                found_domains.append(domain)
                
                # Add specific issues for highly sensitive domains
                if domain in ["healthcare", "biometric", "minors"]:
                    issues.append(create_security_issue(
                        severity="medium",
                        category="dataset",
                        title=f"Sensitive domain: {domain}",
                        description=f"Dataset involves {domain} data which requires strict compliance",
                        recommendation=f"Ensure compliance with regulations (e.g., HIPAA, GDPR, COPPA) for {domain} data"
                    ))
        
        return found_domains

    def _assess_redistribution_risk(self, metadata: Dict[str, Any], issues: List[Dict[str, Any]]) -> str:
        """Assess risk of redistributing this dataset."""
        license_type = metadata.get('license', '').lower()
        
        # High risk licenses for redistribution
        high_risk = ["non-commercial", "cc-by-nc", "research-only", "proprietary"]
        medium_risk = ["share-alike", "sa", "copyleft", "gpl"]
        
        if any(r in license_type for r in high_risk):
            issues.append(create_security_issue(
                severity="medium",
                category="dataset",
                title="Redistribution restricted",
                description=f"License '{license_type}' restricts commercial redistribution",
                recommendation="Do not redistribute without explicit permission"
            ))
            return "high"
        
        if any(r in license_type for r in medium_risk):
            return "medium"
            
        return "low"

    def _calculate_impact_score(self, pii_found: bool, domains: List[str], redistribution_risk: str) -> float:
        """Calculate dataset impact risk score (0-10)."""
        score = 0.0
        
        if pii_found:
            score += 5.0
            
        # Domain risks
        if "healthcare" in domains: score += 2.0
        if "biometric" in domains: score += 2.0
        if "minors" in domains: score += 3.0
        if "finance" in domains: score += 1.0
        
        # Redistribution risk
        if redistribution_risk == "high":
            score += 2.0
        elif redistribution_risk == "medium":
            score += 1.0
            
        return min(10.0, score)
