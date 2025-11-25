"""
License Checker - Analyzes model licenses for compliance and security issues.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from huggingface_hub import ModelInfo

from ..utils.logger import get_logger
from ..utils.security_utils import create_security_issue
from ..data.license_patterns import LICENSE_PATTERNS, PROBLEMATIC_LICENSES

logger = get_logger(__name__)

@dataclass
class LicenseAnalysis:
    """License analysis result."""
    license_type: Optional[str]
    license_compatibility: str
    compliance_issues: List[Dict[str, Any]]
    recommendations: List[str]
    risk_score: float

class LicenseChecker:
    """Analyzes model licenses for compliance and security issues."""
    
    def __init__(self):
        self.license_patterns = LICENSE_PATTERNS
        self.problematic_licenses = PROBLEMATIC_LICENSES
        
        logger.info("LicenseChecker initialized")
    
    def analyze_license(self, model_info: ModelInfo) -> Dict[str, Any]:
        """
        Analyze the license of a model.
        
        Args:
            model_info: Hugging Face ModelInfo object
            
        Returns:
            Analysis results
        """
        license_type = getattr(model_info, "license", None)
        model_id = getattr(model_info, "modelId", "unknown")
        
        logger.info(f"Analyzing license for {model_id}: {license_type}")
        
        compliance_issues = []
        recommendations = []
        risk_score = 0.0
        
        # Check if license is specified
        if not license_type:
            compliance_issues.append({
                "type": "missing_license",
                "description": "No license specified for model",
                "severity": "high",
                "details": "Model lacks license specification, making usage unclear"
            })
            risk_score += 5.0
            recommendations.append("Contact model author to clarify licensing terms")
        else:
            # Analyze license type
            license_analysis = self._analyze_license_type(license_type)
            compliance_issues.extend(license_analysis["issues"])
            recommendations.extend(license_analysis["recommendations"])
            risk_score += license_analysis["risk_score"]
        
        # Check for license compatibility issues
        compatibility_analysis = self._check_license_compatibility(model_info)
        compliance_issues.extend(compatibility_analysis["issues"])
        recommendations.extend(compatibility_analysis["recommendations"])
        risk_score += compatibility_analysis["risk_score"]
        
        # Generate compatibility assessment
        if risk_score == 0:
            compatibility = "FULL"
        elif risk_score <= 3:
            compatibility = "PARTIAL"
        else:
            compatibility = "NOT_COMPATIBLE"
        
        analysis_result = {
            "analysis": {
                "license_type": license_type,
                "license_compatibility": compatibility,
                "risk_score": min(risk_score, 10.0),
                "license_details": self._get_license_details(license_type)
            },
            "issues": compliance_issues,
            "recommendations": recommendations
        }
        
        logger.info(f"License analysis completed for {model_id}. Risk score: {risk_score:.2f}")
        return analysis_result
    
    def _analyze_license_type(self, license_type: str) -> Dict[str, Any]:
        """Analyze specific license type for issues."""
        issues = []
        recommendations = []
        risk_score = 0.0
        
        # Check against problematic licenses
        if license_type.lower() in self.problematic_licenses:
            license_info = self.problematic_licenses[license_type.lower()]
            issues.append(create_security_issue(
                severity=license_info.get("severity", "high"),
                category="license",
                title=f"Problematic license: {license_type}",
                description=license_info.get("reason", "License has known issues"),
                recommendation=license_info.get("recommendation", "Review license terms")
            ))
            risk_score += 7.0 if license_info.get("severity") == "high" else 3.0
            if "recommendation" in license_info:
                recommendations.append(license_info["recommendation"])
        
        # Check if license is in known patterns
        elif license_type.lower() in self.license_patterns:
            pattern_info = self.license_patterns[license_type.lower()]
            # Check for restrictive properties
            if not pattern_info.get("commercial_use", True):
                issues.append(create_security_issue(
                    severity="medium",
                    category="license",
                    title="Commercial use restricted",
                    description=f"{pattern_info['name']} does not allow commercial use",
                    recommendation="Do not use for commercial purposes"
                ))
                risk_score += 5.0
            if pattern_info.get("copyleft"):
                issues.append(create_security_issue(
                    severity="low",
                    category="license",
                    title="Copyleft license",
                    description=f"{pattern_info['name']} requires derivative works to use same license",
                    recommendation="Ensure compliance with copyleft requirements"
                ))
                risk_score += 1.0
        
        # Check for commercial use restrictions
        commercial_restricted = [
            "non-commercial", "nc", "cc-by-nc", "cc-by-nc-sa", "cc-by-nc-nd"
        ]
        
        if any(restriction in license_type.lower() for restriction in commercial_restricted):
            issues.append({
                "type": "commercial_restriction",
                "description": "License restricts commercial use",
                "severity": "medium",
                "details": "Model cannot be used for commercial purposes"
            })
            risk_score += 3.0
            recommendations.append("Consider alternative models for commercial use")
        
        # Check for share-alike requirements
        share_alike = ["sa", "sharealike", "by-sa"]
        if any(sa in license_type.lower() for sa in share_alike):
            issues.append({
                "type": "share_alike",
                "description": "License has share-alike requirement",
                "severity": "low",
                "details": "Derivative works must use same license"
            })
            risk_score += 1.0
            recommendations.append("Ensure compliance with share-alike requirements")
        
        return {
            "issues": issues,
            "recommendations": recommendations,
            "risk_score": risk_score
        }
    
    def _check_license_compatibility(self, model_info: ModelInfo) -> Dict[str, Any]:
        """Check license compatibility with common use cases."""
        issues = []
        recommendations = []
        risk_score = 0.0
        
        license_type = getattr(model_info, "license", None)
        model_tags = getattr(model_info, "tags", [])
        
        # Check for AI-specific license restrictions
        if license_type:
            ai_restricted = [
                "ai-restriction", "ml-restriction", "research-only",
                "educational-use", "personal-use"
            ]
            
            if any(restriction in license_type.lower() for restriction in ai_restricted):
                issues.append({
                    "type": "ai_restriction",
                    "description": "License restricts AI/ML usage",
                    "severity": "high",
                    "details": "Model usage may be restricted for AI applications"
                })
                risk_score += 6.0
                recommendations.append("Verify AI usage is permitted under license terms")
        
        # Check for military/government restrictions
        if "military" in model_tags or "government" in model_tags:
            issues.append({
                "type": "military_usage",
                "description": "Model associated with military/government use",
                "severity": "medium",
                "details": "Review license for military use restrictions"
            })
            risk_score += 2.0
            recommendations.append("Ensure compliance with military use restrictions")
        
        return {
            "issues": issues,
            "recommendations": recommendations,
            "risk_score": risk_score
        }
    
    def _get_license_details(self, license_type: Optional[str]) -> Dict[str, Any]:
        """Get detailed information about a license."""
        if not license_type:
            return {"description": "No license specified", "url": None}
        
        # Common license information
        license_info = {
            "mit": {
                "description": "MIT License - Permissive open source license",
                "url": "https://opensource.org/licenses/MIT",
                "commercial": True,
                "modifications": True,
                "distribution": True,
                "liability": False,
                "warranty": False
            },
            "apache-2.0": {
                "description": "Apache License 2.0 - Permissive with patent grant",
                "url": "https://opensource.org/licenses/Apache-2.0",
                "commercial": True,
                "modifications": True,
                "distribution": True,
                "patent_use": True,
                "liability": False,
                "warranty": False
            },
            "gpl-3.0": {
                "description": "GNU General Public License v3.0 - Copyleft",
                "url": "https://opensource.org/licenses/GPL-3.0",
                "commercial": True,
                "modifications": True,
                "distribution": True,
                "share_alike": True,
                "liability": False,
                "warranty": False
            },
            "cc-by-4.0": {
                "description": "Creative Commons Attribution 4.0",
                "url": "https://creativecommons.org/licenses/by/4.0/",
                "commercial": True,
                "modifications": True,
                "attribution_required": True
            }
        }
        
        return license_info.get(license_type.lower(), {
            "description": f"Custom license: {license_type}",
            "url": None
        })