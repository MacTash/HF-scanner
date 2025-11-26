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
    
    def __init__(self, strict_license: bool = False):
        self.license_patterns = LICENSE_PATTERNS
        self.problematic_licenses = PROBLEMATIC_LICENSES
        self.strict_license = strict_license
        
        logger.info(f"LicenseChecker initialized (strict_license={strict_license})")
    
    def analyze_license(self, model_info: ModelInfo, metadata_license: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze the license of a model.
        
        Args:
            model_info: Hugging Face ModelInfo object
            metadata_license: Optional license value from metadata (for conflict detection)
            
        Returns:
            Analysis results
        """
        # Prefer metadata license if provided — HF ModelInfo.license is often missing
        license_type = metadata_license or getattr(model_info, "license", None)
        
        # Store resolved license on model_info for downstream analysis
        setattr(model_info, "_resolved_license", license_type)
        
        model_id = getattr(model_info, "modelId", "unknown")
        
        logger.info(f"Resolved license for {model_id}: {license_type}")
        logger.debug(
            f"License resolution details - metadata='{metadata_license}', "
            f"parsed='{getattr(model_info, 'license', None)}'"
        )
        
        # Detect conflicts between metadata and parsed license
        has_conflict = False
        conflict_penalty = 0.0
        if metadata_license and not license_type:
            has_conflict = True
            conflict_penalty = 1.0
            logger.warning(f"License conflict detected for {model_id}: metadata has '{metadata_license}' but parsed as None")
        elif metadata_license and license_type and metadata_license != license_type:
            has_conflict = True
            conflict_penalty = 0.5
            logger.warning(f"License mismatch for {model_id}: metadata='{metadata_license}', parsed='{license_type}'")
        
        logger.info(f"Analyzing license for {model_id}: {license_type}")
        
        compliance_issues = []
        recommendations = []
        compatibility = "FULL"
        license_type_display = license_type
        
        # Calculate base risk score using category-based system
        base_risk = self._calculate_license_risk_score(license_type, has_conflict)
        risk_score = base_risk
        
        # Check if license is specified
        if not license_type:
            # Missing license entirely - high risk
            license_type_display = "Not specified"
            compatibility = "NOT_COMPATIBLE"
            if has_conflict:
                compliance_issues.append({
                    "type": "license_conflict",
                    "description": f"Conflicting license signals: metadata indicates '{metadata_license}' but no parseable license found",
                    "severity": "critical",
                    "details": "Metadata and license parser disagree on license presence"
                })
                # Regression check: If metadata says yes but we say Not specified, warn loudly
                logger.error(f"❌ REGRESSION: Metadata has license '{metadata_license}' but resolved license is None/Not specified")
            else:
                compliance_issues.append({
                    "type": "missing_license",
                    "description": "No license specified for model",
                    "severity": "high",
                    "details": "Model lacks license specification, making usage unclear"
                })
            recommendations.append("Contact model author to clarify licensing terms")
        elif license_type.lower() not in self.license_patterns:
            # Unknown/unrecognized license - exists but not in our database
            license_type_display = metadata_license or license_type or "Unknown"
            if license_type_display == "Unknown":
                 license_type_display = f"Unknown ({license_type})"
            compatibility = "REVIEW_REQUIRED"
            
            compliance_issues.append({
                "type": "unknown_license",
                "description": f"License '{license_type}' is not recognized",
                "severity": "high" if self.strict_license else "medium",
                "details": "License field exists but does not match known license patterns"
            })
            recommendations.append("Review the license terms manually before using this model")
            recommendations.append("Verify commercial use is permitted if applicable")
        else:
            # Analyze known license type
            license_analysis = self._analyze_license_type(license_type)
            compliance_issues.extend(license_analysis["issues"])
            recommendations.extend(license_analysis["recommendations"])
            # Note: base_risk already includes category-based scoring, so we only add additional risks
            risk_score += license_analysis["additional_risk"]
        
        # Check for license compatibility issues
        compatibility_analysis = self._check_license_compatibility(model_info)
        compliance_issues.extend(compatibility_analysis["issues"])
        recommendations.extend(compatibility_analysis["recommendations"])
        risk_score += compatibility_analysis["risk_score"]
        
        # Generate compatibility assessment
        if compatibility != "REVIEW_REQUIRED" and compatibility != "NOT_COMPATIBLE":
            if risk_score == 0:
                compatibility = "FULL"
            elif risk_score <= 3:
                compatibility = "PARTIAL"
            else:
                compatibility = "NOT_COMPATIBLE"
        
        analysis_result = {
            "analysis": {
                "license_type": license_type_display,
                "license_compatibility": compatibility,
                "risk_score": min(risk_score, 10.0),
                "license_details": self._get_license_details(license_type)
            },
            "issues": compliance_issues,
            "recommendations": recommendations
        }
        
        logger.info(f"License analysis completed for {model_id}. Risk score: {risk_score:.2f}")
        return analysis_result
    
    def _calculate_license_risk_score(self, license_key: Optional[str], has_conflict: bool = False) -> float:
        """
        Calculate risk score based on license category using 7-tier system.
        
        Args:
            license_key: License identifier (e.g., 'mit', 'gpl-3.0', 'gemma')
            has_conflict: Whether there's a metadata-parser conflict
            
        Returns:
            Risk score from 0.5 to 9.0
        """
        # 7-Tier risk scoring by category
        RISK_SCORES = {
            "osi_approved": 0.5,        # MIT, Apache-2.0, BSD, MPL-2.0, CC-BY, CC0
            "weak_copyleft": 1.75,      # LGPL, EPL, CC-BY-SA
            "strong_copyleft": 3.5,     # GPL, AGPL
            "special_purpose": 5.0,     # Llama, Gemma, OpenRAIL, CreativeML
            "non_commercial": 6.0,      # CC-BY-NC, CC-BY-NC-SA
            "unknown": 7.5,             # Unrecognized license strings
            "missing": 7.5,             # No license specified
        }
        
        if license_key is None:
            base_risk = RISK_SCORES["missing"]
        elif license_key.lower() not in self.license_patterns:
            # Unknown license - check strict mode
            base_risk = RISK_SCORES["unknown"]
            if self.strict_license:
                base_risk = min(base_risk + 0.5, 8.0)  # Increase slightly in strict mode
        else:
            license_info = self.license_patterns[license_key.lower()]
            category = license_info.get("category", "unknown")
            base_risk = RISK_SCORES.get(category, 5.0)
        
        # Apply conflict penalty if detected
        if has_conflict:
            return min(base_risk + 1.0, 9.0)  # Cap at 9.0 for conflicts
        
        return base_risk
    
    def _analyze_license_type(self, license_type: str) -> Dict[str, Any]:
        """Analyze specific license type for issues."""
        issues = []
        recommendations = []
        additional_risk = 0.0  # Changed from risk_score - base risk comes from category
        
        if not license_type:
            return {
                "issues": issues,
                "recommendations": recommendations,
                "additional_risk": 0.0
            }
        
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
            additional_risk += 7.0 if license_info.get("severity") == "high" else 3.0
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
                additional_risk += 5.0
            
            # Check for redistribution restrictions
            if pattern_info.get("weight_redistribution") == "restricted":
                issues.append(create_security_issue(
                    severity="low",
                    category="license",
                    title="Weight redistribution restricted",
                    description=f"{pattern_info['name']} restricts redistribution of model weights",
                    recommendation="Do not re-host model weights without permission"
                ))
                additional_risk += 2.0
            
            # Check for derivative works restrictions
            if pattern_info.get("derivative_works") == "restricted":
                issues.append(create_security_issue(
                    severity="medium",
                    category="license",
                    title="Derivative works restricted",
                    description=f"{pattern_info['name']} restricts creation of derivative works",
                    recommendation="Check terms before fine-tuning or modifying"
                ))
                additional_risk += 3.0

            if pattern_info.get("copyleft"):
                issues.append(create_security_issue(
                    severity="low",
                    category="license",
                    title="Copyleft license",
                    description=f"{pattern_info['name']} requires derivative works to use same license",
                    recommendation="Ensure compliance with copyleft requirements"
                ))
                additional_risk += 1.0
        
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
            additional_risk += 3.0
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
            additional_risk += 1.0
            recommendations.append("Ensure compliance with share-alike requirements")
        
        return {
            "issues": issues,
            "recommendations": recommendations,
            "additional_risk": additional_risk
        }
    
    def _check_license_compatibility(self, model_info: ModelInfo) -> Dict[str, Any]:
        """Check license compatibility with common use cases."""
        issues = []
        recommendations = []
        risk_score = 0.0
        
        # First check the card metadata for resolved license
        license_type = None
        if hasattr(model_info, "cardData") and isinstance(model_info.cardData, dict):
            license_type = model_info.cardData.get("resolved_license")
        
        # Fallback to model_info.license if still missing
        license_type = license_type or getattr(model_info, "license", None)

        model_tags = getattr(model_info, "tags", [])

        # Check for AI-specific license restrictions
        if license_type:
            # Distinguish research-only vs commercial-OK restrictions
            research_only = ["research-only", "academic-only", "non-commercial-research"]
            ai_restricted = ["ai-restriction", "ml-restriction"]
            
            if any(r in license_type.lower() for r in research_only):
                issues.append({
                    "type": "research_restriction",
                    "description": "License restricts usage to research only",
                    "severity": "high",
                    "details": "Model cannot be used for commercial or production applications"
                })
                risk_score += 5.0
                recommendations.append("Use only for academic/research purposes")
            
            elif any(restriction in license_type.lower() for restriction in ai_restricted):
                issues.append({
                    "type": "ai_restriction",
                    "description": "License contains AI-specific restrictions",
                    "severity": "medium",
                    "details": "Model usage has specific AI/ML constraints"
                })
                risk_score += 3.0
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