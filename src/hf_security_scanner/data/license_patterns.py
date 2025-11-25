"""License patterns and compliance data."""

# Open source licenses with their properties
LICENSE_PATTERNS = {
    "apache-2.0": {
        "name": "Apache License 2.0",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": True,
        "risk_level": "low",
        "requires_attribution": True,
    },
    "mit": {
        "name": "MIT License",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "risk_level": "low",
        "requires_attribution": True,
    },
    "gpl-3.0": {
        "name": "GNU General Public License v3.0",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": True,
        "risk_level": "medium",
        "requires_attribution": True,
        "copyleft": True,
        "requires_source_disclosure": True,
    },
    "gpl-2.0": {
        "name": "GNU General Public License v2.0",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "risk_level": "medium",
        "requires_attribution": True,
        "copyleft": True,
        "requires_source_disclosure": True,
    },
    "lgpl-3.0": {
        "name": "GNU Lesser General Public License v3.0",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": True,
        "risk_level": "medium",
        "requires_attribution": True,
        "copyleft": "weak",
    },
    "bsd-3-clause": {
        "name": "BSD 3-Clause License",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "risk_level": "low",
        "requires_attribution": True,
    },
    "bsd-2-clause": {
        "name": "BSD 2-Clause License",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "risk_level": "low",
        "requires_attribution": True,
    },
    "cc-by-4.0": {
        "name": "Creative Commons Attribution 4.0",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "risk_level": "low",
        "requires_attribution": True,
    },
    "cc-by-sa-4.0": {
        "name": "Creative Commons Attribution Share Alike 4.0",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "risk_level": "medium",
        "requires_attribution": True,
        "copyleft": True,
    },
    "cc-by-nc-4.0": {
        "name": "Creative Commons Attribution Non Commercial 4.0",
        "commercial_use": False,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "risk_level": "high",
        "requires_attribution": True,
    },
    "openrail": {
        "name": "Open RAIL License",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "risk_level": "low",
        "requires_attribution": True,
        "use_restrictions": True,
    },
    "bigscience-openrail-m": {
        "name": "BigScience Open RAIL-M License",
        "commercial_use": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "risk_level": "low",
        "requires_attribution": True,
        "use_restrictions": True,
    },
}

# Problematic licenses that should be flagged
PROBLEMATIC_LICENSES = {
    "unknown": {
        "reason": "License not specified or recognized",
        "severity": "high",
        "recommendation": "Contact model author to clarify licensing"
    },
    "other": {
        "reason": "Custom or non-standard license",
        "severity": "medium",
        "recommendation": "Manually review license terms"
    },
    "cc-by-nc-4.0": {
        "reason": "Non-commercial use only",
        "severity": "medium",
        "recommendation": "Cannot be used for commercial purposes"
    },
    "gpl-3.0": {
        "reason": "Strong copyleft - requires derivative works to be GPL",
        "severity": "medium",
        "recommendation": "Review GPL compliance requirements for your use case"
    },
    "agpl-3.0": {
        "reason": "Network copyleft - requires source disclosure even for SaaS",
        "severity": "high",
        "recommendation": "Avoid for commercial SaaS applications"
    },
}

# License compatibility matrix
LICENSE_COMPATIBILITY = {
    "mit": ["apache-2.0", "gpl-3.0", "lgpl-3.0", "bsd-3-clause"],
    "apache-2.0": ["gpl-3.0", "lgpl-3.0"],
    "bsd-3-clause": ["apache-2.0", "gpl-3.0", "lgpl-3.0", "mit"],
    "gpl-3.0": [],  # GPL is one-way compatible
}
