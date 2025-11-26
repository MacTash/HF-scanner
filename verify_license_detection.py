#!/usr/bin/env python3
"""
Simple verification script for license detection improvements.
This can be run without pytest to verify basic functionality.
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from unittest.mock import Mock
from huggingface_hub import ModelInfo
from hf_security_scanner.scanner.license_checker import LicenseChecker


def create_mock_model_info(license_value):
    """Helper to create a mock ModelInfo object."""
    model_info = Mock(spec=ModelInfo)
    model_info.license = license_value
    model_info.modelId = "test/model"
    model_info.tags = []
    return model_info


def test_missing_license():
    """Test missing license detection."""
    print("\\n🔍 Test 1: Missing License")
    print("-" * 50)
    
    checker = LicenseChecker(strict_license=False)
    model_info = create_mock_model_info(None)
    result = checker.analyze_license(model_info)
    
    print(f"  License Type: {result['analysis']['license_type']}")
    print(f"  Compatibility: {result['analysis']['license_compatibility']}")
    print(f"  Risk Score: {result['analysis']['risk_score']}")
    print(f"  Issues: {len(result['issues'])}")
    
    # Assertions
    assert result['analysis']['license_type'] is None, "Expected None for missing license"
    assert result['analysis']['license_compatibility'] == "NOT_COMPATIBLE"
    assert result['analysis']['risk_score'] >= 5.0, "Expected high risk for missing license"
    print("  ✅ PASSED")


def test_unknown_license_default():
    """Test unknown license in default mode."""
    print("\\n🔍 Test 2: Unknown License (Default Mode)")
    print("-" * 50)
    
    checker = LicenseChecker(strict_license=False)
    model_info = create_mock_model_info("custom-proprietary-license")
    result = checker.analyze_license(model_info)
    
    print(f"  License Type: {result['analysis']['license_type']}")
    print(f"  Compatibility: {result['analysis']['license_compatibility']}")
    print(f"  Risk Score: {result['analysis']['risk_score']}")
    
    # Assertions
    assert "Unknown (" in result['analysis']['license_type']
    assert result['analysis']['license_compatibility'] == "REVIEW_REQUIRED"
    assert result['analysis']['risk_score'] == 3.0, f"Expected 3.0, got {result['analysis']['risk_score']}"
    print("  ✅ PASSED")


def test_unknown_license_strict():
    """Test unknown license in strict mode."""
    print("\\n🔍 Test 3: Unknown License (Strict Mode)")
    print("-" * 50)
    
    checker = LicenseChecker(strict_license=True)
    model_info = create_mock_model_info("custom-proprietary-license")
    result = checker.analyze_license(model_info)
    
    print(f"  License Type: {result['analysis']['license_type']}")
    print(f"  Compatibility: {result['analysis']['license_compatibility']}")
    print(f"  Risk Score: {result['analysis']['risk_score']}")
    
    # Assertions
    assert "Unknown (" in result['analysis']['license_type']
    assert result['analysis']['license_compatibility'] == "REVIEW_REQUIRED"
    assert result['analysis']['risk_score'] == 5.0, f"Expected 5.0, got {result['analysis']['risk_score']}"
    print("  ✅ PASSED")


def test_known_permissive():
    """Test known permissive license."""
    print("\\n🔍 Test 4: Known Permissive License (MIT)")
    print("-" * 50)
    
    checker = LicenseChecker(strict_license=False)
    model_info = create_mock_model_info("mit")
    result = checker.analyze_license(model_info)
    
    print(f"  License Type: {result['analysis']['license_type']}")
    print(f"  Compatibility: {result['analysis']['license_compatibility']}")
    print(f"  Risk Score: {result['analysis']['risk_score']}")
    
    # Assertions
    assert result['analysis']['license_type'] == "mit"
    assert not result['analysis']['license_type'].startswith("Unknown")
    assert result['analysis']['risk_score'] < 3.0
    print("  ✅ PASSED")


def test_ai_licenses():
    """Test AI-specific licenses are recognized."""
    print("\\n🔍 Test 5: AI-Specific Licenses")
    print("-" * 50)
    
    ai_licenses = ["creativeml-openrail-m", "bigcode-openrail-m", "llama2", "llama3"]
    checker = LicenseChecker(strict_license=False)
    
    for lic in ai_licenses:
        model_info = create_mock_model_info(lic)
        result = checker.analyze_license(model_info)
        
        print(f"  {lic}: ", end="")
        assert not result['analysis']['license_type'].startswith("Unknown"), f"{lic} should be recognized"
        assert result['analysis']['license_type'] == lic
        print(f"✅ Recognized (risk: {result['analysis']['risk_score']})")
    
    print("  ✅ ALL PASSED")


def test_non_commercial():
    """Test non-commercial license."""
    print("\\n🔍 Test 6: Non-Commercial License")
    print("-" * 50)
    
    checker = LicenseChecker(strict_license=False)
    model_info = create_mock_model_info("cc-by-nc-4.0")
    result = checker.analyze_license(model_info)
    
    print(f"  License Type: {result['analysis']['license_type']}")
    print(f"  Compatibility: {result['analysis']['license_compatibility']}")
    print(f"  Risk Score: {result['analysis']['risk_score']}")
    
    # Assertions
    assert result['analysis']['license_type'] == "cc-by-nc-4.0"
    assert result['analysis']['risk_score'] >= 5.0, "Non-commercial should be high risk"
    print("  ✅ PASSED")


def main():
    """Run all verification tests."""
    print("=" * 60)
    print("LICENSE DETECTION VERIFICATION SCRIPT")
    print("=" * 60)
    
    try:
        test_missing_license()
        test_unknown_license_default()
        test_unknown_license_strict()
        test_known_permissive()
        test_ai_licenses()
        test_non_commercial()
        
        print("\\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        return 0
        
    except AssertionError as e:
        print(f"\\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
