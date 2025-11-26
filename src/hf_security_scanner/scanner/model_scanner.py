"""
Model Scanner - Main scanning orchestrator for Hugging Face models
"""
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from ..utils.hf_utils import HFAPIClient
from ..utils.logger import get_logger
from ..utils.security_utils import calculate_risk_score, generate_recommendations
from .file_analyzer import FileAnalyzer
from .license_checker import LicenseChecker
from .metadata_analyzer import MetadataAnalyzer
from .vulnerability_scanner import VulnerabilityScanner

logger = get_logger(__name__)


@dataclass
class ScanResult:
    """Result of a model security scan"""
    model_id: str
    scan_timestamp: str
    model_info: Dict[str, Any]
    file_analysis: Dict[str, Any]
    license_analysis: Dict[str, Any]
    metadata_analysis: Dict[str, Any]
    vulnerability_analysis: Dict[str, Any]
    dataset_analysis: Dict[str, Any]  # New field
    overall_risk_score: float
    security_issues: List[Dict[str, Any]]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class ModelScanner:
    """Main scanner class for Hugging Face models"""

    def __init__(self,
                 max_workers: int = 4,
                 timeout: int = 30,
                 strict_license: bool = False,
                 token: Optional[str] = None):
        """Initialize the model scanner.
        
        Args:
            max_workers: Maximum number of workers for batch scanning
            timeout: Request timeout in seconds
            strict_license: If True, treat unknown licenses as high-risk
            token: HuggingFace API token (optional)
        """
        self.hf_client = HFAPIClient(token=token, timeout=timeout)
        self.max_workers = max_workers
        self.timeout = timeout
        self.strict_license = strict_license
        
        # Initialize scanners
        self.file_analyzer = FileAnalyzer()
        self.license_checker = LicenseChecker(strict_license=strict_license)
        self.metadata_analyzer = MetadataAnalyzer()
        self.vulnerability_scanner = VulnerabilityScanner()
        from .dataset_scanner import DatasetScanner
        self.dataset_scanner = DatasetScanner()

        logger.info(f"ModelScanner initialized with {max_workers} workers")

    def scan_model(self, model_id: str) -> ScanResult: 
        """
        Scan a single Hugging Face model for security vulnerabilities.

        Args:
            model_id: Hugging Face model identifier (e.g., "gpt2",
        "microsoft/DialoGPT-medium")

        Returns:
            ScanResult containing all analysis results
        """
        logger.info(f"🔍 Starting scan for model: {model_id}")
        start_time = time.time()

        try:
            # Get model information
            model_info = self.hf_client.get_model_info(model_id)
            if not model_info:
                raise ValueError(f"Could not retrieve information for model: {model_id}")

            # Extract metadata
            model_metadata = self.hf_client.extract_model_metadata(model_info)
            
            # Get file list
            files = self.hf_client.list_model_files(model_id)
            logger.info(f"Found {len(files)} files in repository")

            # Initialize lists for aggregating results
            all_security_issues = []
            all_recommendations = []

            # Analyze files
            logger.info("📁 Analyzing files...")
            file_result = self.file_analyzer.analyze_files(files)
            

            file_analysis = {
                "total_files": file_result.total_files,
                "suspicious_files": len(file_result.suspicious_files),
                "file_categories": {k: len(v) for k, v in file_result.file_categories.items()},
                "risk_score": file_result.risk_score
            }
            all_security_issues.extend(file_result.security_issues)
            
            # Analyze license
            logger.info("📜 Analyzing license...")
            # Pass metadata license for accurate detection
            metadata_license = model_metadata.get("license")
            license_result = self.license_checker.analyze_license(
                model_info,
                metadata_license=metadata_license
            )
            license_analysis = license_result["analysis"]
            all_security_issues.extend(license_result["issues"])
            all_recommendations.extend(license_result["recommendations"])
            
            # Analyze metadata
            logger.info("📋 Analyzing metadata...")
            metadata_result = self.metadata_analyzer.analyze_metadata(model_info, model_metadata)
            metadata_analysis = {
                "has_model_card": metadata_result.has_model_card,
                "has_license": metadata_result.has_license,
                "tags_count": len(metadata_result.tags),
                "completeness_score": metadata_result.completeness_score,
                "risk_score": metadata_result.risk_score
            }
            all_security_issues.extend(metadata_result.security_issues)
            
            # Analyze vulnerabilities
            logger.info("🔒 Scanning for vulnerabilities...")
            vuln_result = self.vulnerability_scanner.scan_vulnerabilities(model_metadata, files)
            vulnerability_analysis = {
                "vulnerabilities_found": len(vuln_result.vulnerabilities_found),
                "risk_score": vuln_result.risk_score
            }
            all_security_issues.extend(vuln_result.security_issues)
            
            # Analyze Python code files
            logger.info("💻 Analyzing code files...")
            from .code_analyzer import analyze_python_file_list
            code_issues = analyze_python_file_list(files)
            all_security_issues.extend(code_issues)
            
            # Analyze ONNX files
            logger.info("🔍 Analyzing ONNX models...")
            from .onnx_scanner import analyze_onnx_files_batch
            onnx_issues = analyze_onnx_files_batch(files)
            all_security_issues.extend(onnx_issues)
            
            # Analyze provenance/trust
            logger.info("🔍 Analyzing model provenance...")
            from .provenance_analyzer import calculate_provenance_score, get_provenance_issues
            provenance_score = calculate_provenance_score(model_metadata)
            provenance_issues = get_provenance_issues(provenance_score)
            all_security_issues.extend(provenance_issues)
            
            # Store provenance in metadata for reporting
            model_metadata['provenance_score'] = provenance_score.trust_score
            model_metadata['provenance_level'] = provenance_score
            
            # Dataset Security Analysis (Phase 1 + Linked Datasets)
            logger.info("📊 Analyzing dataset risks...")
            
            # 1. Identify linked datasets
            linked_datasets = set()
            
            # Check cardData
            if hasattr(model_info, "cardData") and model_info.cardData:
                datasets = model_info.cardData.get("datasets", [])
                if isinstance(datasets, str):
                    linked_datasets.add(datasets)
                elif isinstance(datasets, list):
                    linked_datasets.update(datasets)
            
            # Check tags
            for tag in model_metadata.get("tags", []):
                if tag.startswith("dataset:"):
                    linked_datasets.add(tag.split(":", 1)[1])
            
            dataset_results_list = []
            aggregated_impact_score = 0.0
            
            # 2. Scan each dataset
            if linked_datasets:
                logger.info(f"Found {len(linked_datasets)} linked datasets: {', '.join(linked_datasets)}")
                for ds_name in linked_datasets:
                    try:
                        logger.info(f"Scanning dataset: {ds_name}")
                        ds_info = self.hf_client.get_dataset_info(ds_name)
                        if not ds_info:
                            logger.warning(f"Could not fetch info for dataset {ds_name}, skipping")
                            continue
                            
                        ds_files = self.hf_client.list_dataset_files(ds_name)
                        
                        # Convert ds_info to dict for scanner
                        ds_metadata = {
                            "id": ds_name,
                            "description": getattr(ds_info, "description", ""),
                            "tags": getattr(ds_info, "tags", []),
                            "license": getattr(ds_info, "cardData", {}).get("license", ""),
                            "cardData": getattr(ds_info, "cardData", {})
                        }
                        
                        ds_result = self.dataset_scanner.scan_dataset(ds_metadata, ds_files)
                        
                        dataset_results_list.append({
                            "name": ds_name,
                            "pii_found": ds_result.pii_found,
                            "sensitive_domains": ds_result.sensitive_domains,
                            "redistribution_risk": ds_result.redistribution_risk,
                            "impact_score": ds_result.impact_score
                        })
                        
                        # Aggregate issues
                        for issue in ds_result.security_issues:
                            # Contextualize issue title
                            issue['title'] = f"[Dataset: {ds_name}] {issue['title']}"
                            all_security_issues.append(issue)
                            
                        aggregated_impact_score = max(aggregated_impact_score, ds_result.impact_score)
                        
                    except Exception as e:
                        logger.warning(f"Failed to scan dataset {ds_name}: {e}")
            else:
                logger.info("No linked datasets found in metadata")

            # 3. Also scan the model repo itself as a "dataset" if it looks like one (legacy check)
            # (Keeping this lightweight or merging it? The prompt implies full replacement but let's keep it safe)
            # Actually, the prompt says "Implement full linked-dataset scanning support". 
            # If no linked datasets, we might still want to check the model repo for PII if it contains data files.
            # But for now, let's focus on the linked datasets as requested.
            
            dataset_analysis = {
                "datasets": dataset_results_list,
                "total_datasets_scanned": len(dataset_results_list),
                "max_impact_score": aggregated_impact_score
            }
            
            # Usage-Based Validation (Supply Chain Risk)
            downloads = model_metadata.get('downloads', 0)
            if downloads < 10 and file_result.suspicious_files:
                all_security_issues.append({
                    "severity": "high",  # Escalate to high
                    "category": "supply_chain",
                    "title": "High Supply Chain Risk",
                    "description": "Model has very low usage (<10 downloads) AND contains suspicious files",
                    "recommendation": "Do not use without manual code review - high risk of malware",
                    "details": {"suspicious_files": file_result.suspicious_files}
                })
            
            # Calculate overall risk score
            overall_risk_score = calculate_risk_score(all_security_issues)
            
            # Generate recommendations
            all_recommendations.extend(generate_recommendations(all_security_issues))
            
            # Create scan result
            scan_result = ScanResult(
                model_id=model_id,
                scan_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                model_info=model_metadata,
                file_analysis=file_analysis,
                license_analysis=license_analysis,
                metadata_analysis=metadata_analysis,
                vulnerability_analysis=vulnerability_analysis,
                dataset_analysis=dataset_analysis,  # Add dataset analysis
                overall_risk_score=overall_risk_score,
                security_issues=all_security_issues,
                recommendations=list(set(all_recommendations))  # Remove duplicates
            )
            
            scan_time = time.time() - start_time
            logger.info(f"✅ Completed scan for {model_id} in {scan_time:.2f} seconds")
            logger.info(f"📊 Overall risk score: {overall_risk_score:.2f}/10.0")
            logger.info(f"⚠️  Security issues found: {len(all_security_issues)}")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"❌ Error scanning model {model_id}: {str(e)}")
            raise
    
    def scan_models_batch(self, model_ids: List[str]) -> List[ScanResult]:
        """
        Scan multiple models concurrently.
        
        Args:
            model_ids: List of Hugging Face model identifiers
            
        Returns:
            List of ScanResult objects
        """
        logger.info(f"Starting batch scan for {len(model_ids)} models")
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all scan tasks
            future_to_model = {
                executor.submit(self.scan_model, model_id): model_id
                for model_id in model_ids
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_model):
                model_id = future_to_model[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"✓ Successfully scanned {model_id}")
                except Exception as e:
                    logger.error(f"✗ Failed to scan {model_id}: {str(e)}")
        
        logger.info(f"Batch scan completed. {len(results)}/{len(model_ids)} models scanned successfully")
        return results
