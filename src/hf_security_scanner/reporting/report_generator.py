"""
Report Generator - Generates security scan reports in various formats.
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.security_utils import get_risk_level

logger = get_logger(__name__)


class ReportGenerator:
    """Generates security scan reports."""
    
    def __init__(self):
        """Initialize the report generator."""
        logger.debug("ReportGenerator initialized")
    
    def generate_json_report(
        self,
        scan_result: Any,
        output_path: Optional[str] = None
    ) -> str:
        """
        Generate a JSON report from scan results.
        
        Args:
            scan_result: ScanResult object
            output_path: Optional path to save report (if None, returns JSON string)
            
        Returns:
            JSON string
        """
        logger.info(f"Generating JSON report for {scan_result.model_id}")
        
        report_data = scan_result.to_dict()
        json_str = json.dumps(report_data, indent=2)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(json_str)
            logger.info(f"JSON report saved to: {output_path}")
        
        return json_str
    
    def generate_text_report(self, scan_result: Any) -> str:
        """
        Generate a human-readable text report.
        
        Args:
            scan_result: ScanResult object
            
        Returns:
            Formatted text report
        """
        logger.info(f"Generating text report for {scan_result.model_id}")
        
        risk_level = get_risk_level(scan_result.overall_risk_score)
        risk_emoji = {
            "low": "✅",
            "medium": "⚠️",
            "high": "🔴",
            "critical": "🚨"
        }.get(risk_level, "⚠️")
        
        lines = []
        lines.append("=" * 80)
        lines.append(f"HUGGINGFACE MODEL SECURITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append(f"")
        lines.append(f"Model ID: {scan_result.model_id}")
        lines.append(f"Scan Time: {scan_result.scan_timestamp}")
        lines.append(f"")
        lines.append(f"OVERALL RISK SCORE: {scan_result.overall_risk_score:.2f}/10.0 {risk_emoji}")
        lines.append(f"Risk Level: {risk_level.upper()}")
        lines.append(f"")
        
        # Model Info
        lines.append("-" * 80)
        lines.append("MODEL INFORMATION")
        lines.append("-" * 80)
        info = scan_result.model_info
        lines.append(f"Author: {info.get('author', 'Unknown')}")
        lines.append(f"Downloads: {info.get('downloads', 0):,}")
        lines.append(f"Likes: {info.get('likes', 0)}")
        lines.append(f"License: {info.get('license', 'Not specified')}")
        lines.append(f"Pipeline: {info.get('pipeline_tag', 'Not specified')}")
        lines.append(f"Library: {info.get('library_name', 'Not specified')}")
        lines.append("")
        
        # File Analysis
        lines.append("-" * 80)
        lines.append("FILE ANALYSIS")
        lines.append("-" * 80)
        file_analysis = scan_result.file_analysis
        lines.append(f"Total Files: {file_analysis.get('total_files', 0)}")
        lines.append(f"Suspicious Files: {file_analysis.get('suspicious_files', 0)}")
        lines.append(f"File Risk Score: {file_analysis.get('risk_score', 0):.2f}/10.0")
        
        categories = file_analysis.get('file_categories', {})
        if categories:
            lines.append(f"\nFile Categories:")
            for category, count in categories.items():
                if count > 0:
                    lines.append(f"  - {category}: {count}")
        lines.append("")
        
        # License Analysis
        lines.append("-" * 80)
        lines.append("LICENSE ANALYSIS")
        lines.append("-" * 80)
        lic = scan_result.license_analysis
        lines.append(f"License Type: {lic.get('license_type', 'Not specified')}")
        lines.append(f"Compatibility: {lic.get('license_compatibility', 'Unknown')}")
        lines.append(f"License Risk Score: {lic.get('risk_score', 0):.2f}/10.0")
        lines.append("")
        
        # Metadata Analysis
        lines.append("-" * 80)
        lines.append("METADATA ANALYSIS")
        lines.append("-" * 80)
        meta = scan_result.metadata_analysis
        lines.append(f"Has Model Card: {'Yes' if meta.get('has_model_card') else 'No'}")
        lines.append(f"Has License: {'Yes' if meta.get('has_license') else 'No'}")
        lines.append(f"Completeness Score: {meta.get('completeness_score', 0):.1f}/100")
        lines.append(f"Metadata Risk Score: {meta.get('risk_score', 0):.2f}/10.0")
        lines.append("")
        
        # Vulnerability Analysis
        lines.append("-" * 80)
        lines.append("VULNERABILITY ANALYSIS")
        lines.append("-" * 80)
        vuln = scan_result.vulnerability_analysis
        lines.append(f"Vulnerabilities Found: {vuln.get('vulnerabilities_found', 0)}")
        lines.append(f"Vulnerability Risk Score: {vuln.get('risk_score', 0):.2f}/10.0")
        lines.append("")
        
        # Security Issues
        if scan_result.security_issues:
            lines.append("-" * 80)
            lines.append(f"SECURITY ISSUES ({len(scan_result.security_issues)} found)")
            lines.append("-" * 80)
            
            # Group by severity
            by_severity = {}
            for issue in scan_result.security_issues:
                sev = issue.get('severity', 'unknown')
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(issue)
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in by_severity:
                    lines.append(f"\n{severity.upper()} ({len(by_severity[severity])} issues):")
                    for i, issue in enumerate(by_severity[severity][:5], 1):  # Limit to 5 per severity
                        lines.append(f"  {i}. {issue.get('title', 'Unknown issue')}")
                        lines.append(f"     {issue.get('description', '')}")
                    if len(by_severity[severity]) > 5:
                        lines.append(f"  ... and {len(by_severity[severity]) - 5} more")
            lines.append("")
        
        # Recommendations
        if scan_result.recommendations:
            lines.append("-" * 80)
            lines.append(f"RECOMMENDATIONS ({len(scan_result.recommendations)})")
            lines.append("-" * 80)
            for i, rec in enumerate(scan_result.recommendations[:10], 1):  # Limit to 10
                lines.append(f"{i}. {rec}")
            if len(scan_result.recommendations) > 10:
                lines.append(f"... and {len(scan_result.recommendations) - 10} more")
            lines.append("")
        
        lines.append("=" * 80)
        lines.append(f"End of Report")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def generate_html_report(
        self,
        scan_result: Any,
        output_path: Optional[str] = None
    ) -> str:
        """
        Generate an HTML report from scan results.
        
        Args:
            scan_result: ScanResult object
            output_path: Optional path to save report
            
        Returns:
            HTML string
        """
        logger.info(f"Generating HTML report for {scan_result.model_id}")
        
        risk_level = get_risk_level(scan_result.overall_risk_score)
        risk_color = {
            "low": "#28a745",
            "medium": "#ffc107",
            "high": "#fd7e14",
            "critical": "#dc3545"
        }.get(risk_level, "#6c757d")
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_result.model_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px; 
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 12px; 
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        h1 {{ 
            color: #333; 
            margin-bottom: 10px; 
            font-size: 2.5em;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .subtitle {{ color: #666; margin-bottom: 30px; }}
        .risk-badge {{ 
            display: inline-block;
            padding: 12px 24px;
            border-radius: 8px;
            color: white;
            font-weight: bold;
            font-size: 1.3em;
            margin: 20px 0;
            background: {risk_color};
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        .section {{ 
            margin: 30px 0;
            padding: 25px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .section h2 {{ 
            color: #333; 
            margin-bottom: 15px;
            font-size: 1.5em;
        }}
        .info-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }}
        .info-item {{ 
            padding: 12px;
            background: white;
            border-radius: 6px;
            border: 1px solid #e0e0e0;
        }}
        .info-label {{ 
            font-weight: 600; 
            color: #667eea;
            font-size: 0.9em;
            margin-bottom: 4px;
        }}
        .info-value {{ color: #333; font-size: 1.1em; }}
        .issue {{ 
            padding: 15px;
            margin: 10px 0;
            background: white;
            border-radius: 6px;
            border-left: 4px solid #dc3545;
        }}
        .issue.critical {{ border-left-color: #dc3545; }}
        .issue.high {{ border-left-color: #fd7e14; }}
        .issue.medium {{ border-left-color: #ffc107; }}
        .issue.low {{ border-left-color: #28a745; }}
        .issue-title {{ font-weight: bold; color: #333; margin-bottom: 5px; }}
        .issue-desc {{ color: #666; font-size: 0.95em; }}
        .recommendations {{ 
            list-style: none;
            padding: 0;
        }}
        .recommendations li {{ 
            padding: 12px;
            margin: 8px 0;
            background: white;
            border-radius: 6px;
            border-left: 3px solid #28a745;
        }}
        .recommendations li:before {{ 
            content: "✓ ";
            color: #28a745;
            font-weight: bold;
            margin-right: 8px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 HuggingFace Security Scan Report</h1>
        <div class="subtitle">Model: {scan_result.model_id}</div>
        <div class="subtitle">Scanned: {scan_result.scan_timestamp}</div>
        
        <div class="risk-badge">
            Risk Score: {scan_result.overall_risk_score:.2f}/10.0 ({risk_level.upper()})
        </div>
        
        <div class="section">
            <h2>📊 Model Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Author</div>
                    <div class="info-value">{scan_result.model_info.get('author', 'Unknown')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Downloads</div>
                    <div class="info-value">{scan_result.model_info.get('downloads', 0):,}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Likes</div>
                    <div class="info-value">{scan_result.model_info.get('likes', 0)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">License</div>
                    <div class="info-value">{scan_result.model_info.get('license', 'Not specified')}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>📁 File Analysis</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Total Files</div>
                    <div class="info-value">{scan_result.file_analysis.get('total_files', 0)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Suspicious Files</div>
                    <div class="info-value">{scan_result.file_analysis.get('suspicious_files', 0)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Risk Score</div>
                    <div class="info-value">{scan_result.file_analysis.get('risk_score', 0):.2f}/10</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ Security Issues ({len(scan_result.security_issues)})</h2>
"""
        
        # Add issues
        for issue in scan_result.security_issues[:20]:  # Limit to 20
            severity = issue.get('severity', 'unknown')
            html += f"""
            <div class="issue {severity}">
                <div class="issue-title">[{severity.upper()}] {issue.get('title', 'Unknown')}</div>
                <div class="issue-desc">{issue.get('description', '')}</div>
            </div>
"""
        
        if len(scan_result.security_issues) > 20:
            html += f"<p>... and {len(scan_result.security_issues) - 20} more issues</p>"
        
        html += """
        </div>
        
        <div class="section">
            <h2>💡 Recommendations</h2>
            <ul class="recommendations">
"""
        
        for rec in scan_result.recommendations[:15]:  # Limit to 15
            html += f"                <li>{rec}</li>\n"
        
        html += """
            </ul>
        </div>
    </div>
</body>
</html>
"""
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(html)
            logger.info(f"HTML report saved to: {output_path}")
        
        return html