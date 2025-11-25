# src/hf_security_scanner/cli/main.py
"""
Command Line Interface for Hugging Face Security Scanner.
"""

import click
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from ..scanner.model_scanner import ModelScanner
from ..reporting.report_generator import ReportGenerator
from ..utils.logger import setup_logger, get_logger

logger = get_logger(__name__)

@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
def cli(verbose: bool, config: Optional[str]):
    """Hugging Face Security Scanner CLI"""
    setup_logger(level='DEBUG' if verbose else 'INFO')
    
    if config:
        # Load configuration from file
        pass

@cli.command()
@click.argument('model_id')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'text']), default='text', help='Report format')
@click.option('--timeout', type=int, default=30, help='API timeout in seconds')
def scan(model_id: str, output: Optional[str], format: str, timeout: int):
    """Scan a single Hugging Face model."""
    
    click.echo(f"🔍 Scanning model: {model_id}")
    
    try:
        # Initialize scanner
        scanner = ModelScanner(timeout=timeout)
        
        # Perform scan
        result = scanner.scan_model(model_id)
        
        # Generate report
        report_gen = ReportGenerator()
        
        if format == 'json':
            report = report_gen.generate_json_report(result, output)
            if not output:
                click.echo(report)
        elif format == 'html':
            if not output:
                output = f"{model_id.replace('/', '_')}_report.html"
            report_gen.generate_html_report(result, output)
            click.echo(f"📊 HTML report saved to: {output}")
        else:  # text
            report = report_gen.generate_text_report(result)
            if output:
                with open(output, 'w') as f:
                    f.write(report)
                click.echo(f"📄 Text report saved to: {output}")
            else:
                click.echo(report)
        
        click.echo(f"\n✅ Scan completed successfully!")
        click.echo(f"🎯 Risk Score: {result.overall_risk_score:.1f}/10.0")
        
        if result.overall_risk_score >= 7.0:
            click.echo(click.style("⚠️  HIGH RISK detected!", fg='red', bold=True))
        elif result.overall_risk_score >= 3.0:
            click.echo(click.style("⚠️  Medium risk detected", fg='yellow', bold=True))
        else:
            click.echo(click.style("✅ Low risk", fg='green', bold=True))
            
    except Exception as e:
        click.echo(click.style(f"❌ Error: {str(e)}", fg='red'), err=True)
        sys.exit(1)

@cli.command()
@click.argument('model_ids', nargs=-1, required=True)
@click.option('--output', '-o', type=click.Path(), help='Output directory')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'text']), default='html', help='Report format')
@click.option('--workers', '-w', type=int, default=4, help='Number of concurrent workers')
@click.option('--timeout', type=int, default=30, help='API timeout in seconds')
def batch(model_ids: List[str], output: Optional[str], format: str, workers: int, timeout: int):
    """Scan multiple Hugging Face models."""
    
    click.echo(f"🔍 Batch scanning {len(model_ids)} models")
    
    try:
        # Initialize scanner
        scanner = ModelScanner(max_workers=workers, timeout=timeout)
        
        # Perform batch scan
        results = scanner.scan_models_batch(list(model_ids))
        
        # Set up output directory
        if not output:
            output = "reports"
        os.makedirs(output, exist_ok=True)
        
        # Generate individual reports
        report_gen = ReportGenerator()
        
        for result in results:
            safe_name = result.model_id.replace('/', '_')
            if format == 'json':
                filepath = os.path.join(output, f"{safe_name}_report.json")
                report_gen.generate_json_report(result, filepath)
            elif format == 'html':
                filepath = os.path.join(output, f"{safe_name}_report.html")
                report_gen.generate_html_report(result, filepath)
            else:  # text
                filepath = os.path.join(output, f"{safe_name}_report.txt")
                report = report_gen.generate_text_report(result)
                with open(filepath, 'w') as f:
                    f.write(report)
        
        click.echo(f"\n✅ Batch scan completed!")
        click.echo(f"📊 {len(results)} reports generated in: {output}/")
        
        # Show summary
        avg_risk = sum(r.overall_risk_score for r in results) / len(results) if results else 0
        high_risk_count = sum(1 for r in results if r.overall_risk_score >= 7.0)
        
        click.echo(f"📈 Average risk score: {avg_risk:.1f}/10.0")
        click.echo(f"⚠️  High risk models: {high_risk_count}/{len(results)}")
        
    except Exception as e:
        click.echo(click.style(f"❌ Error: {str(e)}", fg='red'), err=True)
        sys.exit(1)

@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output directory for reports')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'csv']), default='html', help='Report format')
@click.option('--workers', '-w', type=int, default=4, help='Number of concurrent workers')
@click.option('--no-download', is_flag=True, help='Skip file download and analysis')
@click.option('--timeout', type=int, default=30, help='API timeout in seconds')
def scan_file(input_file: str, output: Optional[str], format: str, workers: int, no_download: bool, timeout: int):
    """Scan models listed in a file."""
    
    try:
        # Read model IDs from file
        with open(input_file, 'r') as f:
            model_ids = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        click.echo(f"📋 Found {len(model_ids)} models in {input_file}")
        
        # Use batch scan functionality
        ctx = click.get_current_context()
        ctx.invoke(batch, 
                  model_ids=model_ids,
                  output=output,
                  format=format,
                  workers=workers,
                  no_download=no_download,
                  timeout=timeout)
        
    except Exception as e:
        click.echo(click.style(f"❌ Error reading file: {str(e)}", fg='red'), err=True)
        sys.exit(1)

@cli.command()
@click.option('--output', '-o', type=click.Path(), default='config', help='Output directory')
def init_config(output: str):
    """Initialize default configuration files."""
    
    try:
        os.makedirs(output, exist_ok=True)
        
        # Create default scanner configuration
        scanner_config = {
            "max_workers": 4,
            "timeout": 30,
            "download_files": True,
            "temp_dir": "temp_scans",
            "risk_thresholds": {
                "low": 0.0,
                "medium": 3.0,
                "high": 7.0
            }
        }
        
        config_path = os.path.join(output, "scanner_config.yaml")
        with open(config_path, 'w') as f:
            import yaml
            yaml.dump(scanner_config, f, default_flow_style=False)
        
        # Create security rules template
        rules_config = {
            "malicious_file_patterns": [
                {"pattern": r"\.(exe|msi|bat)$", "severity": "critical"},
                {"pattern": r"setup\.", "severity": "high"}
            ],
            "license_restrictions": [
                "all_rights_reserved",
                "copyright"
            ],
            "dangerous_keywords": [
                "malware", "exploit", "backdoor"
            ]
        }
        
        rules_path = os.path.join(output, "security_rules.yaml")
        with open(rules_path, 'w') as f:
            import yaml
            yaml.dump(rules_config, f, default_flow_style=False)
        
        click.echo(f"✅ Configuration files created in {output}/")
        click.echo(f"📄 Scanner config: {config_path}")
        click.echo(f"📄 Security rules: {rules_path}")
        
    except Exception as e:
        click.echo(click.style(f"❌ Error: {str(e)}", fg='red'), err=True)
        sys.exit(1)

if __name__ == "__main__":
    cli()