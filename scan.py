#!/usr/bin/env python3
"""
HF Security Scanner CLI - Direct execution without package installation
Usage: python3 scan.py <model_id> [options]
"""

import sys
import os

# Add src to path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from hf_security_scanner.scanner.model_scanner import ModelScanner
from hf_security_scanner.reporting.report_generator import ReportGenerator
import argparse


def main():
    parser = argparse.ArgumentParser(description='Scan HuggingFace models for security issues')
    parser.add_argument('model_id', help='HuggingFace model ID (e.g., gpt2, bert-base-uncased)')
    parser.add_argument('--format', '-f', choices=['text', 'json', 'html'], default='text',
                        help='Report format (default: text)')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--token', help='HuggingFace API token (optional)')
    
    args = parser.parse_args()
    
    print(f"🔍 Scanning model: {args.model_id}")
    print("=" * 80)
    
    try:
        # Initialize scanner
        scanner = ModelScanner(token=args.token or os.getenv('HF_TOKEN'))
        
        # Perform scan
        result = scanner.scan_model(args.model_id)
        
        # Generate report
        report_gen = ReportGenerator()
        
        if args.format == 'json':
            report = report_gen.generate_json_report(result, args.output)
            if not args.output:
                print(report)
            else:
                print(f"\n✅ JSON report saved to: {args.output}")
        elif args.format == 'html':
            output_path = args.output or f"{args.model_id.replace('/', '_')}_report.html"
            report_gen.generate_html_report(result, output_path)
            print(f"\n✅ HTML report saved to: {output_path}")
        else:  # text
            report = report_gen.generate_text_report(result)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"\n✅ Text report saved to: {args.output}")
            else:
                print(report)
        
        print(f"\n🎯 Risk Score: {result.overall_risk_score:.1f}/10.0")
        
        # Show risk level
        if result.overall_risk_score >= 7.0:
            print("⚠️  HIGH RISK detected!")
        elif result.overall_risk_score >= 3.0:
            print("⚠️  Medium risk detected")
        else:
            print("✅ Low risk")
            
    except Exception as e:
        print(f"\n❌ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
