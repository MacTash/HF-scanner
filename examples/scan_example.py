"""Example usage of the HF Security Scanner."""

from hf_security_scanner.scanner.model_scanner import ModelScanner
from hf_security_scanner.reporting.report_generator import ReportGenerator

def main():
    """Run a simple scan example."""
    
    # Initialize scanner
    scanner = ModelScanner()
    
    # Scan a popular model
    print("Scanning gpt2 model...")
    result = scanner.scan_model("gpt2")
    
    # Generate reports
    report_gen = ReportGenerator()
    
    # Print text report
    print("\n" + "="*80)
    print(report_gen.generate_text_report(result))
    
    # Save JSON report
    report_gen.generate_json_report(result, "gpt2_scan_report.json")
    print(f"\n✅ JSON report saved to: gpt2_scan_report.json")
    
    # Save HTML report
    report_gen.generate_html_report(result, "gpt2_scan_report.html")
    print(f"✅ HTML report saved to: gpt2_scan_report.html")
    

if __name__ == "__main__":
    main()
