#!/usr/bin/env python3
"""
SAP Analyzer Runner

A standalone script to demonstrate using the new SAP Analyzer package.
This script analyzes SAP audit logs and generates reports with SysAid ticket integration.
"""

import os
import sys
import argparse
from datetime import datetime

# Add script directory to path to ensure imports work correctly
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    # Import the SAP Analyzer package
    from sap_analyzer.utils import log_message
    from sap_analyzer.run import run_analysis
    ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"Error: SAP Analyzer package not available: {str(e)}")
    ANALYZER_AVAILABLE = False
    sys.exit(1)

def main():
    """Main function to parse arguments and run the analyzer."""
    parser = argparse.ArgumentParser(description='Run SAP Audit Analysis with SysAid Integration')
    
    # Add command line arguments
    parser.add_argument('--report', help='Path to the SAP Audit Report Excel file')
    parser.add_argument('--output', help='Output directory for analysis files')
    parser.add_argument('--sysaid', help='Path to the SysAid ticket data file')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Set up default paths if not provided
    report_path = args.report
    if not report_path:
        report_path = os.path.join(SCRIPT_DIR, "output", "SAP_Audit_Report.xlsx")
        if not os.path.exists(report_path):
            print(f"No report found at default location: {report_path}")
            print("Please specify a report file with --report")
            return False
    
    output_dir = args.output
    if not output_dir:
        output_dir = os.path.join(SCRIPT_DIR, "output")
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    summary_path = os.path.join(output_dir, "SAP_Audit_Summary.txt")
    analysis_path = os.path.join(output_dir, "SAP_Audit_Analysis.html")
    metadata_path = os.path.join(output_dir, "SAP_Audit_Metadata.json")
    
    # Set up SysAid path if not provided
    sysaid_path = args.sysaid
    if not sysaid_path:
        default_sysaid = os.path.join(SCRIPT_DIR, "input", "SysAid.xlsx")
        if os.path.exists(default_sysaid):
            sysaid_path = default_sysaid
            log_message(f"Using SysAid data from {sysaid_path}")
        else:
            log_message("No SysAid data file found. Proceeding without ticket integration.", "WARNING")
    
    # Display run information
    print("\n" + "="*80)
    print(" SAP ANALYZER ".center(80, "*"))
    print(" Advanced Analysis for SAP Audit Logs ".center(80))
    print("="*80 + "\n")
    
    print(f"Report file:  {report_path}")
    print(f"Output dir:   {output_dir}")
    if sysaid_path:
        print(f"SysAid data:  {sysaid_path}")
    else:
        print("SysAid data:  Not provided")
    print(f"Summary file: {summary_path}")
    print(f"HTML report:  {analysis_path}")
    print(f"Metadata:     {metadata_path}")
    print("\n" + "-"*80 + "\n")
    
    # Run the analysis
    start_time = datetime.now()
    log_message("Starting SAP Audit Analysis...")
    
    try:
        result = run_analysis(
            report_path=report_path,
            summary_path=summary_path,
            analysis_path=analysis_path,
            metadata_path=metadata_path,
            sysaid_path=sysaid_path
        )
        
        # Check for errors
        if "error" in result:
            log_message(f"Error in analysis: {result['error']}", "ERROR")
            return False
        
        # Print success message
        elapsed_time = (datetime.now() - start_time).total_seconds()
        print("\n" + "-"*80)
        print(f"Analysis completed in {elapsed_time:.2f} seconds")
        print(f"Text summary: {result['summary_file']}")
        print(f"HTML report:  {result['html_file']}")
        
        # Print some key findings
        findings = result.get("findings", {})
        risk_distribution = findings.get("risk_distribution", {})
        high_risk_items = findings.get("high_risk_items", [])
        
        if risk_distribution:
            print("\nRisk Distribution:")
            risk_counts = risk_distribution.get("counts", {})
            for level in ["Critical", "High", "Medium", "Low"]:
                count = risk_counts.get(level, 0)
                print(f"  {level}: {count}")
        
        if high_risk_items:
            print("\nHigh Priority Follow-up Items:")
            for i, item in enumerate(high_risk_items[:3]):  # Top 3 items
                print(f"  {i+1}. {item['description']} ({item['count']} occurrences)")
        
        print("\n" + "="*80)
        return True
        
    except Exception as e:
        log_message(f"Error running analysis: {str(e)}", "ERROR")
        import traceback
        log_message(traceback.format_exc(), "ERROR")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
