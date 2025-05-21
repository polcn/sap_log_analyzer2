"""
Run functions for SAP Audit Analysis.

This module provides entry points for running the SAP Audit Analyzer
either standalone or from the main SAP Audit Tool.
"""

import os
import sys
from datetime import datetime

from .utils import (
    log_message, load_audit_report, load_sysaid_data,
    DEFAULT_REPORT_PATH, DEFAULT_ANALYSIS_PATH, DEFAULT_SUMMARY_PATH, DEFAULT_METADATA_PATH
)
from .analysis import (
    analyze_risk_distribution, analyze_high_risk_items,
    analyze_key_users, analyze_debug_activities, analyze_session_patterns,
    analyze_algorithm_improvements, enrich_with_sysaid_data
)
from .metadata import load_metadata, update_metadata
from .reporting import generate_text_summary, generate_html_report

def run_analysis(
    report_path=DEFAULT_REPORT_PATH,
    summary_path=DEFAULT_SUMMARY_PATH,
    analysis_path=DEFAULT_ANALYSIS_PATH,
    metadata_path=DEFAULT_METADATA_PATH,
    sysaid_path=None
):
    """
    Run the SAP audit analysis process as a standalone function.
    
    Args:
        report_path: Path to the SAP Audit Report Excel file
        summary_path: Path to save the text summary
        analysis_path: Path to save the HTML analysis report
        metadata_path: Path to the metadata JSON file
        sysaid_path: Path to the SysAid ticket Excel data (optional)
        
    Returns:
        A dictionary containing analysis results and output paths
    """
    start_time = datetime.now()
    log_message("Starting SAP Audit Analysis...")
    
    # Step 1: Load the audit report
    report_data = load_audit_report(report_path)
    
    if not report_data or report_data.get("timeline", None) is None or report_data["timeline"].empty:
        log_message("No data found in audit report or report could not be loaded", "ERROR")
        return {"error": "No data found in audit report"}
    
    # Step 2: Load SysAid data if provided and enrich the report data
    if sysaid_path:
        sysaid_df = load_sysaid_data(sysaid_path)
        if not sysaid_df.empty:
            log_message(f"Enriching audit data with {len(sysaid_df)} SysAid records")
            report_data = enrich_with_sysaid_data(report_data, sysaid_df)
    
    # Step 3: Perform various analyses
    timeline_df = report_data["timeline"]
    
    log_message("Analyzing risk distribution...")
    risk_distribution = analyze_risk_distribution(timeline_df)
    
    log_message("Analyzing high risk items...")
    high_risk_items = analyze_high_risk_items(timeline_df)
    
    log_message("Analyzing key users...")
    key_users = analyze_key_users(timeline_df)
    
    log_message("Analyzing debug activities...")
    debug_activities = analyze_debug_activities(report_data)
    
    log_message("Analyzing session patterns...")
    session_patterns = analyze_session_patterns(timeline_df)
    
    # Step 4: Load metadata and analyze improvements
    metadata = load_metadata(metadata_path)
    algorithm_improvements = analyze_algorithm_improvements(report_data, metadata)
    
    # Step 5: Update metadata with current run information
    update_metadata(report_data, metadata_path)
    
    # Step 6: Compile all findings
    findings = {
        "risk_distribution": risk_distribution,
        "high_risk_items": high_risk_items,
        "key_users": key_users,
        "debug_activities": debug_activities,
        "session_patterns": session_patterns,
        "algorithm_improvements": algorithm_improvements
    }
    
    # Step 7: Generate reports
    log_message("Generating text summary...")
    summary_file = generate_text_summary(report_data, findings, summary_path)
    
    log_message("Generating HTML report...")
    html_file = generate_html_report(report_data, findings, analysis_path)
    
    # Step 8: Return results
    elapsed_time = (datetime.now() - start_time).total_seconds()
    log_message(f"Analysis completed in {elapsed_time:.2f} seconds")
    
    return {
        "findings": findings,
        "summary_file": summary_file,
        "html_file": html_file,
        "elapsed_time": elapsed_time
    }

def run_analysis_from_audit_tool(excel_path=None, output_dir=None, sysaid_path=None):
    """
    Run the SAP audit analysis as part of the main SAP Audit Tool process.
    This function is called from the main sap_audit_tool.py script.
    
    Args:
        excel_path: Path to the generated Excel report (if not default)
        output_dir: Output directory for analysis files
        sysaid_path: Path to the SysAid ticket data file
        
    Returns:
        A dictionary containing analysis results and output paths
    """
    if output_dir is None:
        from .utils import OUTPUT_DIR
        output_dir = OUTPUT_DIR
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Set up paths
    report_path = excel_path if excel_path else os.path.join(output_dir, "SAP_Audit_Report.xlsx")
    summary_path = os.path.join(output_dir, "SAP_Audit_Summary.txt")
    analysis_path = os.path.join(output_dir, "SAP_Audit_Analysis.html")
    metadata_path = os.path.join(output_dir, "SAP_Audit_Metadata.json")
    
    # Run the analysis
    log_message("Running SAP Audit Analysis from Audit Tool...")
    result = run_analysis(
        report_path=report_path,
        summary_path=summary_path,
        analysis_path=analysis_path,
        metadata_path=metadata_path,
        sysaid_path=sysaid_path
    )
    
    # Log the results
    if "error" not in result:
        log_message("Analysis complete - reports generated:")
        log_message(f"  Text summary: {result['summary_file']}")
        log_message(f"  HTML report: {result['html_file']}")
    else:
        log_message(f"Analysis failed: {result['error']}", "ERROR")
    
    return result

if __name__ == "__main__":
    # If run directly, use default paths or command line arguments
    import argparse
    
    parser = argparse.ArgumentParser(description='Run SAP Audit Analysis')
    parser.add_argument('--report', help='Path to the SAP Audit Report Excel file')
    parser.add_argument('--output', help='Output directory for analysis files')
    parser.add_argument('--sysaid', help='Path to the SysAid ticket data file')
    
    args = parser.parse_args()
    
    # Set up paths
    report_path = args.report if args.report else DEFAULT_REPORT_PATH
    
    output_dir = args.output if args.output else os.path.dirname(DEFAULT_SUMMARY_PATH)
    os.makedirs(output_dir, exist_ok=True)
    
    summary_path = os.path.join(output_dir, os.path.basename(DEFAULT_SUMMARY_PATH))
    analysis_path = os.path.join(output_dir, os.path.basename(DEFAULT_ANALYSIS_PATH))
    metadata_path = os.path.join(output_dir, os.path.basename(DEFAULT_METADATA_PATH))
    
    # Run the analysis
    result = run_analysis(
        report_path=report_path,
        summary_path=summary_path,
        analysis_path=analysis_path,
        metadata_path=metadata_path,
        sysaid_path=args.sysaid
    )
    
    # Print results
    if "error" not in result:
        print("\nAnalysis complete! Reports generated:")
        print(f"  Text summary: {result['summary_file']}")
        print(f"  HTML report: {result['html_file']}")
    else:
        print(f"\nAnalysis failed: {result['error']}")
        sys.exit(1)
