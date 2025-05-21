#!/usr/bin/env python3
"""
Quick script to run the SAP Audit Analyzer with proper output paths
"""

import os
import sys
from sap_audit_analyzer import analyze_report

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")

# Make sure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Input file
REPORT_FILE = os.path.join(OUTPUT_DIR, "SAP_Audit_Report.xlsx")

# Output files
TEXT_SUMMARY_FILE = os.path.join(OUTPUT_DIR, "SAP_Audit_Summary.txt")
HTML_REPORT_FILE = os.path.join(OUTPUT_DIR, "SAP_Audit_Analysis.html")
METADATA_FILE = os.path.join(OUTPUT_DIR, "SAP_Audit_Metadata.json")

# Run the analysis if the report file exists
if os.path.exists(REPORT_FILE):
    print(f"Analyzing report: {REPORT_FILE}")
    analyze_report(
        report_path=REPORT_FILE,
        summary_path=TEXT_SUMMARY_FILE,
        analysis_path=HTML_REPORT_FILE,
        metadata_path=METADATA_FILE
    )
    print(f"\nAnalysis complete")
    print(f"Text summary: {TEXT_SUMMARY_FILE}")
    print(f"HTML report: {HTML_REPORT_FILE}")
else:
    print(f"Error: Report file not found at {REPORT_FILE}")
    sys.exit(1)
