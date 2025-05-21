"""
Utility functions for SAP audit log analysis.
"""

import os
import json
import pandas as pd
import re
from datetime import datetime
import traceback

# Default paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Default file paths
DEFAULT_REPORT_PATH = os.path.join(OUTPUT_DIR, "SAP_Audit_Report.xlsx")
DEFAULT_ANALYSIS_PATH = os.path.join(OUTPUT_DIR, "SAP_Audit_Analysis.html")
DEFAULT_SUMMARY_PATH = os.path.join(OUTPUT_DIR, "SAP_Audit_Summary.txt")
DEFAULT_METADATA_PATH = os.path.join(OUTPUT_DIR, "SAP_Audit_Metadata.json")

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def load_audit_report(report_path=DEFAULT_REPORT_PATH):
    """
    Load the SAP Audit Report Excel file.
    Returns a dictionary of DataFrames, one per sheet.
    """
    try:
        log_message(f"Loading audit report: {report_path}")
        
        # Read all sheets into a dictionary of DataFrames
        sheets = pd.read_excel(report_path, sheet_name=None)
        
        log_message(f"Loaded audit report with {len(sheets)} sheets")
        
        # Extract the main sheets we need
        result = {
            "timeline": sheets.get("Session_Timeline", pd.DataFrame()),
            "debug": sheets.get("Debug_Activities", pd.DataFrame())
        }
        
        # Check if we have the expected data
        if result["timeline"].empty:
            log_message("Warning: Session_Timeline sheet is empty or missing", "WARNING")
        
        log_message(f"Loaded {len(result['timeline'])} timeline events")
        
        return result
    
    except Exception as e:
        log_message(f"Error loading audit report: {str(e)}", "ERROR")
        log_message(traceback.format_exc(), "ERROR")
        return {"timeline": pd.DataFrame(), "debug": pd.DataFrame()}

def extract_field_value(text, field):
    """
    Extract a field value from a risk description text.
    Example: extract_field_value("User: ADMIN, TCode: SE16", "TCode") would return "SE16"
    """
    if not text or not isinstance(text, str):
        return ""
        
    match = re.search(rf"{field}:\s*([^,\s]+)", text, re.IGNORECASE)
    return match.group(1) if match else ""

def load_sysaid_data(sysaid_path=None):
    """
    Load the SysAid ticket data from Excel
    Returns a DataFrame of ticket information
    """
    if sysaid_path is None:
        sysaid_path = os.path.join(SCRIPT_DIR, "input", "SysAid.xlsx")
    
    try:
        log_message(f"Loading SysAid data from: {sysaid_path}")
        
        # Read the Excel file
        sysaid_df = pd.read_excel(sysaid_path)
        
        log_message(f"Loaded {len(sysaid_df)} SysAid tickets")
        
        # Ensure ticket numbers are strings for consistent joining
        if 'Ticket' in sysaid_df.columns:
            sysaid_df['Ticket'] = sysaid_df['Ticket'].astype(str)
        
        return sysaid_df
    
    except Exception as e:
        log_message(f"Error loading SysAid data: {str(e)}", "ERROR")
        log_message(traceback.format_exc(), "ERROR")
        return pd.DataFrame()
