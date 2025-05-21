#!/usr/bin/env python3
"""
SAP Audit Analyzer

This module automatically analyzes the output of the SAP Audit Tool to provide:
1. A summary of high-risk activities
2. Specific items requiring follow-up with clear explanations
3. Performance metrics comparing detection improvements across runs
4. Detailed recommendations for security investigation

This analyzer is designed to run as the final step in the audit process,
providing immediate insights without requiring manual review.
"""

import os
import sys
import json
import pandas as pd
from datetime import datetime
from collections import Counter, defaultdict
import re
import traceback

# --- Configuration ---
VERSION = "1.0.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")

# Make sure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Default file paths (now in output directory)
DEFAULT_REPORT_PATH = os.path.join(OUTPUT_DIR, "SAP_Audit_Report.xlsx")
DEFAULT_ANALYSIS_PATH = os.path.join(OUTPUT_DIR, "SAP_Audit_Analysis.html")
DEFAULT_SUMMARY_PATH = os.path.join(OUTPUT_DIR, "SAP_Audit_Summary.txt")
DEFAULT_METADATA_PATH = os.path.join(OUTPUT_DIR, "SAP_Audit_Metadata.json")

# Risk levels in order of severity
RISK_LEVELS = ["Critical", "High", "Medium", "Low"]

# Specific patterns to look for in risk descriptions
HIGH_INTEREST_PATTERNS = {
    "authorization_bypass": {
        "pattern": r"authorization bypass|auth.*bypass|bypass.*auth",
        "description": "Potential authorization control bypass",
        "recommendation": "Investigate user activity to determine if authorization controls were compromised"
    },
    "stealth_changes": {
        "pattern": r"stealth change|unlogged change|change.*no.*record|potential unlogged",
        "description": "Changes with potentially missing audit trail",
        "recommendation": "Verify if actual data changes occurred and why they weren't properly logged"
    },
    "debug_with_changes": {
        "pattern": r"debug.*change|change.*debug|debugging.*followed by|during debugging session",
        "description": "Debugging tools used in conjunction with data changes",
        "recommendation": "Review the specific changes made during debugging to verify legitimacy"
    },
    "dynamic_abap": {
        "pattern": r"dynamic ABAP|BU4|custom code execution|ran custom code",
        "description": "Dynamic ABAP code execution (high-risk activity)",
        "recommendation": "Review the specific code that was executed to verify it wasn't malicious"
    },
    "inventory_manipulation": {
        "pattern": r"inventory.*manipulation|inventory.*debug|inventory.*fraud",
        "description": "Inventory data manipulation with debugging tools",
        "recommendation": "Investigate inventory records for integrity and compare with physical counts"
    },
    "se16_with_changes": {
        "pattern": r"SE16.*change|change.*SE16|table browser.*change",
        "description": "Direct table manipulation via SE16",
        "recommendation": "Verify business justification for direct table access"
    }
}

# --- Utility Functions ---
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

def load_metadata(metadata_path=DEFAULT_METADATA_PATH):
    """
    Load metadata from previous runs.
    Returns an empty dict if no metadata exists.
    """
    try:
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        log_message(f"Error loading metadata: {str(e)}", "WARNING")
        return {}

def save_metadata(metadata, metadata_path=DEFAULT_METADATA_PATH):
    """
    Save run metadata for future comparison.
    """
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(metadata_path), exist_ok=True)
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        log_message(f"Saved run metadata to {metadata_path}")
    except Exception as e:
        log_message(f"Error saving metadata: {str(e)}", "WARNING")

def extract_field_value(text, field):
    """
    Extract a field value from a risk description text.
    Example: extract_field_value("User: ADMIN, TCode: SE16", "TCode") would return "SE16"
    """
    if not text or not isinstance(text, str):
        return ""
        
    match = re.search(rf"{field}:\s*([^,\s]+)", text, re.IGNORECASE)
    return match.group(1) if match else ""

# --- Analysis Functions ---
def analyze_risk_distribution(df):
    """
    Analyze the distribution of risk levels in the timeline.
    """
    if df.empty or 'risk_level' not in df.columns:
        return {"error": "No risk level data found"}
    
    # Count risk levels
    risk_counts = df['risk_level'].value_counts().to_dict()
    
    # Ensure all risk levels are represented
    for level in RISK_LEVELS:
        if level not in risk_counts:
            risk_counts[level] = 0
    
    # Calculate percentages
    total = len(df)
    risk_percentages = {level: (count / total * 100) for level, count in risk_counts.items()}
    
    return {
        "counts": risk_counts,
        "percentages": risk_percentages,
        "total": total
    }

def analyze_high_risk_items(df):
    """
    Analyze high-risk items requiring follow-up.
    """
    if df.empty:
        return []
    
    # Filter for high and critical risk items
    high_risk_df = df[df['risk_level'].isin(['Critical', 'High'])]
    
    if high_risk_df.empty:
        return []
    
    # Group high risk items by pattern of interest
    findings = []
    
    for category, pattern_info in HIGH_INTEREST_PATTERNS.items():
        pattern = pattern_info["pattern"]
        # Find items matching this pattern
        matches = high_risk_df[high_risk_df['risk_description'].str.contains(
            pattern, case=False, regex=True, na=False)]
        
        if not matches.empty:
            # Get top examples based on session and user
            examples = []
            
            # Group by session and user to find distinct patterns
            if 'Session ID with Date' in matches.columns and 'User' in matches.columns:
                for (session, user), group in matches.groupby(['Session ID with Date', 'User']):
                    # Get the first example from each session/user combination
                    row = group.iloc[0]
                    
                    # Extract key fields with proper NaN handling
                    tcode = row.get('TCode', 'N/A')
                    table = row.get('Table', 'N/A')
                    event = row.get('Event', 'N/A')
                    
                    # Handle NaN values
                    if pd.isna(tcode):
                        tcode = 'N/A'
                    if pd.isna(table):
                        table = 'N/A'
                    if pd.isna(event):
                        event = 'N/A'
                    
                    # Create a concise example
                    example = {
                        "session": session,
                        "user": user,
                        "tcode": tcode,
                        "table": table,
                        "event": event,
                        "risk_level": row.get('risk_level', 'N/A'),
                        "description": row.get('risk_description', 'N/A')
                    }
                    examples.append(example)
            
            # Add finding with examples
            finding = {
                "category": category,
                "description": pattern_info["description"],
                "recommendation": pattern_info["recommendation"],
                "count": len(matches),
                "examples": examples[:3]  # Limit to top 3 examples
            }
            findings.append(finding)
    
    # Sort findings by count (highest first)
    return sorted(findings, key=lambda x: x["count"], reverse=True)

def analyze_key_users(df):
    """
    Analyze key users with suspicious activities.
    """
    if df.empty or 'User' not in df.columns:
        return []
