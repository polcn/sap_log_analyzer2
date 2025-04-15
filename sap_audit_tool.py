#!/usr/bin/env python3
"""
SAP Audit Tool - Main Script

This script ties together the modular components of the SAP Audit Tool:
1. Checks if session timeline exists
2. If not, calls SAP Log Session Merger functionality
3. Applies risk assessment
4. Generates output

Usage:
  python sap_audit_tool.py [input_dir] [output_file]

Dependencies:
  - sap_audit_tool_risk_assessment.py
  - sap_audit_tool_output.py
  - SAP Log Session Merger.py (functionality)
"""

import sys
import os
import time
import subprocess
from datetime import datetime
import pandas as pd

# Import modules for risk assessment and output generation
try:
    from sap_audit_tool_risk_assessment import (
        get_sensitive_tables, get_critical_field_patterns, get_sensitive_tcodes,
        assess_risk_session, custom_field_risk_assessment, log_message
    )
    from sap_audit_tool_output import generate_excel_output
    print("Using SAP Audit Risk Assessment module")
except ImportError:
    print("Error: Required modules not found. Please ensure sap_audit_tool_risk_assessment.py and sap_audit_tool_output.py are in the same directory.")
    sys.exit(1)

# --- Configuration ---
VERSION = "4.1.0"  # Updated for Field Description System enhancements (April 2025)

# Get the script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
print(f"Script directory: {SCRIPT_DIR}")
print(f"Current working directory: {os.getcwd()}")

# File paths - can be overridden via command line arguments
if len(sys.argv) > 2:
    INPUT_DIR = sys.argv[1]
    OUTPUT_FILE = sys.argv[2]
else:
    # Default paths
    INPUT_DIR = os.path.join(SCRIPT_DIR, "input")
    OUTPUT_FILE = os.path.join(SCRIPT_DIR, "SAP_Audit_Report.xlsx")

# Session timeline file (produced by session merger)
SESSION_TIMELINE_FILE = os.path.join(SCRIPT_DIR, "SAP_Session_Timeline.xlsx")

# Session Timeline columns (from SAP Log Session Merger)
SESSION_ID_COL = 'Session ID'
SESSION_ID_WITH_DATE_COL = 'Session ID with Date'
SESSION_USER_COL = 'User'
SESSION_DATETIME_COL = 'Datetime'
SESSION_SOURCE_COL = 'Source'
SESSION_TCODE_COL = 'TCode'
SESSION_TABLE_COL = 'Table'
SESSION_FIELD_COL = 'Field'
SESSION_CHANGE_IND_COL = 'Change_Indicator'
SESSION_OLD_VALUE_COL = 'Old_Value'
SESSION_NEW_VALUE_COL = 'New_Value'
SESSION_DESCRIPTION_COL = 'Description'
SESSION_OBJECT_COL = 'Object'
SESSION_OBJECT_ID_COL = 'Object_ID'
SESSION_DOC_NUMBER_COL = 'Doc_Number'

def load_session_timeline():
    """
    Load the session timeline Excel file produced by the SAP Log Session Merger.
    Returns the DataFrame if successful, None otherwise.
    """
    try:
        # Check if the session timeline file exists
        if not os.path.exists(SESSION_TIMELINE_FILE):
            log_message(f"Session timeline file not found: {SESSION_TIMELINE_FILE}", "WARNING")
            return None
            
        log_message(f"Loading session timeline from: {SESSION_TIMELINE_FILE}")
        
        # Load the Excel file
        timeline_df = pd.read_excel(SESSION_TIMELINE_FILE, sheet_name="Session_Timeline")
        
        # Verify required columns
        required_cols = [SESSION_ID_WITH_DATE_COL, SESSION_USER_COL, SESSION_DATETIME_COL, SESSION_SOURCE_COL]
        missing_cols = [col for col in required_cols if col not in timeline_df.columns]
        
        if missing_cols:
            log_message(f"Missing required columns in session timeline: {', '.join(missing_cols)}", "WARNING")
            return None
            
        log_message(f"Loaded session timeline with {len(timeline_df)} records")
        return timeline_df
        
    except Exception as e:
        log_message(f"Error loading session timeline: {str(e)}", "ERROR")
        return None

def prepare_session_data(timeline_df):
    """
    Prepare the session timeline data for risk assessment.
    Adds necessary columns and flags for analysis.
    """
    log_message("Preparing session timeline data for analysis...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        df = timeline_df.copy()
        
        # Ensure datetime column is datetime type
        if SESSION_DATETIME_COL in df.columns:
            df[SESSION_DATETIME_COL] = pd.to_datetime(df[SESSION_DATETIME_COL], errors='coerce')
            
        # Add a column to identify display-only activities (for SM20 entries)
        if SESSION_DESCRIPTION_COL in df.columns:
            df['is_display_only'] = df[SESSION_DESCRIPTION_COL].str.contains(
                r'DISPLAY|READ|VIEW|SHOW|REPORT|LIST',
                case=False,
                regex=True
            )
        else:
            df['is_display_only'] = False
            
        # Add a column to identify actual changes (for CDPOS entries)
        if SESSION_CHANGE_IND_COL in df.columns:
            df['is_actual_change'] = df[SESSION_CHANGE_IND_COL].isin(['I', 'U', 'D'])
        else:
            df['is_actual_change'] = False
            
        # Identify special case: SM20 shows display but CDPOS indicates changes
        if 'is_display_only' in df.columns and 'is_actual_change' in df.columns:
            df['display_but_changed'] = df['is_display_only'] & df['is_actual_change']
        else:
            df['display_but_changed'] = False
            
        log_message(f"Session timeline data prepared. {len(df)} entries.")
        return df
        
    except Exception as e:
        log_message(f"Error preparing session timeline data: {str(e)}", "ERROR")
        return timeline_df

def run_session_merger():
    """Run the SAP Log Session Merger script to create a session timeline."""
    log_message("Running SAP Log Session Merger...")
    
    try:
        # Check if the merger script exists
        merger_script = os.path.join(SCRIPT_DIR, "SAP Log Session Merger.py")
        if not os.path.exists(merger_script):
            log_message(f"Session merger script not found: {merger_script}", "ERROR")
            return False
        
        # Run the merger script
        result = subprocess.run(
            [sys.executable, merger_script],
            capture_output=True,
            text=True
        )
        
        # Check if the script ran successfully
        if result.returncode == 0:
            log_message("Session merger completed successfully")
            
            # Check if the output file was created
            if os.path.exists(SESSION_TIMELINE_FILE):
                log_message(f"Session timeline created: {SESSION_TIMELINE_FILE}")
                return True
            else:
                log_message("Session merger did not create a timeline file", "WARNING")
                return False
        else:
            log_message(f"Session merger failed with error: {result.stderr}", "ERROR")
            return False
    
    except Exception as e:
        log_message(f"Error running session merger: {str(e)}", "ERROR")
        return False

# --- Main Function ---
def main():
    """Main function to execute the SAP audit analysis."""
    start_time = time.time()
    log_message(f"Starting SAP Audit Tool v{VERSION}...")
    
    try:
        # Step 1: Check if session timeline file exists
        session_df = load_session_timeline()
        
        # If session timeline doesn't exist, run the session merger
        if session_df is None:
            log_message("No session timeline found. Running session merger...")
            if run_session_merger():
                # Try loading the session timeline again
                session_df = load_session_timeline()
            else:
                log_message("Failed to create session timeline. Exiting.", "ERROR")
                return False
        
        # If we still don't have a session timeline, exit
        if session_df is None:
            log_message("No session timeline available. Exiting.", "ERROR")
            return False
        
        # Step 2: Prepare session data
        session_df = prepare_session_data(session_df)
        
        # Step 3: Apply risk assessment to session data
        log_message("Applying risk assessment to session timeline...")
        try:
            session_df = assess_risk_session(session_df)
        except Exception as e:
            log_message(f"Error applying risk assessment to session timeline: {str(e)}", "ERROR")
            # Create empty risk columns to avoid errors later
            session_df.loc[:, "risk_level"] = "Unknown"
            session_df.loc[:, "risk_factors"] = "Risk assessment failed"
        
        # Step 4: Generate Excel output with session data
        # Sort chronologically by session ID first, then by timestamp within session, then by risk level
        # Extract the numeric part of session IDs for proper numerical sorting
        log_message("Preparing chronological sorting...")
        
        # Extract Session IDs from "Session ID with Date" format (e.g., "S0001 (2025-04-10)")
        session_df['Session_ID_Numeric'] = session_df[SESSION_ID_WITH_DATE_COL].str.extract(r'S(\d+)').astype(int)
        
        # Create a risk level sort key (High=0, Medium=1, Low=2, Unknown=3)
        session_df['Risk_Sort'] = session_df['risk_level'].map({'High': 0, 'Medium': 1, 'Low': 2, 'Unknown': 3})
        
        # Sort by numerical session ID, then by timestamp within session, then by risk level
        session_df = session_df.sort_values(['Session_ID_Numeric', SESSION_DATETIME_COL, 'Risk_Sort'], 
                                           ascending=[True, True, True])
        
        # Drop the temporary columns used for sorting
        session_df = session_df.drop(['Session_ID_Numeric', 'Risk_Sort'], axis=1)
        
        log_message("Sorting complete. Data ordered chronologically by session number.")
        
        # Generate Excel output with session data (empty dataframes for legacy mode)
        generate_excel_output(pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), session_df, OUTPUT_FILE)
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        log_message(f"Processing complete in {elapsed_time:.2f} seconds.")
        
        log_message(f"Audit report saved to: {os.path.abspath(OUTPUT_FILE)}")
        print(f"\nAudit report saved to: {os.path.abspath(OUTPUT_FILE)}")
        
        return True
    
    except Exception as e:
        log_message(f"Error in main execution: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return False

if __name__ == "__main__":
    # Add a banner
    banner = "\n" + "="*80 + "\n"
    banner += " SAP AUDIT TOOL v{} ".format(VERSION).center(80, "*") + "\n"
    banner += " Enhanced Security Analysis for SAP Logs ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)
    
    main()
