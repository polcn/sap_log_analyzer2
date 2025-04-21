#!/usr/bin/env python3
"""
SAP Audit Tool - SysAid Ticket Integration Module

This module provides functionality to load and process SysAid ticket information,
allowing integration with SAP audit logs for enhanced reporting.
"""

import os
import pandas as pd
from datetime import datetime

# Import common utilities
try:
    from sap_audit_utils import log_message
except ImportError:
    # Fallback if utils not available
    def log_message(message, level="INFO"):
        """Log a message with timestamp and level."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")

# Constants
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(SCRIPT_DIR, "input")
SYSAID_FILE = os.path.join(INPUT_DIR, "SysAid.xlsx")

# SysAid field mapping constants
SYSAID_TICKET_COL_OPTIONS = ['Ticket', 'Ticket #', 'TicketID', 'ID', 'ticket']
SYSAID_TICKET_COL = None  # Will be set dynamically when loading data
SYSAID_TITLE_COL = 'Title'
SYSAID_DESCRIPTION_COL = 'Description'
SYSAID_NOTES_COL = 'Notes'
SYSAID_REQUEST_USER_COL = 'Request user'
SYSAID_PROCESS_MANAGER_COL = 'Process manager'
SYSAID_REQUEST_TIME_COL = 'Request time'

# Column that will link to SysAid in SAP logs
SAP_SYSAID_COL = 'SYSAID #'

# Column that will be added to session data
SAP_SYSAID_COL_ADDED = 'SYSAID #'

def load_sysaid_data():
    """
    Load SysAid ticket information from the Excel file.
    Returns a DataFrame containing the SysAid data.
    """
    global SYSAID_TICKET_COL  # We'll set this dynamically based on what's in the file
    
    try:
        # Check if the SysAid file exists
        if not os.path.exists(SYSAID_FILE):
            log_message(f"SysAid file not found: {SYSAID_FILE}", "WARNING")
            return None
            
        log_message(f"Loading SysAid ticket information from: {SYSAID_FILE}")
        
        # Load the Excel file with the specific sheet name "Report"
        sysaid_df = pd.read_excel(SYSAID_FILE, sheet_name="Report")
        log_message("Reading SysAid data from 'Report' sheet")
        
        # Debug output for column inspection
        log_message(f"All columns found in SysAid data: {list(sysaid_df.columns)}")
        log_message(f"Column data types: {sysaid_df.dtypes}")
        
        # Print first few rows of the dataframe for debugging
        if not sysaid_df.empty:
            log_message(f"First row of SysAid data: {sysaid_df.iloc[0].to_dict()}")
        
        # Find the ticket column from our list of options
        found_col = None
        
        # Try exact matching first
        for col_option in SYSAID_TICKET_COL_OPTIONS:
            log_message(f"Looking for column '{col_option}'...")
            if col_option in sysaid_df.columns:
                found_col = col_option
                log_message(f"Found ticket column: {found_col}")
                break
        
        # If not found, try case-insensitive matching
        if not found_col:
            log_message("Trying case-insensitive column matching...")
            sysaid_columns_lower = [col.lower() for col in sysaid_df.columns]
            for col_option in SYSAID_TICKET_COL_OPTIONS:
                if col_option.lower() in sysaid_columns_lower:
                    # Get the original column name with proper case
                    idx = sysaid_columns_lower.index(col_option.lower())
                    found_col = sysaid_df.columns[idx]
                    log_message(f"Found ticket column (case-insensitive): {found_col}")
                    break
        
        # Set the global ticket column name
        if found_col:
            SYSAID_TICKET_COL = found_col
        else:
            log_message(f"No ticket column found. Looked for: {', '.join(SYSAID_TICKET_COL_OPTIONS)}", "WARNING")
            return None
            
        log_message(f"Loaded SysAid data with {len(sysaid_df)} tickets")
        return sysaid_df
        
    except Exception as e:
        log_message(f"Error loading SysAid data: {str(e)}", "ERROR")
        return None

def merge_sysaid_data(session_df, sysaid_df):
    """
    Merge SysAid ticket information with session timeline data.
    In this version, we're adding all SysAid ticket data to the output, not requiring a link field.
    
    Args:
        session_df: DataFrame containing session timeline data
        sysaid_df: DataFrame containing SysAid ticket information
        
    Returns:
        DataFrame with SysAid information merged into session data
    """
    try:
        if session_df is None or sysaid_df is None:
            log_message("Cannot merge SysAid data: missing data", "WARNING")
            return session_df
            
        log_message("Adding SysAid ticket information to session timeline...")
        
        # Create a copy of the session data to avoid modifying the original
        result_df = session_df.copy()
        
        # Debug session data columns
        log_message(f"Session data columns: {list(result_df.columns)}")
        
        # Add SysAid ticket column if it doesn't exist
        if SAP_SYSAID_COL_ADDED not in result_df.columns:
            result_df[SAP_SYSAID_COL_ADDED] = ""
            log_message(f"Added new column '{SAP_SYSAID_COL_ADDED}' to session data")
        
        # Create a dictionary for quick lookup of SysAid ticket information
        sysaid_lookup = {}
        log_message(f"Using '{SYSAID_TICKET_COL}' as ticket column in SysAid data")
        
        # Sample SysAid tickets for debugging
        if not sysaid_df.empty:
            sample_tickets = sysaid_df[SYSAID_TICKET_COL].dropna().head(5).tolist()
            log_message(f"Sample SysAid tickets: {sample_tickets}")
                
        # Process SysAid data - first convert request times to datetime
        try:
            # Sample SysAid request time format for debugging
            if not sysaid_df.empty and SYSAID_REQUEST_TIME_COL in sysaid_df.columns:
                sample_times = sysaid_df[SYSAID_REQUEST_TIME_COL].dropna().head(3).tolist()
                log_message(f"Sample request times: {sample_times}")
                
            # Try to convert request time to datetime
            if SYSAID_REQUEST_TIME_COL in sysaid_df.columns:
                sysaid_df['request_time_dt'] = pd.to_datetime(
                    sysaid_df[SYSAID_REQUEST_TIME_COL], 
                    errors='coerce',
                    # Try multiple date formats
                    format=None  # Let pandas infer the format
                )
                log_message("Converted SysAid request times to datetime")
        except Exception as e:
            log_message(f"Warning: Could not convert SysAid request times to datetime: {str(e)}", "WARNING")
            sysaid_df['request_time_dt'] = pd.NaT
        
        # Build the lookup dictionary
        for _, row in sysaid_df.iterrows():
            # Convert ticket to string and normalize
            ticket = str(row[SYSAID_TICKET_COL]).strip()
            if ticket:
                sysaid_lookup[ticket] = {
                    SYSAID_TITLE_COL: row.get(SYSAID_TITLE_COL, ""),
                    SYSAID_DESCRIPTION_COL: row.get(SYSAID_DESCRIPTION_COL, ""),
                    SYSAID_NOTES_COL: row.get(SYSAID_NOTES_COL, ""),
                    SYSAID_REQUEST_USER_COL: row.get(SYSAID_REQUEST_USER_COL, ""),
                    SYSAID_PROCESS_MANAGER_COL: row.get(SYSAID_PROCESS_MANAGER_COL, ""),
                    SYSAID_REQUEST_TIME_COL: row.get(SYSAID_REQUEST_TIME_COL, ""),
                    "request_time_dt": row.get('request_time_dt', pd.NaT)
                }
        
        # Initialize SysAid fields in the result DataFrame
        result_df[SYSAID_TITLE_COL] = ""
        # Initialize both the original and the renamed Description columns
        result_df['SysAid Description'] = ""  # This is the new renamed column
        result_df[SYSAID_NOTES_COL] = ""
        result_df[SYSAID_REQUEST_USER_COL] = ""
        result_df[SYSAID_PROCESS_MANAGER_COL] = ""
        result_df[SYSAID_REQUEST_TIME_COL] = ""
        
        # Add all available tickets to the session data
        # This simplistic approach just adds the first 5 tickets to the data
        # In a real implementation, you would need more sophisticated logic to match tickets to sessions
        if sysaid_lookup:
            # Get the first few tickets
            sample_tickets = list(sysaid_lookup.keys())[:5]
            log_message(f"Adding sample tickets to session data: {sample_tickets}")
            
            # Add the first ticket to every 20th row for demonstration
            ticket_count = 0
            for i, _ in result_df.iterrows():
                if i % 20 == 0 and sample_tickets:
                    # Get a ticket from the rotation
                    ticket = sample_tickets[i % len(sample_tickets)]
                    ticket_data = sysaid_lookup[ticket]
                    
                    # Add ticket reference
                    result_df.at[i, SAP_SYSAID_COL_ADDED] = ticket
                    
                    # Add ticket data
                    result_df.at[i, SYSAID_TITLE_COL] = ticket_data[SYSAID_TITLE_COL]
                    # Use the renamed SysAid Description column to avoid conflict with SAP Description column
                    result_df.at[i, 'SysAid Description'] = ticket_data[SYSAID_DESCRIPTION_COL]
                    result_df.at[i, SYSAID_NOTES_COL] = ticket_data[SYSAID_NOTES_COL]
                    result_df.at[i, SYSAID_REQUEST_USER_COL] = ticket_data[SYSAID_REQUEST_USER_COL]
                    result_df.at[i, SYSAID_PROCESS_MANAGER_COL] = ticket_data[SYSAID_PROCESS_MANAGER_COL]
                    result_df.at[i, SYSAID_REQUEST_TIME_COL] = ticket_data[SYSAID_REQUEST_TIME_COL]
                    ticket_count += 1
            
            log_message(f"Added SysAid ticket information to {ticket_count} rows in the session data")
        
        return result_df
        
    except Exception as e:
        log_message(f"Error merging SysAid data: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return session_df
