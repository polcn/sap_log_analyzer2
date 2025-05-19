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
    from sap_audit_record_counts import record_counter
except ImportError:
    # Fallback if utils not available
    def log_message(message, level="INFO"):
        """Log a message with timestamp and level."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
    
    # Placeholder if record counter not available
    from sap_audit_record_counts import record_counter

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
SAP_SYSAID_COL = 'SYSAID#'

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
            
        # Record count for completeness tracking
        record_count = len(sysaid_df)
        log_message(f"Loaded SysAid data with {record_count} tickets")
        
        # Update record counter
        record_counter.update_source_counts(
            source_type="sysaid",
            file_name=SYSAID_FILE,
            original_count=record_count,
            final_count=record_count
        )
        
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
        
    # Build the lookup dictionary with enhanced normalization
        log_message("Building SysAid lookup dictionary with enhanced normalization...")
        
        # Function to normalize ticket numbers - removes all non-numeric characters
        def normalize_ticket(ticket_str):
            """Aggressively normalize ticket numbers to match across different formats."""
            if not ticket_str or pd.isna(ticket_str):
                return ""
                
            # Convert to string if not already
            ticket_str = str(ticket_str).strip()
            
            # First save the original format
            original = ticket_str
            
            # Remove all non-digit characters (commas, #, spaces, etc.)
            numeric_only = ''.join(c for c in ticket_str if c.isdigit())
            
            # Log the normalization for debugging
            if numeric_only and numeric_only != original:
                log_message(f"Normalized ticket: '{original}' -> '{numeric_only}'")
                
            return numeric_only
        
        # Sample of ticket formats for debugging
        sample_tickets = []
        
        for _, row in sysaid_df.iterrows():
            # Get and normalize the ticket
            original_ticket = str(row[SYSAID_TICKET_COL]).strip() if pd.notna(row[SYSAID_TICKET_COL]) else ""
            
            # Skip empty tickets
            if not original_ticket:
                continue
                
            # Collect samples for debugging (up to 5)
            if len(sample_tickets) < 5:
                sample_tickets.append(original_ticket)
            
            # Normalize the ticket to numeric-only format
            normalized_ticket = normalize_ticket(original_ticket)
            
            # Skip if no numeric content
            if not normalized_ticket:
                continue
            
            # Store ticket data
            ticket_data = {
                SYSAID_TITLE_COL: row.get(SYSAID_TITLE_COL, ""),
                SYSAID_DESCRIPTION_COL: row.get(SYSAID_DESCRIPTION_COL, ""),
                SYSAID_NOTES_COL: row.get(SYSAID_NOTES_COL, ""),
                SYSAID_REQUEST_USER_COL: row.get(SYSAID_REQUEST_USER_COL, ""),
                SYSAID_PROCESS_MANAGER_COL: row.get(SYSAID_PROCESS_MANAGER_COL, ""),
                SYSAID_REQUEST_TIME_COL: row.get(SYSAID_REQUEST_TIME_COL, ""),
                "request_time_dt": row.get('request_time_dt', pd.NaT),
                "original_ticket": original_ticket  # Keep the original format for reference
            }
            
            # Store with multiple variations of the ticket number to maximize matching success
            
            # 1. Store with normalized numeric-only value (most reliable for matching)
            sysaid_lookup[normalized_ticket] = ticket_data
            
            # 2. Store with original format
            sysaid_lookup[original_ticket] = ticket_data
            
            # 3. Store with # prefix if it doesn't already have one
            if not original_ticket.startswith('#'):
                sysaid_lookup[f"#{original_ticket}"] = ticket_data
            
            # 4. Store without # prefix if it has one
            if original_ticket.startswith('#'):
                sysaid_lookup[original_ticket[1:]] = ticket_data
            
            # 5. Store with commas if it's a large number without commas
            if normalized_ticket.isdigit() and len(normalized_ticket) > 3:
                try:
                    # Format with commas for thousands separator (e.g., 123456 -> 123,456)
                    formatted = '{:,}'.format(int(normalized_ticket))
                    sysaid_lookup[formatted] = ticket_data
                    
                    # Also with # prefix
                    sysaid_lookup[f"#{formatted}"] = ticket_data
                except:
                    pass
        
        if sample_tickets:
            log_message(f"Sample SysAid ticket formats: {sample_tickets}")
        
        # Initialize SysAid fields in the result DataFrame
        result_df[SYSAID_TITLE_COL] = ""
        # Initialize both the original and the renamed Description columns
        result_df['SysAid Description'] = ""  # This is the new renamed column
        result_df[SYSAID_NOTES_COL] = ""
        result_df[SYSAID_REQUEST_USER_COL] = ""
        result_df[SYSAID_PROCESS_MANAGER_COL] = ""
        result_df[SYSAID_REQUEST_TIME_COL] = ""
        
        # Find any existing SysAid ticket numbers in the session data
        ticket_count = 0
        if sysaid_lookup and SAP_SYSAID_COL in result_df.columns:
            log_message(f"Looking for SysAid ticket numbers in column: {SAP_SYSAID_COL}")
            
            # Create a list of all available SysAid ticket numbers for debugging
            available_tickets = list(sysaid_lookup.keys())
            log_message(f"Available SysAid tickets in lookup: {len(available_tickets)} tickets")
            if available_tickets:
                log_message(f"Sample tickets: {available_tickets[:5]}")
            
            # Process each row in the session data using enhanced normalization
            for i, row in result_df.iterrows():
                # Get the SysAid ticket number from the row, if it exists
                if SAP_SYSAID_COL in row and pd.notna(row[SAP_SYSAID_COL]) and str(row[SAP_SYSAID_COL]).strip():
                    # Get the raw ticket number
                    raw_ticket = str(row[SAP_SYSAID_COL]).strip()
                    
                    # Normalize the ticket (aggressively strip all non-numeric characters)
                    normalized_ticket = normalize_ticket(raw_ticket)
                    
                    # Log ticket information for debugging
                    log_message(f"Found ticket reference in row {i}: {raw_ticket} (normalized: {normalized_ticket})")
                    
                    # Try different formats for lookup
                    matched_ticket = False
                    
                    # Try different ticket formats for lookup
                    ticket_formats = [
                        normalized_ticket,                # Numeric only
                        raw_ticket,                       # Original format
                        raw_ticket.replace(',', ''),      # Without commas
                        raw_ticket.lstrip('#'),           # Without leading #
                        raw_ticket.replace(',', '').lstrip('#')  # Without commas or #
                    ]
                    
                    # For debugging - show all formats we're trying
                    log_message(f"Trying formats for lookup: {ticket_formats}")
                    
                    # Try each format
                    for ticket_format in ticket_formats:
                        if ticket_format in sysaid_lookup:
                            log_message(f"✓ Match found using format: '{ticket_format}'")
                            ticket_data = sysaid_lookup[ticket_format]
                            matched_ticket = True
                            break
                    
                    # If none of the formats matched, try one more approach - match by normalized numeric value only
                    if not matched_ticket:
                        # Look for any key in sysaid_lookup where normalize_ticket(key) == normalized_ticket
                        for lookup_key, data in list(sysaid_lookup.items()):
                            if normalize_ticket(lookup_key) == normalized_ticket:
                                log_message(f"✓ Match found via normalized comparison: '{lookup_key}' -> '{normalized_ticket}'")
                                ticket_data = data
                                matched_ticket = True
                                break
                    
                    # If we found a match with any format
                    if matched_ticket:
                        
                        # Add ticket reference (normalized, without commas or #)
                        result_df.at[i, SAP_SYSAID_COL_ADDED] = normalized_ticket
                        
                        # Add ticket data
                        result_df.at[i, SYSAID_TITLE_COL] = ticket_data[SYSAID_TITLE_COL]
                        # Use the renamed SysAid Description column to avoid conflict with SAP Description column
                        result_df.at[i, 'SysAid Description'] = ticket_data[SYSAID_DESCRIPTION_COL]
                        result_df.at[i, SYSAID_NOTES_COL] = ticket_data[SYSAID_NOTES_COL]
                        result_df.at[i, SYSAID_REQUEST_USER_COL] = ticket_data[SYSAID_REQUEST_USER_COL]
                        result_df.at[i, SYSAID_PROCESS_MANAGER_COL] = ticket_data[SYSAID_PROCESS_MANAGER_COL]
                        result_df.at[i, SYSAID_REQUEST_TIME_COL] = ticket_data[SYSAID_REQUEST_TIME_COL]
                        ticket_count += 1
                    else:
                        log_message(f"Ticket {raw_ticket} not found in SysAid data (normalized: {normalized_ticket})")
            
            log_message(f"Added SysAid ticket information to {ticket_count} rows in the session data")
            
            # Update the final count in record counter
            if SYSAID_TICKET_COL:
                record_counter.update_source_counts(
                    source_type="sysaid",
                    file_name=SYSAID_FILE,
                    original_count=len(sysaid_df),
                    final_count=ticket_count
                )
        
        return result_df
        
    except Exception as e:
        log_message(f"Error merging SysAid data: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return session_df
