#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced SysAid Ticket Integration Module

This module provides improved functionality to load and process SysAid ticket information,
allowing integration with SAP audit logs for enhanced reporting with better handling of:
1. Standardized SysAid number formats 
2. Session-to-SysAid mapping
3. Persistent mapping cache
4. Multiple ticket formats
"""

import os
import pandas as pd
import json
import re
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
    try:
        from sap_audit_record_counts import record_counter
    except ImportError:
        class RecordCounter:
            def update_source_counts(self, source_type, file_name, original_count, final_count):
                log_message(f"Record counts: {source_type} - {file_name}: {original_count} → {final_count}")
        record_counter = RecordCounter()

# Constants
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(SCRIPT_DIR, "input")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
CACHE_DIR = os.path.join(SCRIPT_DIR, "cache")
SYSAID_FILE = os.path.join(INPUT_DIR, "SysAid.xlsx")
SYSAID_SESSION_CACHE = os.path.join(CACHE_DIR, "sysaid_session_map.json")

# Create necessary directories
os.makedirs(INPUT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# SysAid field mapping constants
SYSAID_TICKET_COL_OPTIONS = ['Ticket', 'Ticket #', 'TicketID', 'ID', 'ticket', 'SysAid #', 'SYSAID#', 'SYSAID']
SYSAID_TICKET_COL = None  # Will be set dynamically when loading data
SYSAID_TITLE_COL = 'Title'
SYSAID_DESCRIPTION_COL = 'Description'
SYSAID_NOTES_COL = 'Notes'
SYSAID_REQUEST_USER_COL = 'Request user'
SYSAID_PROCESS_MANAGER_COL = 'Process manager'
SYSAID_REQUEST_TIME_COL = 'Request time'

# Column that will link to SysAid in SAP logs (case-insensitive search)
SAP_SYSAID_COL_OPTIONS = ['SYSAID#', 'SysAid#', 'SYSAID', 'SysAid', 'Ticket', 'Ticket #']
SAP_SYSAID_COL = None  # Will be set dynamically when analyzing data

# Column that will be added to session data
SAP_SYSAID_COL_ADDED = 'SYSAID #'

# Session and timeline column options
SESSION_COL_OPTIONS = ['Session ID', 'SESSION ID', 'SessionID', 'Session']
SESSION_COL = None  # Will be set dynamically

# Debug mode for verbose logging
DEBUG = False

def standardize_sysaid(value):
    """
    Enhanced standardization of SysAid numbers.
    
    Properly handles:
    - Values with hash prefixes (#120,568)
    - Values with commas (120,568)
    - Values with SR/CR prefixes (SR-120568)
    - Plain numeric values (120568)
    - Empty or None values (returns "UNKNOWN")
    """
    if not value or pd.isna(value) or str(value).strip() == '':
        return "UNKNOWN"
    
    value = str(value).strip()
    
    # Log original value in debug mode
    if DEBUG:
        log_message(f"Standardizing SysAid: '{value}'", "DEBUG")
    
    # Remove hash prefix
    value = re.sub(r'^#', '', value)
    
    # Remove SR- or CR- prefixes
    value = re.sub(r'^(SR|CR)-', '', value)
    
    # Remove commas
    value = value.replace(',', '')
    
    # Log the standardized value in debug mode
    if DEBUG:
        log_message(f"Standardized to: '{value}'", "DEBUG")
    
    return value

def get_sysaid_column(df, column_options):
    """
    Dynamically find a SysAid column in a DataFrame based on list of potential column names.
    """
    # First check for exact matches (case-insensitive)
    for option in column_options:
        matches = [col for col in df.columns if option.upper() == col.upper()]
        if matches:
            log_message(f"Found SysAid column by exact match: {matches[0]}")
            return matches[0]
    
    # Then check for partial matches (case-insensitive)
    for option in column_options:
        matches = [col for col in df.columns if option.upper() in col.upper()]
        if matches:
            log_message(f"Found SysAid column by partial match: {matches[0]}")
            return matches[0]
    
    # If no direct matches, check for standalone CR or SR columns
    for col in ['CR', 'SR']:
        matches = [c for c in df.columns if c.upper() == col.upper()]
        if matches:
            log_message(f"Found SysAid column as {col}: {matches[0]}")
            return matches[0]
    
    return None

def get_session_column(df):
    """Find the session ID column in the DataFrame."""
    for option in SESSION_COL_OPTIONS:
        matches = [col for col in df.columns if option.upper() in col.upper()]
        if matches:
            log_message(f"Found session column: {matches[0]}")
            return matches[0]
    
    # If no standard column found, look for any column with "SESSION" in the name
    for col in df.columns:
        if "SESSION" in col.upper():
            log_message(f"Found session column by partial match: {col}")
            return col
    
    return None

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
        
        # Try to load the Excel file with the specific sheet name "Report"
        try:
            sysaid_df = pd.read_excel(SYSAID_FILE, sheet_name="Report")
            log_message("Reading SysAid data from 'Report' sheet")
        except Exception as e:
            # If "Report" sheet doesn't exist, try loading the default sheet
            log_message(f"Could not read 'Report' sheet: {str(e)}", "WARNING")
            sysaid_df = pd.read_excel(SYSAID_FILE)
            log_message("Reading SysAid data from default sheet")
        
        # Debug output for column inspection
        log_message(f"All columns found in SysAid data: {list(sysaid_df.columns)}")
        
        # Print first few rows of the dataframe for debugging
        if not sysaid_df.empty and DEBUG:
            log_message(f"First row of SysAid data: {sysaid_df.iloc[0].to_dict()}")
        
        # Find the ticket column from our list of options
        SYSAID_TICKET_COL = get_sysaid_column(sysaid_df, SYSAID_TICKET_COL_OPTIONS)
        
        # If no ticket column found, can't proceed
        if not SYSAID_TICKET_COL:
            log_message(f"No ticket column found. Looked for: {', '.join(SYSAID_TICKET_COL_OPTIONS)}", "WARNING")
            return None
        
        # Ensure SysAid ticket column is a string
        sysaid_df[SYSAID_TICKET_COL] = sysaid_df[SYSAID_TICKET_COL].astype(str)
        
        # Add standardized column
        sysaid_df['Standardized_SysAid'] = sysaid_df[SYSAID_TICKET_COL].apply(standardize_sysaid)
        
        # Record count for completeness tracking
        record_count = len(sysaid_df)
        log_message(f"Loaded SysAid data with {record_count} tickets")
        
        # Count unique standardized tickets
        unique_std_tickets = sysaid_df['Standardized_SysAid'].nunique()
        log_message(f"Found {unique_std_tickets} unique standardized SysAid tickets")
        
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
        import traceback
        log_message(traceback.format_exc(), "ERROR")
        return None

def load_session_sysaid_map():
    """Load the cached session-to-SysAid mapping if available."""
    try:
        if os.path.exists(SYSAID_SESSION_CACHE):
            log_message(f"Loading cached session-to-SysAid mapping from: {SYSAID_SESSION_CACHE}")
            with open(SYSAID_SESSION_CACHE, 'r') as f:
                session_map = json.load(f)
            
            log_message(f"Loaded mapping with {len(session_map)} sessions")
            return session_map
    except Exception as e:
        log_message(f"Error loading cached session map: {str(e)}", "WARNING")
    
    return {}

def save_session_sysaid_map(session_map):
    """Save the session-to-SysAid mapping for future use."""
    try:
        log_message(f"Saving session-to-SysAid mapping to: {SYSAID_SESSION_CACHE}")
        with open(SYSAID_SESSION_CACHE, 'w') as f:
            json.dump(session_map, f, indent=2)
        log_message(f"Saved mapping with {len(session_map)} sessions")
    except Exception as e:
        log_message(f"Error saving session map: {str(e)}", "ERROR")

def map_sessions_to_sysaid(df, session_col, sysaid_col):
    """
    Maps session IDs to SysAid values, ensuring proper standardization.
    
    For sessions with multiple SysAid values, prioritizes non-UNKNOWN values.
    """
    session_to_sysaid = {}
    
    # Try to load existing mapping first
    cached_map = load_session_sysaid_map()
    if cached_map:
        session_to_sysaid = cached_map
        log_message(f"Using cached session mapping with {len(cached_map)} entries")
    
    # Get unique session IDs
    session_ids = df[session_col].unique()
    log_message(f"Mapping {len(session_ids)} unique sessions to SysAid values")
    
    # Keep track of new or updated mappings
    updated_mappings = False
    
    for session_id in session_ids:
        # Skip if already in cached map
        if str(session_id) in session_to_sysaid and session_to_sysaid[str(session_id)] != "UNKNOWN":
            if DEBUG:
                log_message(f"Using cached mapping for session {session_id}: {session_to_sysaid[str(session_id)]}", "DEBUG")
            continue
        
        subset = df[df[session_col] == session_id]
        sysaid_values = subset[sysaid_col].dropna().unique()
        
        # Skip if no SysAid values
        if len(sysaid_values) == 0:
            session_to_sysaid[str(session_id)] = "UNKNOWN"
            continue
        
        # Standardize all SysAid values in this session
        std_values = [standardize_sysaid(val) for val in sysaid_values]
        unique_std_values = list(set(std_values))
        
        # Remove UNKNOWN from the unique values
        non_unknown = [val for val in unique_std_values if val != "UNKNOWN"]
        
        # If we have non-UNKNOWN values, use those
        if non_unknown:
            # If only one, use it
            if len(non_unknown) == 1:
                session_to_sysaid[str(session_id)] = non_unknown[0]
            else:
                # Multiple non-UNKNOWN, take the most frequent
                value_counts = {}
                for val in std_values:
                    if val != "UNKNOWN":
                        value_counts[val] = value_counts.get(val, 0) + 1
                
                most_common = max(value_counts.items(), key=lambda x: x[1])[0]
                session_to_sysaid[str(session_id)] = most_common
        else:
            session_to_sysaid[str(session_id)] = "UNKNOWN"
        
        updated_mappings = True
    
    # Log the mapping results
    log_message(f"Session to SysAid mapping results:")
    unknown_count = sum(1 for v in session_to_sysaid.values() if v == "UNKNOWN")
    known_count = len(session_to_sysaid) - unknown_count
    log_message(f"  Total sessions: {len(session_to_sysaid)}")
    log_message(f"  Sessions with known SysAid: {known_count} ({known_count/len(session_to_sysaid)*100:.1f}%)")
    log_message(f"  Sessions with unknown SysAid: {unknown_count} ({unknown_count/len(session_to_sysaid)*100:.1f}%)")
    
    # Save updated mapping
    if updated_mappings:
        save_session_sysaid_map(session_to_sysaid)
    
    return session_to_sysaid

def build_sysaid_lookup(sysaid_df):
    """Build an enhanced lookup dictionary for efficient SysAid ticket matching."""
    if SYSAID_TICKET_COL is None or sysaid_df is None or SYSAID_TICKET_COL not in sysaid_df.columns:
        log_message("Cannot build SysAid lookup: missing required columns", "WARNING")
        return {}
    
    lookup = {}
    log_message("Building enhanced SysAid lookup dictionary...")
    
    sample_tickets = []
    
    for _, row in sysaid_df.iterrows():
        # Get original and standardized ticket
        original_ticket = str(row[SYSAID_TICKET_COL]).strip()
        standardized_ticket = row['Standardized_SysAid']
        
        # Skip UNKNOWN tickets
        if standardized_ticket == "UNKNOWN":
            continue
            
        # Collect samples for debugging (up to 5)
        if len(sample_tickets) < 5:
            sample_tickets.append((original_ticket, standardized_ticket))
        
        # Store the ticket data
        ticket_data = {
            "original_ticket": original_ticket,
            "standardized_ticket": standardized_ticket
        }
        
        # Add all available columns from the row
        for col in sysaid_df.columns:
            if col != SYSAID_TICKET_COL and col != 'Standardized_SysAid':
                ticket_data[col] = row.get(col, "")
        
        # Add special datetime handling for request time if available
        if SYSAID_REQUEST_TIME_COL in sysaid_df.columns:
            ticket_data["request_time_dt"] = pd.NaT
            try:
                if pd.notna(row.get(SYSAID_REQUEST_TIME_COL)):
                    ticket_data["request_time_dt"] = pd.to_datetime(
                        row.get(SYSAID_REQUEST_TIME_COL), 
                        errors='coerce',
                        format=None  # Let pandas infer the format
                    )
            except:
                pass
        
        # Store using multiple keys for better matching:
        
        # 1. Store with standardized numeric-only value (most reliable for matching)
        lookup[standardized_ticket] = ticket_data
        
        # 2. Store with original format
        lookup[original_ticket] = ticket_data
        
        # 3. Store with # prefix if it doesn't already have one
        if not original_ticket.startswith('#'):
            lookup[f"#{original_ticket}"] = ticket_data
        
        # 4. Store without # prefix if it has one
        if original_ticket.startswith('#'):
            lookup[original_ticket[1:]] = ticket_data
            
        # 5. Store with commas for large numbers
        if standardized_ticket.isdigit() and len(standardized_ticket) > 3:
            try:
                # Format with commas for thousands separator
                formatted = '{:,}'.format(int(standardized_ticket))
                lookup[formatted] = ticket_data
                
                # Also with # prefix
                lookup[f"#{formatted}"] = ticket_data
            except:
                pass
    
    if sample_tickets:
        log_message(f"Sample ticket standardization: {sample_tickets}")
    
    log_message(f"Built SysAid lookup with {len(lookup)} entries")
    return lookup

def merge_sysaid_data(session_df, sysaid_df):
    """
    Improved merge of SysAid ticket information with session timeline data.
    
    Args:
        session_df: DataFrame containing session timeline data
        sysaid_df: DataFrame containing SysAid ticket information
        
    Returns:
        DataFrame with SysAid information merged into session data
    """
    global SAP_SYSAID_COL, SESSION_COL
    
    try:
        if session_df is None:
            log_message("Cannot merge SysAid data: missing session data", "WARNING")
            return session_df
            
        log_message("Adding SysAid ticket information to session timeline...")
        
        # Create a copy of the session data to avoid modifying the original
        result_df = session_df.copy()
        
        # Find the session column
        SESSION_COL = get_session_column(result_df)
        if not SESSION_COL:
            log_message("No session column found, cannot map sessions to SysAid", "WARNING")
            return result_df
        
        # Add SysAid ticket column if it doesn't exist
        if SAP_SYSAID_COL_ADDED not in result_df.columns:
            result_df[SAP_SYSAID_COL_ADDED] = ""
            log_message(f"Added new column '{SAP_SYSAID_COL_ADDED}' to session data")
        
        # Initialize SysAid fields in the result DataFrame
        if SYSAID_TITLE_COL not in result_df.columns:
            result_df[SYSAID_TITLE_COL] = ""
        
        # Initialize both the original and the renamed Description columns
        if 'SysAid Description' not in result_df.columns:
            result_df['SysAid Description'] = ""  # This is the new renamed column
            
        # Other SysAid fields
        if SYSAID_NOTES_COL not in result_df.columns:
            result_df[SYSAID_NOTES_COL] = ""
            
        if SYSAID_REQUEST_USER_COL not in result_df.columns:
            result_df[SYSAID_REQUEST_USER_COL] = ""
            
        if SYSAID_PROCESS_MANAGER_COL not in result_df.columns:
            result_df[SYSAID_PROCESS_MANAGER_COL] = ""
            
        if SYSAID_REQUEST_TIME_COL not in result_df.columns:
            result_df[SYSAID_REQUEST_TIME_COL] = ""
        
        # If we have SysAid data, process it
        if sysaid_df is not None:
            # Find the SysAid column in the session data if it exists
            SAP_SYSAID_COL = get_sysaid_column(result_df, SAP_SYSAID_COL_OPTIONS)
            has_sysaid_column = SAP_SYSAID_COL is not None
            
            if has_sysaid_column:
                log_message(f"Found SysAid column in session data: {SAP_SYSAID_COL}")
                
                # Add standardized SysAid column
                result_df['Standardized_SysAid'] = result_df[SAP_SYSAID_COL].apply(standardize_sysaid)
                log_message("Added standardized SysAid column to session data")
                
                # Map sessions to SysAid values
                session_to_sysaid = map_sessions_to_sysaid(result_df, SESSION_COL, SAP_SYSAID_COL)
            else:
                log_message("No SysAid column found in session data, using session-only mapping", "WARNING")
                
                # Load cached session mapping
                session_to_sysaid = load_session_sysaid_map()
                
                # Add a dummy column for standardization if needed for downstream processing
                result_df['Standardized_SysAid'] = "UNKNOWN"
            
            # Build the SysAid lookup dictionary
            sysaid_lookup = build_sysaid_lookup(sysaid_df)
            
            # Apply the session to SysAid mapping to all rows
            log_message("Applying session-to-SysAid mapping to all rows...")
            
            # Add the mapped SysAid values
            result_df['Mapped_SysAid'] = result_df[SESSION_COL].astype(str).map(session_to_sysaid)
            
            # Fill in SysAid data based on mapped values
            ticket_count = 0
            
            # Process each unique SysAid value
            unique_mapped = result_df['Mapped_SysAid'].unique()
            for mapped_sysaid in [m for m in unique_mapped if m != "UNKNOWN"]:
                # If this SysAid exists in our lookup
                if mapped_sysaid in sysaid_lookup:
                    ticket_data = sysaid_lookup[mapped_sysaid]
                    
                    # Flag all rows with this mapped SysAid
                    mask = result_df['Mapped_SysAid'] == mapped_sysaid
                    count = mask.sum()
                    
                    # Update SysAid information for these rows
                    result_df.loc[mask, SAP_SYSAID_COL_ADDED] = mapped_sysaid
                    
                    # Add ticket data for all matching fields
                    for field, value in ticket_data.items():
                        if field in result_df.columns:
                            result_df.loc[mask, field] = value
                        
                    # Special handling for Description to avoid column conflicts
                    if SYSAID_DESCRIPTION_COL in ticket_data:
                        result_df.loc[mask, 'SysAid Description'] = ticket_data[SYSAID_DESCRIPTION_COL]
                    
                    ticket_count += count
                    log_message(f"Updated {count} rows with SysAid {mapped_sysaid}")
            
            log_message(f"Added SysAid ticket information to {ticket_count} rows in the session data")
            
            # Update the final count in record counter
            if ticket_count > 0:
                record_counter.update_source_counts(
                    source_type="sysaid",
                    file_name=SYSAID_FILE,
                    original_count=len(sysaid_df) if sysaid_df is not None else 0,
                    final_count=ticket_count
                )
        
        return result_df
        
    except Exception as e:
        log_message(f"Error merging SysAid data: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return session_df

# Example usage
if __name__ == "__main__":
    # Enable debug mode for standalone execution
    DEBUG = True
    
    # Load SysAid data
    sysaid_data = load_sysaid_data()
    
    # Try to load a sample session file if one exists
    session_file = os.path.join(INPUT_DIR, "sap_session_timeline.xlsx")
    if os.path.exists(session_file):
        log_message(f"Loading sample session data from: {session_file}")
        try:
            session_data = pd.read_excel(session_file)
            log_message(f"Loaded session data with {len(session_data)} rows")
            
            # Process the session data
            result = merge_sysaid_data(session_data, sysaid_data)
            
            # Save the result
            output_file = os.path.join(OUTPUT_DIR, "enhanced_session_timeline.xlsx")
            result.to_excel(output_file, index=False)
            log_message(f"Saved enhanced session data to: {output_file}")
            
        except Exception as e:
            log_message(f"Error processing sample data: {str(e)}", "ERROR")
    else:
        log_message("No sample session data found. SysAid data processing ready for integration.")
