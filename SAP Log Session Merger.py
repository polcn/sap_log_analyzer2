#!/usr/bin/env python3
"""
SAP Log Session Merger

This script combines SM20, CDHDR, and CDPOS logs into a user session timeline.
It creates a unified, chronological view of SAP user activity for internal audit purposes.

Key features:
- Assigns session IDs based on SysAid ticket numbers (or user+date when SysAid is unavailable)
- Preserves all relevant fields from each source
- Joins CDHDR with CDPOS to show field-level changes
- Creates a formatted Excel output with color-coding by source
"""

import os
import sys
import pandas as pd
from datetime import datetime, timedelta

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(SCRIPT_DIR, "input")

# Input files (standardized names from data prep script)
SM20_FILE = os.path.join(INPUT_DIR, "SM20.csv")
CDHDR_FILE = os.path.join(INPUT_DIR, "CDHDR.csv")
CDPOS_FILE = os.path.join(INPUT_DIR, "CDPOS.csv")

# Output file
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "SAP_Session_Timeline.xlsx")

# Column mappings for UPPERCASE headers
# SM20 Security Audit Log columns
SM20_USER_COL = 'USER'
SM20_DATE_COL = 'DATE'
SM20_TIME_COL = 'TIME'
SM20_EVENT_COL = 'EVENT'
SM20_TCODE_COL = 'SOURCE TA'
SM20_ABAP_SOURCE_COL = 'ABAP SOURCE'
SM20_MSG_COL = 'AUDIT LOG MSG. TEXT'
SM20_NOTE_COL = 'NOTE'

# CDHDR Change Document Header columns
CDHDR_USER_COL = 'USER'
CDHDR_DATE_COL = 'DATE'
CDHDR_TIME_COL = 'TIME'
CDHDR_TCODE_COL = 'TCODE'
CDHDR_CHANGENR_COL = 'DOC.NUMBER'
CDHDR_OBJECTCLAS_COL = 'OBJECT'
CDHDR_OBJECTID_COL = 'OBJECT VALUE'
CDHDR_CHANGE_FLAG_COL = 'CHANGE FLAG FOR APPLICATION OBJECT'

# CDPOS Change Document Item columns
CDPOS_CHANGENR_COL = 'DOC.NUMBER'
CDPOS_TABNAME_COL = 'TABLE NAME'
CDPOS_TABLE_KEY_COL = 'TABLE KEY'
CDPOS_FNAME_COL = 'FIELD NAME'
CDPOS_CHANGE_IND_COL = 'CHANGE INDICATOR'
CDPOS_TEXT_FLAG_COL = 'TEXT FLAG'
CDPOS_VALUE_NEW_COL = 'NEW VALUE'
CDPOS_VALUE_OLD_COL = 'OLD VALUE'

# Fields to exclude (as per user request)
EXCLUDE_FIELDS = ['COMMENTS']  # Removed 'SYSAID #' to preserve it through the process

# --- Utility Functions ---
def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def find_sysaid_column(df):
    """
    Find the best column to use for SysAid ticket numbers.
    Handles different naming conventions across data sources.
    
    Args:
        df: DataFrame to search for SysAid columns
        
    Returns:
        Column name to use for SysAid tickets, or None if not found
    """
    potential_columns = ['SYSAID#', 'SYSAID #', 'SysAid', 'Ticket#', 'Ticket', 'Change_Request']
    
    for col in potential_columns:
        if col in df.columns:
            # Check if the column has any non-empty values
            if df[col].notna().any() and (df[col] != '').any():
                log_message(f"Using '{col}' as SysAid ticket reference column")
                return col
    
    log_message("No SysAid ticket column found with data", "WARNING")
    return None

def standardize_sysaid_references(df, sysaid_col):
    """
    Standardize SysAid ticket references to a consistent format.
    - Handles prefixes like "SR-", "CR-", or "#"
    - Removes commas from numbers
    - Converts all references to uppercase
    - Removes extraneous spaces
    
    Args:
        df: DataFrame containing SysAid references
        sysaid_col: Column containing SysAid references
        
    Returns:
        DataFrame with standardized SysAid references
    """
    if sysaid_col not in df.columns:
        return df
        
    # Make a copy to avoid warnings
    df = df.copy()
    
    # Debug: print distinct values before standardization
    original_values = df[sysaid_col].astype(str).unique().tolist()
    log_message(f"Original SysAid values (sample of {min(10, len(original_values))} of {len(original_values)} unique): {original_values[:10]}")
    
    # Standardize SysAid references
    df[sysaid_col] = df[sysaid_col].astype(str)
    
    # Handle empty values first - mark these as UNKNOWN
    df.loc[df[sysaid_col].isin(['nan', 'None', 'NULL', 'NAN', 'NONE', '']), sysaid_col] = 'UNKNOWN'
    
    # Only process non-UNKNOWN values
    mask = df[sysaid_col] != 'UNKNOWN'
    if mask.any():
        # Remove common prefixes including '#'
        df.loc[mask, sysaid_col] = df.loc[mask, sysaid_col].str.replace(r'^(SR-|CR-|SR|CR|#)', '', regex=True)
        
        # Remove commas from numbers
        df.loc[mask, sysaid_col] = df.loc[mask, sysaid_col].str.replace(',', '', regex=False)
        
        # Remove spaces and convert to uppercase
        df.loc[mask, sysaid_col] = df.loc[mask, sysaid_col].str.strip().str.upper()
    
    # Debug: print distinct values after standardization
    standardized_values = df[sysaid_col].unique().tolist()
    log_message(f"Standardized SysAid values (sample of {min(10, len(standardized_values))} of {len(standardized_values)} unique): {standardized_values[:10]}")
    
    # Count of each unique value for debugging
    value_counts = df[sysaid_col].value_counts().head(5).to_dict()
    log_message(f"Top SysAid values by frequency: {value_counts}")
    
    return df

def load_csv_file(file_path):
    """Load a CSV file with UTF-8-sig encoding."""
    try:
        log_message(f"Loading file: {file_path}")
        df = pd.read_csv(file_path, encoding='utf-8-sig')
        log_message(f"Loaded {len(df)} rows from {os.path.basename(file_path)}")
        return df
    except Exception as e:
        log_message(f"Error loading {file_path}: {str(e)}", "ERROR")
        return pd.DataFrame()

def assign_session_ids_by_sysaid(df, sysaid_col, time_col, session_col='Session ID'):
    """
    Assign session IDs to rows based on SysAid ticket numbers.
    A new session starts when the SysAid ticket number changes.
    
    Args:
        df: DataFrame containing session data
        sysaid_col: Column name for SysAid ticket numbers
        time_col: Column name for datetime
        session_col: Output column name for session IDs
        
    Returns:
        DataFrame with session IDs assigned
    """
    if len(df) == 0:
        return df
        
    # Make a copy to avoid SettingWithCopyWarning
    df = df.sort_values(by=[sysaid_col, time_col]).copy()
    
    # Create a standardized SysAid value
    # - Fill missing values with a special indicator
    # - Remove any leading/trailing whitespace
    # - Standardize case
    df['_temp_sysaid'] = df[sysaid_col].astype(str)
    df.loc[df['_temp_sysaid'].isin(['nan', 'None', '']), '_temp_sysaid'] = 'UNKNOWN'
    df['_temp_sysaid'] = df['_temp_sysaid'].str.strip().str.upper()
    
    # Sort SysAid numbers by their first occurrence timestamp
    # This ensures that session IDs are assigned chronologically
    first_occurrences = df.groupby('_temp_sysaid')[time_col].min().reset_index()
    first_occurrences = first_occurrences.sort_values(by=time_col)
    
    # Create mapping from SysAid numbers to sequential session IDs
    session_mapping = {
        sysaid: f"S{i+1:04}" 
        for i, sysaid in enumerate(first_occurrences['_temp_sysaid'])
    }
    
    # Apply the mapping to create session IDs
    df[session_col] = df['_temp_sysaid'].map(session_mapping)
    
    # Add session date for display purposes (from first occurrence of each SysAid)
    first_date_mapping = {
        sysaid: pd.to_datetime(timestamp).strftime('%Y-%m-%d')
        for sysaid, timestamp in zip(first_occurrences['_temp_sysaid'], 
                                     first_occurrences[time_col])
    }
    
    df['Session_Date'] = df['_temp_sysaid'].map(first_date_mapping)
    
    # Create "Session ID with Date" format for display
    df['Session ID with Date'] = df.apply(
        lambda x: f"{x[session_col]} ({x['Session_Date']})", axis=1
    )
    
    # Clean up temporary columns
    df = df.drop(['_temp_sysaid'], axis=1)
    
    log_message(f"Assigned {len(session_mapping)} unique session IDs based on SysAid ticket numbers")
    
    return df

def assign_session_ids_by_user_date(df, user_col, time_col, session_col='Session ID'):
    """
    Legacy method: Assign session IDs based on user and calendar date.
    Used as fallback when SysAid column is not available.
    
    Args:
        df: DataFrame containing session data
        user_col: Column name for user
        time_col: Column name for datetime
        session_col: Output column name for session IDs
        
    Returns:
        DataFrame with session IDs assigned
    """
    if len(df) == 0:
        return df
        
    log_message("Using legacy session assignment based on user+date", "INFO")
    
    # Make a copy to avoid SettingWithCopyWarning
    df = df.sort_values(by=[user_col, time_col]).copy()
    
    # Add a date column for session grouping
    df['_session_date'] = df[time_col].dt.date
    
    # First pass: identify session boundaries
    session_boundaries = []
    prev_user = None
    prev_date = None
    session_id = 0
    
    for idx, row in df.iterrows():
        user = row[user_col]
        date = row['_session_date']
        dt = row[time_col]
        
        # Start a new session if user changes or date changes
        if user != prev_user or date != prev_date:
            session_id += 1
            # Store the session ID, start time, and index
            session_boundaries.append((session_id, dt, idx))
            
        prev_user = user
        prev_date = date
    
    # Sort sessions by start time
    session_boundaries.sort(key=lambda x: x[1])
    
    # Create mapping from original session ID to chronological session ID
    session_mapping = {orig_id: f"S{i+1:04}" for i, (orig_id, _, _) in enumerate(session_boundaries)}
    
    # Second pass: assign chronological session IDs
    session_ids = []
    prev_user = None
    prev_date = None
    current_session_id = 0
    
    for _, row in df.iterrows():
        user = row[user_col]
        date = row['_session_date']
        
        # Start a new session if user changes or date changes
        if user != prev_user or date != prev_date:
            current_session_id += 1
            
        # Map to chronological session ID
        chronological_id = session_mapping[current_session_id]
        session_ids.append(chronological_id)
        
        prev_user = user
        prev_date = date
    
    # Clean up temporary column
    df.drop('_session_date', axis=1, inplace=True)

    # Add session ID column
    df[session_col] = session_ids
    
    # Add "Session ID with Date" column for display
    df['Session_Date'] = df[time_col].dt.strftime('%Y-%m-%d')
    df['Session ID with Date'] = df.apply(
        lambda x: f"{x[session_col]} ({x['Session_Date']})", axis=1
    )
    df.drop('Session_Date', axis=1, inplace=True)
    
    return df

def assign_session_ids(df, user_col, time_col, session_col='Session ID', sysaid_col=None):
    """
    Assign session IDs to rows, using SysAid ticket numbers if available,
    otherwise falling back to user+date based sessions.
    
    Args:
        df: DataFrame containing session data
        user_col: Column name for user
        time_col: Column name for datetime
        session_col: Output column name for session IDs
        sysaid_col: Column name for SysAid ticket numbers (if None, will attempt to find it)
        
    Returns:
        DataFrame with session IDs assigned
    """
    if len(df) == 0:
        return df
    
    # If sysaid_col is not specified, try to find it
    if sysaid_col is None:
        sysaid_col = find_sysaid_column(df)
    
    # If we found a SysAid column with data, use it for grouping
    if sysaid_col is not None:
        log_message(f"Assigning session IDs based on SysAid ticket numbers from column: {sysaid_col}")
        return assign_session_ids_by_sysaid(df, sysaid_col, time_col, session_col)
    else:
        # Fall back to legacy user+date based sessions
        log_message("No SysAid column found. Falling back to user+date based sessions.", "WARNING")
        return assign_session_ids_by_user_date(df, user_col, time_col, session_col)

# --- Data Processing Functions ---
def prepare_sm20(sm20):
    """Prepare SM20 data with datetime."""
    if len(sm20) == 0:
        return sm20
        
    # Create datetime column
    sm20['Datetime'] = pd.to_datetime(
        sm20[SM20_DATE_COL].astype(str) + ' ' + sm20[SM20_TIME_COL].astype(str),
        errors='coerce'
    )
    
    # Drop rows with invalid datetime
    sm20 = sm20.dropna(subset=['Datetime'])
    
    # Add source identifier
    sm20['Source'] = 'SM20'
    
    return sm20

def prepare_cdhdr(cdhdr):
    """Prepare CDHDR data with datetime."""
    if len(cdhdr) == 0:
        return cdhdr
    
    # Fix duplicate column names
    col_list = cdhdr.columns.tolist()
    renamed_cols = []
    
    for i, col in enumerate(col_list):
        if col in renamed_cols:
            # For duplicate columns, append a suffix
            j = 1
            while f"{col}_{j}" in renamed_cols:
                j += 1
            new_name = f"{col}_{j}"
            log_message(f"Renamed duplicate column: {col} -> {new_name}")
            renamed_cols.append(new_name)
        else:
            renamed_cols.append(col)
    
    # Assign new column names
    cdhdr.columns = renamed_cols
    
    # Now clean up column names
    cdhdr.columns = [col.strip() for col in cdhdr.columns]
    
    # Log all column names for debugging
    log_message(f"CDHDR columns (after renaming): {cdhdr.columns.tolist()}")
    
    # Check if the date and time columns exist
    if CDHDR_DATE_COL not in cdhdr.columns or CDHDR_TIME_COL not in cdhdr.columns:
        # Look for similarly named columns
        date_cols = [col for col in cdhdr.columns if 'DATE' in col and not col.endswith('_1') and not col.endswith('_2')]
        time_cols = [col for col in cdhdr.columns if 'TIME' in col and not col.endswith('_1') and not col.endswith('_2')]
        
        if date_cols and time_cols:
            log_message(f"Using alternative columns: Date={date_cols[0]}, Time={time_cols[0]}")
            date_col = date_cols[0]
            time_col = time_cols[0]
        elif 'DATETIME' in cdhdr.columns:
            log_message("Using pre-existing DATETIME column")
            cdhdr['Datetime'] = pd.to_datetime(cdhdr['DATETIME'], errors='coerce')
            cdhdr = cdhdr.dropna(subset=['Datetime'])
            cdhdr['Source'] = 'CDHDR'
            return cdhdr
        else:
            log_message("Cannot find date/time columns in CDHDR data", "WARNING")
            return pd.DataFrame()
    else:
        date_col = CDHDR_DATE_COL
        time_col = CDHDR_TIME_COL
    
    # Create datetime column with better error handling
    try:
        # Ensure both columns are strings
        cdhdr[date_col] = cdhdr[date_col].astype(str)
        cdhdr[time_col] = cdhdr[time_col].astype(str)
        
        # Create datetime values
        cdhdr['Datetime'] = pd.to_datetime(
            cdhdr[date_col] + ' ' + cdhdr[time_col],
            errors='coerce'
        )
        
        # Check for NaT values
        nat_count = cdhdr['Datetime'].isna().sum()
        if nat_count > 0:
            log_message(f"Warning: {nat_count} rows have invalid date/time in CDHDR", "WARNING")
        
        # Drop rows with invalid datetime
        before_count = len(cdhdr)
        cdhdr = cdhdr.dropna(subset=['Datetime'])
        after_count = len(cdhdr)
        
        if before_count > after_count:
            log_message(f"Dropped {before_count - after_count} CDHDR rows with invalid datetime", "WARNING")
    except Exception as e:
        log_message(f"Error creating datetime for CDHDR: {str(e)}", "ERROR")
        # Try to continue with empty DataFrame rather than failing completely
        return pd.DataFrame()
    
    # Add source identifier
    cdhdr['Source'] = 'CDHDR'
    log_message(f"Prepared {len(cdhdr)} CDHDR records with datetime")
    
    return cdhdr

def merge_cdhdr_cdpos(cdhdr, cdpos):
    """Merge CDHDR with CDPOS data."""
    # If both are empty, return empty DataFrame
    if len(cdhdr) == 0 and len(cdpos) == 0:
        log_message("Both CDHDR and CDPOS are empty, skipping merge")
        return pd.DataFrame()
        
    # If only CDPOS has data, prepare it directly with datetime
    if len(cdhdr) == 0 and len(cdpos) > 0:
        log_message(f"CDHDR is empty but CDPOS has {len(cdpos)} records. Using CDPOS directly.")
        cdpos = cdpos.copy()
        cdpos.columns = [col.strip() for col in cdpos.columns]
        
        # We need to add a datetime column for CDPOS
        # Since CDPOS doesn't have date/time, use current time as placeholder
        # This will be adjusted when merging with SM20 data
        log_message("Adding placeholder datetime to CDPOS records")
        cdpos['Datetime'] = pd.to_datetime('today')
        cdpos['User'] = 'SYSTEM'  # Default user as placeholder
        cdpos['Source'] = 'CDPOS'
        return cdpos
        
    # If only CDHDR has data, return it as is
    if len(cdhdr) > 0 and len(cdpos) == 0:
        log_message(f"CDPOS is empty but CDHDR has {len(cdhdr)} records. Using CDHDR directly.")
        return cdhdr
    
    # Clean up column names by stripping whitespace
    cdhdr.columns = [col.strip() for col in cdhdr.columns]
    cdpos.columns = [col.strip() for col in cdpos.columns]
    
    # Check if the expected columns exist
    cdhdr_cols = [CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL, CDHDR_CHANGENR_COL]
    cdpos_cols = [CDPOS_CHANGENR_COL, CDPOS_TABNAME_COL]
    
    # Log available columns for debugging
    log_message(f"CDHDR columns: {cdhdr.columns.tolist()}")
    log_message(f"CDPOS columns: {cdpos.columns.tolist()}")
    
    # Find closest matches if columns don't exist exactly
    for col in cdhdr_cols:
        if col not in cdhdr.columns:
            closest = [c for c in cdhdr.columns if col in c]
            if closest:
                log_message(f"CDHDR: Using '{closest[0]}' instead of '{col}'")
                cdhdr[col] = cdhdr[closest[0]]
    
    for col in cdpos_cols:
        if col not in cdpos.columns:
            closest = [c for c in cdpos.columns if col in c]
            if closest:
                log_message(f"CDPOS: Using '{closest[0]}' instead of '{col}'")
                cdpos[col] = cdpos[closest[0]]
    
    # Ensure all required columns exist
    for df, name, cols in [(cdhdr, "CDHDR", cdhdr_cols), (cdpos, "CDPOS", [CDPOS_CHANGENR_COL])]:
        missing = [col for col in cols if col not in df.columns]
        if missing:
            log_message(f"Missing required columns in {name}: {missing}", "WARNING")
            # Create empty columns for missing ones
            for col in missing:
                df[col] = None
    
    # Merge on OBJECTCLAS, OBJECTID, and CHANGENR as per requirements
    try:
        merged = pd.merge(
            cdhdr,
            cdpos,
            left_on=[CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL, CDHDR_CHANGENR_COL],
            right_on=[CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL, CDPOS_CHANGENR_COL],
            how='left'
        )
        
        # Update source for rows with CDPOS data
        if CDPOS_TABNAME_COL in merged.columns:
            merged.loc[merged[CDPOS_TABNAME_COL].notna(), 'Source'] = 'CDPOS'
            log_message(f"Successfully merged CDPOS data: {sum(merged['Source'] == 'CDPOS')} CDPOS records")
        else:
            log_message(f"Warning: {CDPOS_TABNAME_COL} not found in merged data", "WARNING")
        
        return merged
    except Exception as e:
        log_message(f"Error merging CDHDR with CDPOS: {str(e)}", "ERROR")
        # Return the original CDHDR data if merge fails
        return cdhdr

def create_unified_timeline(sm20, cdhdr_cdpos):
    """Create a unified timeline from all sources with proper session assignment.
    
    This function ensures no duplication of records when consolidating data sources.
    """
    # Define columns to keep from each source (excluding Session ID which we'll reassign)
    sm20_cols = [
        'Source', SM20_USER_COL, 'Datetime', 
        SM20_EVENT_COL, SM20_TCODE_COL, SM20_ABAP_SOURCE_COL, 
        SM20_MSG_COL, SM20_NOTE_COL,
        # Variable fields needed for debug detection
        'FIRST VARIABLE VALUE FOR EVENT', 'VARIABLE 2', 'VARIABLE 3',
        'VARIABLE DATA FOR MESSAGE',
        # SysAid ticket reference field
        'SYSAID#'
    ]
    
    cdhdr_cdpos_cols = [
        'Source', CDHDR_USER_COL, 'Datetime',
        CDHDR_TCODE_COL, CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL,
        CDHDR_CHANGENR_COL, CDHDR_CHANGE_FLAG_COL,
        CDPOS_TABNAME_COL, CDPOS_TABLE_KEY_COL, CDPOS_FNAME_COL,
        CDPOS_CHANGE_IND_COL, CDPOS_TEXT_FLAG_COL,
        CDPOS_VALUE_OLD_COL, CDPOS_VALUE_NEW_COL
    ]
    
    # Filter out excluded fields from both datasets
    if len(sm20) > 0:
        for field in EXCLUDE_FIELDS:
            if field in sm20.columns:
                sm20 = sm20.drop(columns=[field])
    
    if len(cdhdr_cdpos) > 0:
        for field in EXCLUDE_FIELDS:
            if field in cdhdr_cdpos.columns:
                cdhdr_cdpos = cdhdr_cdpos.drop(columns=[field])
    
    # Select and rename columns for SM20
    if len(sm20) > 0:
        # Only include columns that actually exist in the dataframe
        available_sm20_cols = [col for col in sm20_cols if col in sm20.columns or col == 'Source']
        sm20_subset = sm20[available_sm20_cols].copy()
        
        # Create a mapping dictionary for renaming
        rename_map = {
            SM20_USER_COL: 'User',
            SM20_TCODE_COL: 'TCode',
            SM20_MSG_COL: 'Description',
            SM20_EVENT_COL: 'Event',
            SM20_ABAP_SOURCE_COL: 'ABAP_Source',
            SM20_NOTE_COL: 'Note',
            # Variable field standardized names for debug detection
            'FIRST VARIABLE VALUE FOR EVENT': 'Variable_First',
            'VARIABLE 2': 'Variable_2',
            'VARIABLE 3': 'Variable_3',
            'VARIABLE DATA FOR MESSAGE': 'Variable_Data'
        }
        
        # Only include keys that exist in the dataframe
        rename_map = {k: v for k, v in rename_map.items() if k in sm20_subset.columns}
        sm20_subset = sm20_subset.rename(columns=rename_map)
        
        # Add empty columns for fields not in SM20
        for col in ['Object', 'Object_ID', 'Doc_Number', 'Change_Flag', 
                   'Table', 'Table_Key', 'Field', 'Change_Indicator', 
                   'Text_Flag', 'Old_Value', 'New_Value']:
            if col not in sm20_subset.columns:
                sm20_subset[col] = None
    else:
        sm20_subset = pd.DataFrame()
    
    # Select and rename columns for CDHDR/CDPOS
    if len(cdhdr_cdpos) > 0:
        # Only include columns that actually exist in the dataframe
        available_cdhdr_cdpos_cols = [col for col in cdhdr_cdpos_cols if col in cdhdr_cdpos.columns or col == 'Source']
        cdhdr_subset = cdhdr_cdpos[available_cdhdr_cdpos_cols].copy()
        
        # Create a mapping dictionary for renaming
        rename_map = {
            CDHDR_USER_COL: 'User',
            CDHDR_TCODE_COL: 'TCode',
            CDHDR_OBJECTCLAS_COL: 'Object',
            CDHDR_OBJECTID_COL: 'Object_ID',
            CDHDR_CHANGENR_COL: 'Doc_Number',
            CDHDR_CHANGE_FLAG_COL: 'Change_Flag',
            CDPOS_TABNAME_COL: 'Table',
            CDPOS_TABLE_KEY_COL: 'Table_Key',
            CDPOS_FNAME_COL: 'Field',
            CDPOS_CHANGE_IND_COL: 'Change_Indicator',
            CDPOS_TEXT_FLAG_COL: 'Text_Flag',
            CDPOS_VALUE_OLD_COL: 'Old_Value',
            CDPOS_VALUE_NEW_COL: 'New_Value'
        }
        
        # Standardize change indicator values to uppercase if present
        if CDPOS_CHANGE_IND_COL in cdhdr_subset.columns and not cdhdr_subset[CDPOS_CHANGE_IND_COL].isna().all():
            cdhdr_subset[CDPOS_CHANGE_IND_COL] = cdhdr_subset[CDPOS_CHANGE_IND_COL].astype(str).str.upper()
            log_message("Standardized all change indicators to uppercase")
        
        # Only include keys that exist in the dataframe
        rename_map = {k: v for k, v in rename_map.items() if k in cdhdr_subset.columns}
        cdhdr_subset = cdhdr_subset.rename(columns=rename_map)
        
        # Add Description column (combine object info)
        cdhdr_subset['Description'] = cdhdr_subset.apply(
            lambda x: f"Changed {x['Object']} {x['Object_ID']}" if pd.notna(x['Object']) else "", 
            axis=1
        )
        
        # Add empty columns for SM20 fields not in CDHDR/CDPOS
        for col in ['Event', 'ABAP_Source', 'Note']:
            if col not in cdhdr_subset.columns:
                cdhdr_subset[col] = None
    else:
        cdhdr_subset = pd.DataFrame()
    
    # Process SM20 and CDPOS separately to avoid concatenation issues
    sm20_original_count = 0
    cdpos_original_count = 0
    
    # Start with SM20 as the base timeline
    if len(sm20_subset) > 0:
        timeline = sm20_subset.copy()
        sm20_original_count = len(timeline)
        log_message(f"SM20 original count: {sm20_original_count} records")
    else:
        timeline = pd.DataFrame()
    
    # Then manually append CDPOS records one by one to avoid index conflicts
    if len(cdhdr_subset) > 0:
        cdpos_only = cdhdr_subset[cdhdr_subset['Source'] == 'CDPOS'].copy()
        cdpos_original_count = len(cdpos_only)
        log_message(f"CDPOS original count: {cdpos_original_count} records")
        
        if cdpos_original_count > 0:
            if len(timeline) > 0:
                # We have both SM20 and CDPOS data
                log_message(f"Manually appending {cdpos_original_count} CDPOS records to timeline")
                
                # Use a completely different approach - create a new dataframe
                log_message("Creating a fresh dataframe to safely combine SM20 and CDPOS data")
                
                # Create list of all column names
                all_columns = list(set(timeline.columns) | set(cdpos_only.columns))
                
                # Create empty DataFrame with all columns
                combined_data = []
                
                # Add SM20 data
                for _, row in timeline.iterrows():
                    row_dict = {}
                    for col in all_columns:
                        row_dict[col] = row[col] if col in timeline.columns else None
                    combined_data.append(row_dict)
                
                # Add CDPOS data
                for _, row in cdpos_only.iterrows():
                    row_dict = {}
                    for col in all_columns:
                        row_dict[col] = row[col] if col in cdpos_only.columns else None
                    combined_data.append(row_dict)
                
                # Create new DataFrame
                timeline = pd.DataFrame(combined_data)
            else:
                # We only have CDPOS data
                timeline = cdpos_only
    
    # If we still have no data, return empty DataFrame
    if len(timeline) == 0:
        return pd.DataFrame()
        
    # Log source-specific counts
    sm20_count = len(timeline[timeline['Source'] == 'SM20'])
    cdhdr_count = len(timeline[timeline['Source'] == 'CDHDR'])
    cdpos_count = len(timeline[timeline['Source'] == 'CDPOS'])
    log_message(f"Combined records - SM20: {sm20_count}, CDHDR: {cdhdr_count}, CDPOS: {cdpos_count}")
    
    # Validate record counts - SM20 + CDPOS = Total
    expected_count = (sm20_original_count if 'sm20_original_count' in locals() else 0) + \
                     (cdpos_original_count if 'cdpos_original_count' in locals() else 0)
    actual_count = len(timeline)
    
    if actual_count != expected_count:
        log_message(f"WARNING: Record count mismatch - Expected: {expected_count}, Actual: {actual_count}", "WARNING")
    else:
        log_message(f"Record count validation passed: {actual_count} records match expected total")
    
    # Remove the record_index column as it's no longer needed
    if 'record_index' in timeline.columns:
        timeline = timeline.drop(columns=['record_index'])
    
    # Find and standardize SysAid ticket numbers if present
    sysaid_col = find_sysaid_column(timeline)
    if sysaid_col:
        log_message(f"Found SysAid column: {sysaid_col}")
        timeline = standardize_sysaid_references(timeline, sysaid_col)
    
    # Now assign session IDs based on the combined timeline
    log_message("Assigning session IDs to combined timeline...")
    timeline = assign_session_ids(timeline, 'User', 'Datetime', sysaid_col=sysaid_col)
    
    # Extract numeric part of session ID for proper numerical sorting
    timeline['Session_Num'] = timeline['Session ID'].str.extract(r'S(\d+)').astype(int)
    
    # Sort by session number and datetime
    timeline = timeline.sort_values(by=['Session_Num', 'Datetime'])
    
    # Drop the temporary columns used for sorting
    timeline = timeline.drop(columns=['Session_Num', 'Session_Date'])
    
    # Reset index
    timeline = timeline.reset_index(drop=True)
    
    return timeline

def generate_excel_output(timeline, output_file):
    """Generate a formatted Excel output with the timeline."""
    try:
        # Ensure output directory exists
        output_dir = os.path.dirname(os.path.abspath(output_file))
        os.makedirs(output_dir, exist_ok=True)
        
        # Create a copy of the timeline with the Session ID with Date as the first column
        output_timeline = timeline.copy()
        
        # Reorder columns to put Session ID with Date first
        cols = output_timeline.columns.tolist()
        if 'Session ID with Date' in cols and 'Session ID' in cols:
            cols.remove('Session ID with Date')
            cols.insert(0, 'Session ID with Date')
            # Remove the original Session ID column
            cols.remove('Session ID')
            output_timeline = output_timeline[cols]
        
        # Create Excel writer
        with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
            # Write timeline to Excel
            output_timeline.to_excel(writer, sheet_name='Session_Timeline', index=False)
            
            # Get workbook and worksheet
            workbook = writer.book
            worksheet = writer.sheets['Session_Timeline']
            
            # Define formats
            header_format = workbook.add_format({
                'bold': True,
                'bg_color': '#4F81BD',
                'font_color': 'white',
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
            
            sm20_format = workbook.add_format({'bg_color': '#DCE6F1'})
            cdhdr_format = workbook.add_format({'bg_color': '#E6F0D0'})
            cdpos_format = workbook.add_format({'bg_color': '#FDE9D9'})
            
            # Apply header format
            for col_num, col_name in enumerate(output_timeline.columns):
                worksheet.write(0, col_num, col_name, header_format)
                
            # Set column widths for all fields
            column_widths = {
                'Session ID with Date': 20,
                'Source': 8,
                'User': 12,
                'Datetime': 18,
                'Event': 15,
                'TCode': 10,
                'ABAP_Source': 15,
                'Description': 40,
                'Note': 20,
                'Object': 15,
                'Object_ID': 15,
                'Doc_Number': 12,
                'Change_Flag': 15,
                'Table': 15,
                'Table_Key': 20,
                'Field': 20,
                'Change_Indicator': 10,
                'Text_Flag': 10,
                'Old_Value': 25,
                'New_Value': 25
            }
            
            # Apply column widths based on the actual columns in the output
            for i, col_name in enumerate(output_timeline.columns):
                if col_name in column_widths:
                    worksheet.set_column(i, i, column_widths[col_name])
                else:
                    # Default width for any columns not explicitly specified
                    worksheet.set_column(i, i, 15)
            
            # Apply conditional formatting based on Source
            worksheet.conditional_format(1, 0, len(timeline), len(timeline.columns)-1, {
                'type': 'formula',
                'criteria': '=$B2="SM20"',
                'format': sm20_format
            })
            
            worksheet.conditional_format(1, 0, len(timeline), len(timeline.columns)-1, {
                'type': 'formula',
                'criteria': '=$B2="CDHDR"',
                'format': cdhdr_format
            })
            
            worksheet.conditional_format(1, 0, len(timeline), len(timeline.columns)-1, {
                'type': 'formula',
                'criteria': '=$B2="CDPOS"',
                'format': cdpos_format
            })
            
            # Add autofilter
            worksheet.autofilter(0, 0, len(timeline), len(timeline.columns)-1)
            
            # Freeze panes
            worksheet.freeze_panes(1, 0)
            
        log_message(f"Excel output successfully generated: {output_file}")
        return True
    except Exception as e:
        log_message(f"Error generating Excel output: {str(e)}", "ERROR")
        return False

# --- Main Function ---
def main():
    """Main function to execute the SAP log session merger."""
    start_time = datetime.now()
    log_message("Starting SAP Log Session Merger...")
    
    try:
        # Step 1: Load input files
        sm20 = load_csv_file(SM20_FILE)
        cdhdr = load_csv_file(CDHDR_FILE)
        cdpos = load_csv_file(CDPOS_FILE)
        
        if len(sm20) == 0 and len(cdhdr) == 0:
            log_message("No valid data found in input files.", "ERROR")
            return False
        
        # Step 2: Prepare data
        sm20_prepared = prepare_sm20(sm20)
        
        # Standardize SysAid references if present
        sysaid_col = find_sysaid_column(sm20_prepared)
        if sysaid_col:
            log_message(f"Standardizing SysAid ticket references in column: {sysaid_col}")
            sm20_prepared = standardize_sysaid_references(sm20_prepared, sysaid_col)
            
        cdhdr_prepared = prepare_cdhdr(cdhdr)
        
        # Step 3: Merge CDHDR with CDPOS
        cdhdr_cdpos = merge_cdhdr_cdpos(cdhdr_prepared, cdpos)
        
        # Step 4: Create unified timeline
        timeline = create_unified_timeline(sm20_prepared, cdhdr_cdpos)
        
        if len(timeline) == 0:
            log_message("No data to output after processing.", "WARNING")
            return False
            
        # Step 5: Generate Excel output
        success = generate_excel_output(timeline, OUTPUT_FILE)
        
        # Calculate elapsed time
        elapsed_time = (datetime.now() - start_time).total_seconds()
        log_message(f"Processing complete in {elapsed_time:.2f} seconds.")
        
        if success:
            log_message(f"Session timeline saved to: {os.path.abspath(OUTPUT_FILE)}")
            print(f"\nSession timeline saved to: {os.path.abspath(OUTPUT_FILE)}")
        
        return success
    
    except Exception as e:
        log_message(f"Error in main execution: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return False

# --- Script Entry Point ---
if __name__ == "__main__":
    # Add a banner
    banner = "\n" + "="*80 + "\n"
    banner += " SAP LOG SESSION MERGER ".center(80, "*") + "\n"
    banner += " Creates a unified session timeline from SAP logs ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)
    
    main()
