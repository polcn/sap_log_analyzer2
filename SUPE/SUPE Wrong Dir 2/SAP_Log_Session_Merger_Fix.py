#!/usr/bin/env python3
"""
SAP Log Session Merger - Enhanced Version

This script combines SM20, CDHDR, and CDPOS logs into a user session timeline.
It creates a unified, chronological view of SAP user activity for internal audit purposes.

Key features:
- Assigns session IDs based on user activity with a 60-minute timeout
- Preserves all relevant fields from each source
- Joins CDHDR with CDPOS to show field-level changes
- Creates a formatted Excel output with color-coding by source
- Enhanced record count tracking for validation

Updates:
- Added detailed record count validation and logging
- Added explicit tracking of source record integration
- Fixed potential record count inconsistencies
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

# Validation log file
VALIDATION_LOG = os.path.join(SCRIPT_DIR, "session_merger_validation.log")

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
SM20_VAR_FIRST_COL = 'FIRST VARIABLE VALUE FOR EVENT'
SM20_VAR_2_COL = 'VARIABLE 2'
SM20_VAR_DATA_COL = 'VARIABLE DATA FOR MESSAGE'

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
EXCLUDE_FIELDS = ['SYSAID #', 'COMMENTS']

# --- Utility Functions ---
def log_message(message, level="INFO", validation_log=False):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {level}: {message}"
    
    # Print to console
    print(log_entry)
    
    # Write to validation log if requested
    if validation_log:
        try:
            with open(VALIDATION_LOG, 'a') as f:
                f.write(f"{log_entry}\n")
        except Exception as e:
            print(f"[{timestamp}] WARNING: Could not write to validation log: {str(e)}")

def validate_record_counts(source_name, original_count, processed_count, final_count=None):
    """Validate and log record counts through processing stages."""
    message = f"Record count validation for {source_name}:"
    message += f"\n  * Original records: {original_count}"
    message += f"\n  * After processing: {processed_count}"
    
    if original_count != processed_count:
        message += f"\n  * Difference: {processed_count - original_count}"
        message += f"\n  * Reason: Records may have been filtered or had invalid dates/values"
        log_message(message, level="WARNING", validation_log=True)
    else:
        message += "\n  * All records preserved through processing"
        log_message(message, level="INFO", validation_log=True)
    
    if final_count is not None:
        if final_count != processed_count:
            log_message(
                f"Final {source_name} count ({final_count}) differs from processed count ({processed_count}).\n"
                f"Difference: {final_count - processed_count} records.\n"
                f"This is expected if records were merged from multiple sources.",
                level="INFO", validation_log=True
            )

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

def assign_session_ids(df, user_col, time_col, session_timeout_minutes=60, session_col='Session ID'):
    """
    Assign session IDs to rows based on user and timestamp.
    A new session starts when:
    1. User changes, or
    2. Time gap exceeds the session timeout
    
    Sessions are numbered chronologically by their start time.
    """
    if len(df) == 0:
        return df
        
    # Make a copy to avoid SettingWithCopyWarning
    df = df.sort_values(by=[user_col, time_col]).copy()
    
    # First pass: identify session boundaries
    session_boundaries = []
    prev_user = None
    prev_time = None
    session_id = 0
    
    for idx, row in df.iterrows():
        user = row[user_col]
        dt = row[time_col]
        
        # Start a new session if user changes or timeout exceeded
        if user != prev_user or (prev_time and (dt - prev_time) > timedelta(minutes=session_timeout_minutes)):
            session_id += 1
            # Store the session ID, start time, and index
            session_boundaries.append((session_id, dt, idx))
            
        prev_user = user
        prev_time = dt
    
    # Sort sessions by start time
    session_boundaries.sort(key=lambda x: x[1])
    
    # Create mapping from original session ID to chronological session ID
    session_mapping = {orig_id: f"S{i+1:04}" for i, (orig_id, _, _) in enumerate(session_boundaries)}
    
    # Second pass: assign chronological session IDs
    session_ids = []
    prev_user = None
    prev_time = None
    current_session_id = 0
    
    for _, row in df.iterrows():
        user = row[user_col]
        dt = row[time_col]
        
        # Start a new session if user changes or timeout exceeded
        if user != prev_user or (prev_time and (dt - prev_time) > timedelta(minutes=session_timeout_minutes)):
            current_session_id += 1
            
        # Map to chronological session ID
        chronological_id = session_mapping[current_session_id]
        session_ids.append(chronological_id)
        
        prev_user = user
        prev_time = dt

    # Add session ID column
    df[session_col] = session_ids
    
    return df

# --- Data Processing Functions ---
def prepare_sm20(sm20):
    """Prepare SM20 data with datetime and session IDs."""
    original_count = len(sm20)
    log_message(f"Starting SM20 preparation with {original_count} records")
    
    if len(sm20) == 0:
        log_message("No SM20 records to process", "WARNING")
        return sm20
        
    # Create datetime column
    sm20['Datetime'] = pd.to_datetime(
        sm20[SM20_DATE_COL].astype(str) + ' ' + sm20[SM20_TIME_COL].astype(str),
        errors='coerce'
    )
    
    # Log invalid date records before dropping
    invalid_dates = sm20[sm20['Datetime'].isna()]
    if len(invalid_dates) > 0:
        log_message(f"Dropping {len(invalid_dates)} SM20 records with invalid dates", "WARNING", validation_log=True)
        for idx, row in invalid_dates.iterrows():
            log_message(f"  Invalid date: {row[SM20_DATE_COL]} {row[SM20_TIME_COL]}", "DEBUG", validation_log=True)
    
    # Drop rows with invalid datetime
    sm20 = sm20.dropna(subset=['Datetime'])
    post_date_count = len(sm20)
    
    if original_count != post_date_count:
        log_message(f"SM20 record count after date validation: {post_date_count} (dropped {original_count - post_date_count})", 
                   "WARNING", validation_log=True)
    
    # Assign session IDs
    sm20 = assign_session_ids(sm20, SM20_USER_COL, 'Datetime')
    
    # Add source identifier
    sm20['Source'] = 'SM20'
    
    # Validate record counts
    processed_count = len(sm20)
    validate_record_counts('SM20', original_count, processed_count)
    
    return sm20

def prepare_cdhdr(cdhdr):
    """Prepare CDHDR data with datetime and session IDs."""
    original_count = len(cdhdr)
    log_message(f"Starting CDHDR preparation with {original_count} records")
    
    if len(cdhdr) == 0:
        log_message("No CDHDR records to process", "WARNING")
        return cdhdr
        
    # Create datetime column
    cdhdr['Datetime'] = pd.to_datetime(
        cdhdr[CDHDR_DATE_COL].astype(str) + ' ' + cdhdr[CDHDR_TIME_COL].astype(str),
        errors='coerce'
    )
    
    # Log invalid date records before dropping
    invalid_dates = cdhdr[cdhdr['Datetime'].isna()]
    if len(invalid_dates) > 0:
        log_message(f"Dropping {len(invalid_dates)} CDHDR records with invalid dates", "WARNING", validation_log=True)
        for idx, row in invalid_dates.iterrows():
            log_message(f"  Invalid date: {row[CDHDR_DATE_COL]} {row[CDHDR_TIME_COL]}", "DEBUG", validation_log=True)
    
    # Drop rows with invalid datetime
    cdhdr = cdhdr.dropna(subset=['Datetime'])
    post_date_count = len(cdhdr)
    
    if original_count != post_date_count:
        log_message(f"CDHDR record count after date validation: {post_date_count} (dropped {original_count - post_date_count})", 
                   "WARNING", validation_log=True)
    
    # Assign session IDs
    cdhdr = assign_session_ids(cdhdr, CDHDR_USER_COL, 'Datetime')
    
    # Add source identifier
    cdhdr['Source'] = 'CDHDR'
    
    # Validate record counts
    processed_count = len(cdhdr)
    validate_record_counts('CDHDR', original_count, processed_count)
    
    return cdhdr

def merge_cdhdr_cdpos(cdhdr, cdpos):
    """Merge CDHDR with CDPOS data with enhanced record tracking."""
    cdhdr_count = len(cdhdr)
    cdpos_count = len(cdpos)
    
    log_message(f"Merging CDHDR ({cdhdr_count} records) with CDPOS ({cdpos_count} records)")
    
    if len(cdhdr) == 0 or len(cdpos) == 0:
        if len(cdhdr) == 0:
            log_message("No CDHDR records for merging", "WARNING")
        if len(cdpos) == 0:
            log_message("No CDPOS records for merging", "WARNING")
        return pd.DataFrame()
        
    # Merge on OBJECTCLAS, OBJECTID, and CHANGENR as per requirements
    merged = pd.merge(
        cdhdr,
        cdpos,
        left_on=[CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL, CDHDR_CHANGENR_COL],
        right_on=[CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL, CDPOS_CHANGENR_COL],
        how='left'
    )
    
    # Count CDPOS records successfully joined
    cdpos_matched = merged[merged[CDPOS_TABNAME_COL].notna()].shape[0]
    cdpos_unmatched = cdpos_count - cdpos_matched
    
    log_message(f"CDPOS matching: {cdpos_matched} joined, {cdpos_unmatched} unmatched", validation_log=True)
    
    # Update source for rows with CDPOS data
    merged.loc[merged[CDPOS_TABNAME_COL].notna(), 'Source'] = 'CDPOS'
    
    # Validate total record counts after merge
    merged_count = len(merged)
    merged_cdpos_count = len(merged[merged['Source'] == 'CDPOS'])
    merged_cdhdr_count = len(merged[merged['Source'] == 'CDHDR'])
    
    log_message(f"After merging: {merged_count} total records", validation_log=True)
    log_message(f"  - CDHDR records remaining: {merged_cdhdr_count}", validation_log=True)
    log_message(f"  - CDPOS records created: {merged_cdpos_count}", validation_log=True)
    
    if merged_count > cdhdr_count:
        log_message(
            f"Merge expanded record count by {merged_count - cdhdr_count} records due to "
            f"multiple CDPOS records matching single CDHDR records",
            validation_log=True
        )
    
    return merged

def create_unified_timeline(sm20, cdhdr_cdpos):
    """Create a unified timeline from all sources with proper session assignment and validation."""
    # Log initial record counts
    sm20_count = len(sm20)
    cdhdr_cdpos_count = len(cdhdr_cdpos)
    
    log_message("Creating unified timeline")
    log_message(f"Initial record counts:", validation_log=True)
    log_message(f"  - SM20: {sm20_count} records", validation_log=True)
    log_message(f"  - CDHDR/CDPOS: {cdhdr_cdpos_count} records", validation_log=True)
    log_message(f"  - Total: {sm20_count + cdhdr_cdpos_count} records", validation_log=True)
    
    # Define columns to keep from each source (excluding Session ID which we'll reassign)
    sm20_cols = [
        'Source', SM20_USER_COL, 'Datetime', 
        SM20_EVENT_COL, SM20_TCODE_COL, SM20_ABAP_SOURCE_COL, 
        SM20_MSG_COL, SM20_NOTE_COL,
        SM20_VAR_FIRST_COL, SM20_VAR_2_COL, SM20_VAR_DATA_COL
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
                log_message(f"Removing excluded field '{field}' from SM20", validation_log=True)
                sm20 = sm20.drop(columns=[field])
    
    if len(cdhdr_cdpos) > 0:
        for field in EXCLUDE_FIELDS:
            if field in cdhdr_cdpos.columns:
                log_message(f"Removing excluded field '{field}' from CDHDR/CDPOS", validation_log=True)
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
            SM20_VAR_FIRST_COL: 'Variable_First',
            SM20_VAR_2_COL: 'Variable_2',
            SM20_VAR_DATA_COL: 'Variable_Data'
        }
        
        # Only include keys that exist in the dataframe
        rename_map = {k: v for k, v in rename_map.items() if k in sm20_subset.columns}
        sm20_subset = sm20_subset.rename(columns=rename_map)
        
        # Verify count after column selection
        post_subset_sm20_count = len(sm20_subset)
        if post_subset_sm20_count != sm20_count:
            log_message(
                f"SM20 record count changed after column selection: {sm20_count} -> {post_subset_sm20_count}",
                "WARNING", validation_log=True
            )
        
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
        
        # Verify count after column selection
        post_subset_cdhdr_count = len(cdhdr_subset)
        if post_subset_cdhdr_count != cdhdr_cdpos_count:
            log_message(
                f"CDHDR/CDPOS record count changed after column selection: {cdhdr_cdpos_count} -> {post_subset_cdhdr_count}",
                "WARNING", validation_log=True
            )
        
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
    
    # Combine datasets
    if len(sm20_subset) > 0 and len(cdhdr_subset) > 0:
        timeline = pd.concat([sm20_subset, cdhdr_subset], ignore_index=True)
    elif len(sm20_subset) > 0:
        timeline = sm20_subset
    elif len(cdhdr_subset) > 0:
        timeline = cdhdr_subset
    else:
        log_message("No data to combine into timeline", "WARNING", validation_log=True)
        return pd.DataFrame()
    
    # Now assign session IDs based on the combined timeline
    log_message("Assigning session IDs to combined timeline...")
    timeline = assign_session_ids(timeline, 'User', 'Datetime')
    
    # Add date to session ID for clarity
    timeline['Session_Date'] = timeline['Datetime'].dt.strftime('%Y-%m-%d')
    timeline['Session ID with Date'] = timeline.apply(
        lambda x: f"{x['Session ID']} ({x['Session_Date']})", axis=1
    )
    
    # Extract numeric part of session ID for proper numerical sorting
    timeline['Session_Num'] = timeline['Session ID'].str.extract(r'S(\d+)').astype(int)
    
    # Sort by session number and datetime
    timeline = timeline.sort_values(by=['Session_Num', 'Datetime'])
    
    # Drop the temporary columns used for sorting
    timeline = timeline.drop(columns=['Session_Num', 'Session_Date'])
    
    # Reset index
    timeline = timeline.reset_index(drop=True)
    
    # Final record count validation
    final_count = len(timeline)
    final_sm20_count = len(timeline[timeline['Source'] == 'SM20'])
    final_cdpos_count = len(timeline[timeline['Source'] == 'CDPOS'])
    final_cdhdr_count = len(timeline[timeline['Source'] == 'CDHDR'])
    
    log_message("Final timeline record count analysis:", validation_log=True)
    log_message(f"  - Total timeline records: {final_count}", validation_log=True)
    log_message(f"  - SM20 records: {final
