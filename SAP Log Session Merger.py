#!/usr/bin/env python3
"""
SAP Log Session Merger

This script combines SM20, CDHDR, and CDPOS logs into a user session timeline.
It creates a unified, chronological view of SAP user activity for internal audit purposes.

Key features:
- Assigns session IDs based on user activity per calendar day (date-based sessions)
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
EXCLUDE_FIELDS = ['SYSAID #', 'COMMENTS']

# --- Utility Functions ---
def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

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

def assign_session_ids(df, user_col, time_col, session_col='Session ID'):
    """
    Assign session IDs to rows based on user and calendar date.
    A new session starts when:
    1. User changes, or
    2. Date changes (calendar day boundary)
    
    Sessions are numbered chronologically by their start date/time.
    """
    if len(df) == 0:
        return df
        
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
    
    return df

# --- Data Processing Functions ---
def prepare_sm20(sm20):
    """Prepare SM20 data with datetime and session IDs."""
    if len(sm20) == 0:
        return sm20
        
    # Create datetime column
    sm20['Datetime'] = pd.to_datetime(
        sm20[SM20_DATE_COL].astype(str) + ' ' + sm20[SM20_TIME_COL].astype(str),
        errors='coerce'
    )
    
    # Drop rows with invalid datetime
    sm20 = sm20.dropna(subset=['Datetime'])
    
    # Assign session IDs
    sm20 = assign_session_ids(sm20, SM20_USER_COL, 'Datetime')
    
    # Add source identifier
    sm20['Source'] = 'SM20'
    
    return sm20

def prepare_cdhdr(cdhdr):
    """Prepare CDHDR data with datetime and session IDs."""
    if len(cdhdr) == 0:
        return cdhdr
        
    # Create datetime column
    cdhdr['Datetime'] = pd.to_datetime(
        cdhdr[CDHDR_DATE_COL].astype(str) + ' ' + cdhdr[CDHDR_TIME_COL].astype(str),
        errors='coerce'
    )
    
    # Drop rows with invalid datetime
    cdhdr = cdhdr.dropna(subset=['Datetime'])
    
    # Assign session IDs
    cdhdr = assign_session_ids(cdhdr, CDHDR_USER_COL, 'Datetime')
    
    # Add source identifier
    cdhdr['Source'] = 'CDHDR'
    
    return cdhdr

def merge_cdhdr_cdpos(cdhdr, cdpos):
    """Merge CDHDR with CDPOS data."""
    if len(cdhdr) == 0 or len(cdpos) == 0:
        return pd.DataFrame()
        
    # Merge on OBJECTCLAS, OBJECTID, and CHANGENR as per requirements
    merged = pd.merge(
        cdhdr,
        cdpos,
        left_on=[CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL, CDHDR_CHANGENR_COL],
        right_on=[CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL, CDPOS_CHANGENR_COL],
        how='left'
    )
    
    # Update source for rows with CDPOS data
    merged.loc[merged[CDPOS_TABNAME_COL].notna(), 'Source'] = 'CDPOS'
    
    return merged

def create_unified_timeline(sm20, cdhdr_cdpos):
    """Create a unified timeline from all sources with proper session assignment."""
    # Define columns to keep from each source (excluding Session ID which we'll reassign)
    sm20_cols = [
        'Source', SM20_USER_COL, 'Datetime', 
        SM20_EVENT_COL, SM20_TCODE_COL, SM20_ABAP_SOURCE_COL, 
        SM20_MSG_COL, SM20_NOTE_COL,
        # Variable fields needed for debug detection
        'FIRST VARIABLE VALUE FOR EVENT', 'VARIABLE 2', 'VARIABLE 3',
        'VARIABLE DATA FOR MESSAGE'
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
    
    # Combine datasets
    if len(sm20_subset) > 0 and len(cdhdr_subset) > 0:
        timeline = pd.concat([sm20_subset, cdhdr_subset], ignore_index=True)
    elif len(sm20_subset) > 0:
        timeline = sm20_subset
    elif len(cdhdr_subset) > 0:
        timeline = cdhdr_subset
    else:
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
