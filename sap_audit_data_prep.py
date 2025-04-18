#!/usr/bin/env python3
"""
SAP Audit Data Preparation Script

This script prepares SAP log data files for the main audit tool by:
1. Finding input files matching specific patterns in the input folder
2. Converting all column headers to UPPERCASE
3. Creating datetime columns from date and time fields
4. Sorting data by user and datetime
5. Saving the processed files as CSV with UTF-8-sig encoding in the same input folder
"""

import os
import sys
import glob
import pandas as pd
from datetime import datetime, timedelta

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(SCRIPT_DIR, "input")

# File patterns to search for
SM20_PATTERN = os.path.join(INPUT_DIR, "*_sm20_*.xlsx")
CDHDR_PATTERN = os.path.join(INPUT_DIR, "*_cdhdr_*.xlsx")
CDPOS_PATTERN = os.path.join(INPUT_DIR, "*_cdpos_*.xlsx")

# Output file paths
SM20_OUTPUT_FILE = os.path.join(INPUT_DIR, "SM20.csv")
CDHDR_OUTPUT_FILE = os.path.join(INPUT_DIR, "CDHDR.csv")
CDPOS_OUTPUT_FILE = os.path.join(INPUT_DIR, "CDPOS.csv")

# Column name constants (UPPERCASE)
# SM20 Security Audit Log columns
SM20_USER_COL = 'USER'
SM20_DATE_COL = 'DATE'
SM20_TIME_COL = 'TIME'
SM20_EVENT_COL = 'EVENT'
SM20_TCODE_COL = 'SOURCE TA'
SM20_ABAP_SOURCE_COL = 'ABAP SOURCE'
SM20_MSG_COL = 'AUDIT LOG MSG. TEXT'
SM20_NOTE_COL = 'NOTE'
# SM20 Debugging/RFC Analysis fields
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

# Date/Time format
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'  # Matches '2025-03-10 19:17:23' format

# --- Utility Functions ---
def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def find_latest_file(pattern):
    """Find the most recent file matching the pattern."""
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)

def clean_whitespace(df):
    """Clean whitespace from all string columns in the dataframe."""
    log_message("Cleaning whitespace from string columns...")
    
    for col in df.columns:
        if df[col].dtype == 'object':  # Only process string/object columns
            df[col] = df[col].astype(str).str.strip()
            
    # Report the cleaning
    log_message(f"Cleaned whitespace from {sum(df.dtypes == 'object')} string columns")
    return df

def process_sm20(input_file, output_file):
    """Process SM20 file with enhanced data preparation."""
    try:
        # Read the Excel file
        log_message(f"Reading SM20 file: {input_file}")
        df = pd.read_excel(input_file)
        
        # Get original column count
        original_columns = df.columns.tolist()
        log_message(f"Original columns: {len(original_columns)}")
        
        # Store original column names for later mapping
        original_col_names = df.columns.tolist()
        
        # Convert column headers to UPPERCASE
        df.columns = [col.strip().upper() for col in df.columns]
        log_message(f"Converted {len(df.columns)} column headers to UPPERCASE")
        
        # Clean whitespace from all string columns
        df = clean_whitespace(df)
        
        # Handle field mapping for SM20 columns that may have different names in different extracts
        # This is based on SAP's dynamic column behavior where field labels can change based on
        # GUI layout, language, and kernel patch level
        field_mapping = {
            # Transaction code variations
            'TCODE': SM20_TCODE_COL,
            'TRANSACTION': SM20_TCODE_COL,
            'TRANSACTION CODE': SM20_TCODE_COL,
            
            # ABAP program variations
            'PROGRAM': SM20_ABAP_SOURCE_COL,
            
            # Variable field variations - based on SAP export behavior
            # First variable
            'FIRST VARIABLE': SM20_VAR_FIRST_COL,
            'VARIABLE 1': SM20_VAR_FIRST_COL,
            'VARIABLE_1': SM20_VAR_FIRST_COL,
            'VAR1': SM20_VAR_FIRST_COL,
            
            # Second variable/data field - these are actually the same field with different labels
            'VARIABLE 2': SM20_VAR_DATA_COL,  # In March extract
            'VARIABLE DATA': SM20_VAR_DATA_COL,  # In January extract
            'VARIABLE_2': SM20_VAR_DATA_COL,
            'VAR2': SM20_VAR_DATA_COL,
            
            # Third variable field - can be VARIABLE 3 in some extracts
            'VARIABLE 3': SM20_VAR_DATA_COL,  # Also maps to VAR_DATA as per SAP's behavior
            'VARIABLE_3': SM20_VAR_DATA_COL,
            'VAR3': SM20_VAR_DATA_COL
        }
        
        # Apply field mapping - only if target column doesn't already exist
        for old_name, new_name in field_mapping.items():
            if old_name in df.columns and new_name not in df.columns:
                df[new_name] = df[old_name]
                log_message(f"Mapped SM20 column {old_name} → {new_name}")
        
        # Check for important fields
        important_sm20_fields = [
            SM20_USER_COL, SM20_DATE_COL, SM20_TIME_COL, SM20_TCODE_COL, 
            SM20_MSG_COL, SM20_EVENT_COL, SM20_ABAP_SOURCE_COL, SM20_NOTE_COL,
            SM20_VAR_FIRST_COL, SM20_VAR_2_COL, SM20_VAR_DATA_COL
        ]
        
        # Add empty columns for any missing fields to ensure consistent schema
        for field in important_sm20_fields:
            if field not in df.columns:
                log_message(f"Warning: Important field '{field}' not found in SM20 data - adding empty column", "WARNING")
                df[field] = ""  # Add empty column
        
        # Filter out excluded fields
        for field in EXCLUDE_FIELDS:
            if field in df.columns:
                log_message(f"Removing excluded field '{field}' from SM20 data")
                df = df.drop(columns=[field])
        
        # Create datetime column
        log_message("Creating datetime column from date and time fields")
        try:
            if SM20_DATE_COL in df.columns and SM20_TIME_COL in df.columns:
                df['DATETIME'] = pd.to_datetime(
                    df[SM20_DATE_COL].astype(str) + ' ' + df[SM20_TIME_COL].astype(str),
                    format=DATETIME_FORMAT,
                    errors='coerce'
                )
                
                # Drop rows with invalid datetime
                invalid_dates = df[df['DATETIME'].isna()]
                if len(invalid_dates) > 0:
                    log_message(f"Warning: Dropping {len(invalid_dates)} SM20 rows with invalid dates", "WARNING")
                    df = df.dropna(subset=['DATETIME'])
            else:
                log_message(f"Warning: Cannot create datetime column, missing date or time column", "WARNING")
        except Exception as e:
            log_message(f"Warning: Could not create datetime column: {str(e)}", "WARNING")
        
        # Sort by user and datetime
        if SM20_USER_COL in df.columns and 'DATETIME' in df.columns:
            log_message("Sorting SM20 data by user and datetime")
            df = df.sort_values(by=[SM20_USER_COL, 'DATETIME'])
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Save to output file as CSV with UTF-8-sig encoding
        log_message(f"Saving processed SM20 file to: {output_file}")
        df.to_csv(output_file, index=False, encoding='utf-8-sig')
        log_message(f"Successfully saved {len(df)} rows to {output_file}")
        
        return True
    except Exception as e:
        log_message(f"Error processing SM20 file {input_file}: {str(e)}", "ERROR")
        return False

def process_cdhdr(input_file, output_file):
    """Process CDHDR file with enhanced data preparation."""
    try:
        # Read the Excel file
        log_message(f"Reading CDHDR file: {input_file}")
        df = pd.read_excel(input_file)
        
        # Get original column count
        original_columns = df.columns.tolist()
        log_message(f"Original columns: {len(original_columns)}")
        
        # Convert column headers to UPPERCASE
        df.columns = [col.strip().upper() for col in df.columns]
        log_message(f"Converted {len(df.columns)} column headers to UPPERCASE")
        
        # Clean whitespace from all string columns
        df = clean_whitespace(df)
        
        # Handle field mapping for alternate field names that might be in raw exports
        # Enhanced based on the SAP's variable field dynamics across different exports
        field_mapping = {
            # Transaction code variations
            'TRANSACTION CODE': CDHDR_TCODE_COL,
            'SOURCE TA': CDHDR_TCODE_COL,
            
            # Variable field variations
            # First variable
            'FIRST VARIABLE VALUE FOR EVENT': SM20_VAR_FIRST_COL,
            'FIRST VARIABLE': SM20_VAR_FIRST_COL,
            'VARIABLE 1': SM20_VAR_FIRST_COL,
            'VARIABLE_1': SM20_VAR_FIRST_COL,
            'VARIABLE1': SM20_VAR_FIRST_COL,
            'VAR_1': SM20_VAR_FIRST_COL,
            'VAR1': SM20_VAR_FIRST_COL,
            
            # Second variable/data field - these are the same field with different labels
            'VARIABLE 2': SM20_VAR_DATA_COL,  # March extract
            'VARIABLE DATA': SM20_VAR_DATA_COL,  # January extract
            'VARIABLE DATA FOR MESSAGE': SM20_VAR_DATA_COL,  # February extract
            'VARIABLE_2': SM20_VAR_DATA_COL,
            'VARIABLE2': SM20_VAR_DATA_COL,
            'VAR_2': SM20_VAR_DATA_COL,
            'VAR2': SM20_VAR_DATA_COL,
            'VARIABL_D': SM20_VAR_DATA_COL,
            'VARIABLE_D': SM20_VAR_DATA_COL,
            'VARIABLED': SM20_VAR_DATA_COL,
            'VAR_D': SM20_VAR_DATA_COL,
            'VAR_DATA': SM20_VAR_DATA_COL,
            
            # Third variable field
            'VARIABLE 3': SM20_VAR_DATA_COL,  # Maps to VAR_DATA as per SAP behavior
            'VARIABLE_3': SM20_VAR_DATA_COL,
            'VARIABLE3': SM20_VAR_DATA_COL,
            'VAR_3': SM20_VAR_DATA_COL,
            'VAR3': SM20_VAR_DATA_COL
        }
        
        # Rename columns if they exist with different names
        for old_name, new_name in field_mapping.items():
            if old_name in df.columns and new_name not in df.columns:
                df[new_name] = df[old_name]
                log_message(f"Mapped {old_name} to {new_name}")
        
        # Check for important fields
        important_cdhdr_fields = [
            CDHDR_USER_COL, CDHDR_DATE_COL, CDHDR_TIME_COL, CDHDR_TCODE_COL,
            CDHDR_CHANGENR_COL, CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL,
            CDHDR_CHANGE_FLAG_COL
        ]
        
        # Add empty columns for any missing fields to ensure consistent schema
        for field in important_cdhdr_fields:
            if field not in df.columns:
                log_message(f"Warning: Important field '{field}' not found in CDHDR data - adding empty column", "WARNING")
                df[field] = ""  # Add empty column
        
        # Filter out excluded fields
        for field in EXCLUDE_FIELDS:
            if field in df.columns:
                log_message(f"Removing excluded field '{field}' from CDHDR data")
                df = df.drop(columns=[field])
        
        # Create datetime column
        log_message("Creating datetime column from date and time fields")
        try:
            if CDHDR_DATE_COL in df.columns and CDHDR_TIME_COL in df.columns:
                df['DATETIME'] = pd.to_datetime(
                    df[CDHDR_DATE_COL].astype(str) + ' ' + df[CDHDR_TIME_COL].astype(str),
                    format=DATETIME_FORMAT,
                    errors='coerce'
                )
                
                # Drop rows with invalid datetime
                invalid_dates = df[df['DATETIME'].isna()]
                if len(invalid_dates) > 0:
                    log_message(f"Warning: Dropping {len(invalid_dates)} CDHDR rows with invalid dates", "WARNING")
                    df = df.dropna(subset=['DATETIME'])
            else:
                log_message(f"Warning: Cannot create datetime column, missing date or time column", "WARNING")
        except Exception as e:
            log_message(f"Warning: Could not create datetime column: {str(e)}", "WARNING")
        
        # Sort by user and datetime
        if CDHDR_USER_COL in df.columns and 'DATETIME' in df.columns:
            log_message("Sorting CDHDR data by user and datetime")
            df = df.sort_values(by=[CDHDR_USER_COL, 'DATETIME'])
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Save to output file as CSV with UTF-8-sig encoding
        log_message(f"Saving processed CDHDR file to: {output_file}")
        df.to_csv(output_file, index=False, encoding='utf-8-sig')
        log_message(f"Successfully saved {len(df)} rows to {output_file}")
        
        return True
    except Exception as e:
        log_message(f"Error processing CDHDR file {input_file}: {str(e)}", "ERROR")
        return False

def process_cdpos(input_file, output_file):
    """Process CDPOS file with enhanced data preparation."""
    try:
        # Read the Excel file
        log_message(f"Reading CDPOS file: {input_file}")
        df = pd.read_excel(input_file)
        
        # Get original column count
        original_columns = df.columns.tolist()
        log_message(f"Original columns: {len(original_columns)}")
        
        # Convert column headers to UPPERCASE
        df.columns = [col.strip().upper() for col in df.columns]
        log_message(f"Converted {len(df.columns)} column headers to UPPERCASE")
        
        # Clean whitespace from all string columns
        df = clean_whitespace(df)
        
        # Check for important fields
        important_cdpos_fields = [
            CDPOS_CHANGENR_COL, CDPOS_TABNAME_COL, CDPOS_TABLE_KEY_COL,
            CDPOS_FNAME_COL, CDPOS_CHANGE_IND_COL, CDPOS_TEXT_FLAG_COL,
            CDPOS_VALUE_NEW_COL, CDPOS_VALUE_OLD_COL
        ]
        
        # Add empty columns for any missing fields to ensure consistent schema
        for field in important_cdpos_fields:
            if field not in df.columns:
                log_message(f"Warning: Important field '{field}' not found in CDPOS data - adding empty column", "WARNING")
                df[field] = ""  # Add empty column
        
        # Filter out excluded fields
        for field in EXCLUDE_FIELDS:
            if field in df.columns:
                log_message(f"Removing excluded field '{field}' from CDPOS data")
                df = df.drop(columns=[field])
        
        # Log change indicator values if present
        if CDPOS_CHANGE_IND_COL in df.columns:
            # Instead of validating against a fixed set, just log the unique values
            unique_indicators = df[CDPOS_CHANGE_IND_COL].dropna().unique()
            log_message(f"Found {len(unique_indicators)} unique change indicator values: {', '.join(map(str, unique_indicators))}")
            
            # Convert all indicators to uppercase for consistency
            if not df[CDPOS_CHANGE_IND_COL].isna().all():
                df[CDPOS_CHANGE_IND_COL] = df[CDPOS_CHANGE_IND_COL].astype(str).str.upper()
                log_message("Standardized all change indicators to uppercase")
        
        # Sort by change document number
        if CDPOS_CHANGENR_COL in df.columns:
            log_message("Sorting CDPOS data by change document number")
            df = df.sort_values(by=[CDPOS_CHANGENR_COL])
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Save to output file as CSV with UTF-8-sig encoding
        log_message(f"Saving processed CDPOS file to: {output_file}")
        df.to_csv(output_file, index=False, encoding='utf-8-sig')
        log_message(f"Successfully saved {len(df)} rows to {output_file}")
        
        return True
    except Exception as e:
        log_message(f"Error processing CDPOS file {input_file}: {str(e)}", "ERROR")
        return False

# --- Main Function ---
def main():
    """Main function to execute the data preparation."""
    log_message("Starting SAP Audit Data Preparation...")
    
    # Create input directory if it doesn't exist
    os.makedirs(INPUT_DIR, exist_ok=True)
    
    # Find the latest files matching each pattern
    sm20_file = find_latest_file(SM20_PATTERN)
    cdhdr_file = find_latest_file(CDHDR_PATTERN)
    cdpos_file = find_latest_file(CDPOS_PATTERN)
    
    # Process SM20 file
    if sm20_file:
        log_message(f"Found SM20 file: {sm20_file}")
        sm20_success = process_sm20(sm20_file, SM20_OUTPUT_FILE)
    else:
        log_message("No SM20 file found matching pattern '*_sm20_*.xlsx'", "WARNING")
        sm20_success = False
    
    # Process CDHDR file
    if cdhdr_file:
        log_message(f"Found CDHDR file: {cdhdr_file}")
        cdhdr_success = process_cdhdr(cdhdr_file, CDHDR_OUTPUT_FILE)
    else:
        log_message("No CDHDR file found matching pattern '*_cdhdr_*.xlsx'", "WARNING")
        cdhdr_success = False
    
    # Process CDPOS file
    if cdpos_file:
        log_message(f"Found CDPOS file: {cdpos_file}")
        cdpos_success = process_cdpos(cdpos_file, CDPOS_OUTPUT_FILE)
    else:
        log_message("No CDPOS file found matching pattern '*_cdpos_*.xlsx'", "WARNING")
        cdpos_success = False
    
    # Report overall status
    if sm20_success and cdhdr_success and cdpos_success:
        log_message("Data preparation completed successfully.")
        log_message(f"Output files:")
        log_message(f"  SM20: {os.path.abspath(SM20_OUTPUT_FILE)}")
        log_message(f"  CDHDR: {os.path.abspath(CDHDR_OUTPUT_FILE)}")
        log_message(f"  CDPOS: {os.path.abspath(CDPOS_OUTPUT_FILE)}")
    else:
        log_message("Data preparation completed with some issues.", "WARNING")
        if not sm20_success:
            log_message("Failed to process SM20 file.", "WARNING")
        if not cdhdr_success:
            log_message("Failed to process CDHDR file.", "WARNING")
        if not cdpos_success:
            log_message("Failed to process CDPOS file.", "WARNING")

# --- Script Entry Point ---
if __name__ == "__main__":
    # Add a banner
    banner = "\n" + "="*80 + "\n"
    banner += " SAP AUDIT DATA PREPARATION ".center(80, "*") + "\n"
    banner += " Prepares and standardizes SAP log files for analysis ".center(80) + "\n"
    banner += " (UPPERCASE headers, datetime columns, sorting) ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)
    
    try:
        main()
    except Exception as e:
        log_message(f"Fatal error during data preparation: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        sys.exit(1)
