#!/usr/bin/env python3
"""
SAP Audit Data Preparation Script

This script prepares SAP log data files for the main audit tool by:
1. Finding input files matching specific patterns in the input folder
2. Converting all column headers to UPPERCASE
3. Creating datetime columns from date and time fields
4. Sorting data by user and datetime
5. Saving the processed files as CSV with UTF-8-sig encoding in the same input folder
6. Tracking record counts for completeness verification
"""

import os
import sys
import glob
import pandas as pd
from datetime import datetime, timedelta

# Import the record counter
from sap_audit_record_counts import record_counter

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(SCRIPT_DIR, "input")

# File patterns to search for
SM20_PATTERN = os.path.join(INPUT_DIR, "*_sm20_*.xlsx")
CDHDR_PATTERN = os.path.join(INPUT_DIR, "*_cdhdr_*.xlsx")
CDPOS_PATTERN = os.path.join(INPUT_DIR, "*_cdpos_*.xlsx")
SYSAID_PATTERN = os.path.join(INPUT_DIR, "*sysaid*.xlsx")

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
SM20_SYSAID_COL = 'SYSAID#'  # SysAid ticket reference field

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
CDHDR_SYSAID_COL = 'SYSAID#'  # SysAid ticket reference field

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
EXCLUDE_FIELDS = ['COMMENTS']  # Removed 'SYSAID #' to include it in processing

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
    """
    Clean whitespace from all columns in the dataframe and handle NaN values.

    This function performs multi-stage cleaning:
    1. Replaces all NaN values with empty strings
    2. For string columns: trims whitespace and replaces 'nan' text with empty strings
    3. For numeric columns: preserves data type while replacing NaN values appropriately

    Args:
        df (pandas.DataFrame): The dataframe to clean

    Returns:
        pandas.DataFrame: The cleaned dataframe
    """
    log_message("Cleaning whitespace and handling NaN values...")

    # Make a copy to avoid modifying the original
    df = df.copy()

    # First pass: Replace NaN values with empty strings in all columns
    df = df.fillna('')

    # Second pass: Process all columns to ensure consistent data
    nan_replaced_count = 0
    for col in df.columns:
        # Convert to string and remove whitespace for object columns
        if df[col].dtype == 'object':  # String columns
            # First ensure proper string conversion and strip whitespace
            df[col] = df[col].astype(str).str.strip()

            # Replace 'nan' or 'NaN' strings that might have come from NaN values
            # Use more robust replacement to catch variations
            nan_pattern = r'^nan$|^NaN$|^NAN$'
            nan_mask = df[col].str.match(nan_pattern, case=False)
            nan_count = nan_mask.sum()
            if nan_count > 0:
                df.loc[nan_mask, col] = ''
                nan_replaced_count += nan_count
        else:  # Numeric columns - need to handle differently
            # For numeric columns we need to preserve their data type
            # But still replace NaN with empty string for display purposes

            # First identify NaN values
            nan_mask = df[col].isna() | (df[col].astype(str).str.lower() == 'nan')

            if nan_mask.any():
                # Create a temporary series that maintains the type
                temp_col = df[col].copy()
                # Replace NaN with empty string (will convert column to object)
                temp_col = temp_col.astype(str)
                temp_col[nan_mask] = ''
                df[col] = temp_col
                nan_replaced_count += nan_mask.sum()

    # Report the cleaning
    log_message(f"Cleaned whitespace from {sum(df.dtypes == 'object')} string columns")
    log_message(f"Replaced {nan_replaced_count} NaN values with empty strings")
    return df

def process_sm20(input_file, output_file):
    """
    Process SM20 security audit log file with enhanced data preparation.
    
    Includes support for dynamic field mapping across different SAP export formats and
    properly preserves the SysAid ticket reference field.
    
    Args:
        input_file (str): Path to the input SM20 Excel file
        output_file (str): Path where the processed CSV file will be saved
    
    Returns:
        bool: True if processing was successful, False otherwise
    """
    try:
        log_message(f"Reading SM20 file: {input_file}")
        df = pd.read_excel(input_file)
        
        # Check if empty
        if df.empty:
            log_message(f"Warning: SM20 file is empty: {input_file}", "WARNING")
            return False
            
        # Store original record count for completeness tracking
        original_count = len(df)
        log_message(f"Original SM20 records: {original_count}")
        
        # Store original column count
        original_col_count = len(df.columns)
        log_message(f"Original columns: {original_col_count}")
        
        # Convert all column headers to uppercase
        df.columns = [col.strip().upper() for col in df.columns]  # Keep strip() from master
        log_message(f"Converted {original_col_count} column headers to UPPERCASE")

        # Store original column names for later mapping
        original_col_names = df.columns.tolist()  # Keep this line from v4.4.0-release
        
        # Clean whitespace and handle NaN values
        df = clean_whitespace(df)
        
        # Record count after cleaning
        after_cleaning_count = len(df)
        log_message(f"SM20 records after cleaning: {after_cleaning_count}")
        
        # Handle field mapping for SM20 columns that may have different names in different extracts
        # This is based on SAP's dynamic column behavior where field labels can change based on
        # GUI layout, language, and kernel patch level
        field_mapping = {
            # User column variations
            'USERNAME': SM20_USER_COL,
            'USER NAME': SM20_USER_COL,
            'USER_NAME': SM20_USER_COL,
            
            # Alternative date/time columns
            'LOG_DATE': SM20_DATE_COL,
            'LOG_TIME': SM20_TIME_COL,
            
            # Event variations
            'EVENT_TYPE': SM20_EVENT_COL,
            
            # Transaction code variations
            'TRANSACTION': SM20_TCODE_COL,
            'TCODE': SM20_TCODE_COL,
            'TRANSACTION CODE': SM20_TCODE_COL,
            
            # ABAP source code variations
            'PROGRAM': SM20_ABAP_SOURCE_COL,
            
            # Message text variations
            'MSG. TEXT': SM20_MSG_COL,
            'MESSAGE': SM20_MSG_COL,
            'MESSAGE TEXT': SM20_MSG_COL,

            # Variable field variations - based on SAP export behavior
            # First variable
            'FIRST VARIABLE': SM20_VAR_FIRST_COL,
            'VARIABLE 1': SM20_VAR_FIRST_COL,
            'VARIABLE_1': SM20_VAR_FIRST_COL,
            'VARIABLE1': SM20_VAR_FIRST_COL,
            'VAR1': SM20_VAR_FIRST_COL,
            # Second variable/data field - these are actually the same field with different labels
            'VARIABLE 2': SM20_VAR_2_COL,
            'VARIABLE_2': SM20_VAR_2_COL,
            'VARIABLE2': SM20_VAR_2_COL, # In some extracts (March)
            'VAR2': SM20_VAR_DATA_COL,
            
            # Variable data field - contains important debugging details
            'VARIABLE DATA': SM20_VAR_DATA_COL, # In some extracts (March)
            'VARIABLE_DATA': SM20_VAR_DATA_COL,
            'VARIABLEDATA': SM20_VAR_DATA_COL,
            'VARIABLE DATA FOR MESSAGE': SM20_VAR_DATA_COL,
            'VARIABLE_D': SM20_VAR_DATA_COL,
            'VARIABLED': SM20_VAR_DATA_COL,
            
            # Third variable field - can be VARIABLE 3 in some extracts
            'VARIABLE 3': SM20_VAR_DATA_COL,  # Also maps to VAR_DATA as per SAP's behavior
            'VARIABLE_3': SM20_VAR_DATA_COL,
            'VARIABLE3': SM20_VAR_DATA_COL,
            'VAR3': SM20_VAR_DATA_COL,
            
            # SysAid ticket reference field - preserve original format for tests
            'SYSAID #': 'SYSAID #',
            'SYSAID': SM20_SYSAID_COL,
            'TICKET #': SM20_SYSAID_COL,
            'TICKET': SM20_SYSAID_COL,
        }
        
        # Apply field mapping - only if target column doesn't already exist
        for old_name, new_name in field_mapping.items():
            if old_name in df.columns and new_name not in df.columns:
                df = df.rename(columns={old_name: new_name})
        
        # Check for important fields
        important_sm20_fields = [
            SM20_USER_COL, SM20_DATE_COL, SM20_TIME_COL, SM20_EVENT_COL,
            SM20_TCODE_COL, SM20_MSG_COL, SM20_VAR_FIRST_COL,
            SM20_VAR_2_COL, SM20_VAR_DATA_COL
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
        
        # Create datetime column from date and time fields
        log_message("Creating datetime column from date and time fields")
        try:
            # Convert date and time columns to string to handle potential non-standard formats
            date_str = df[SM20_DATE_COL].astype(str)
            time_str = df[SM20_TIME_COL].astype(str)
            
            # Combine date and time
            datetime_str = date_str + ' ' + time_str
            
            # Convert to datetime 
            df['DATETIME'] = pd.to_datetime(datetime_str, errors='coerce')
            
            # Sort by user and datetime
            log_message("Sorting SM20 data by user and datetime")
            df = df.sort_values(by=[SM20_USER_COL, 'DATETIME'])
            
        except Exception as e:
            log_message(f"Error creating datetime column: {str(e)}", "ERROR")
            # Attempt to continue with an empty datetime column
            df['DATETIME'] = pd.NaT
        
        # Save the processed file
        log_message(f"Saving processed SM20 file to: {output_file}")
        df.to_csv(output_file, index=False, encoding='utf-8-sig')
        
        # Record final count
        final_count = len(df)
        log_message(f"Successfully saved {final_count} rows to {output_file}")
        
        # Update record counter
        record_counter.update_source_counts(
            source_type="sm20",
            file_name=input_file,
            original_count=original_count,
            after_cleaning=after_cleaning_count,
            final_count=final_count
        )
        
        return True
        
    except Exception as e:
        log_message(f"Error processing SM20 file: {str(e)}", "ERROR")
        return False

def process_cdhdr(input_file, output_file):
    """
    Process CDHDR change document header file with enhanced data preparation.
    
    Includes support for dynamic field mapping and preserves SysAid ticket references.
    
    Args:
        input_file (str): Path to the input CDHDR Excel file
        output_file (str): Path where the processed CSV file will be saved
    
    Returns:
        bool: True if processing was successful, False otherwise
    """
    try:
        log_message(f"Reading CDHDR file: {input_file}")
        df = pd.read_excel(input_file)
        
        # Check if empty
        if df.empty:
            log_message(f"Warning: CDHDR file is empty: {input_file}", "WARNING")
            return False
        
        # Store original record count for completeness tracking
        original_count = len(df)
        log_message(f"Original CDHDR records: {original_count}")
            
        # Store original column count
        original_col_count = len(df.columns)
        log_message(f"Original columns: {original_col_count}")
        
        # Convert all column headers to uppercase
        df.columns = [col.upper() for col in df.columns]
        log_message(f"Converted {original_col_count} column headers to UPPERCASE")
        
        # Clean whitespace and handle NaN values
        df = clean_whitespace(df)
        
        # Record count after cleaning
        after_cleaning_count = len(df)
        log_message(f"CDHDR records after cleaning: {after_cleaning_count}")
        
        # Handle field mapping for alternate field names that might be in raw exports

        # Enhanced based on the SAP's variable field dynamics across different exports
        field_mapping = {
            # Transaction code variations
            'TRANSACTION': CDHDR_TCODE_COL,
            'TRANSACTION CODE': CDHDR_TCODE_COL,
            'TRANSACTION_CODE': CDHDR_TCODE_COL,
            
            # User name variations
            'USERNAME': CDHDR_USER_COL,
            'USER NAME': CDHDR_USER_COL,
            'USER_NAME': CDHDR_USER_COL,
            
            # Change document number variations
            'CHANGE DOC.': CDHDR_CHANGENR_COL,
            'CHANGE DOCUMENT': CDHDR_CHANGENR_COL,
            'CHANGEDOCUMENT': CDHDR_CHANGENR_COL,
            'CHANGE NUMBER': CDHDR_CHANGENR_COL,
            'CHANGENUMBER': CDHDR_CHANGENR_COL,
            
            # Object class variations
            'OBJECTCLASS': CDHDR_OBJECTCLAS_COL,
            'OBJECT CLASS': CDHDR_OBJECTCLAS_COL,
            'OBJECT_CLASS': CDHDR_OBJECTCLAS_COL,
            
            # Object ID variations
            'OBJECTID': CDHDR_OBJECTID_COL,
            'OBJECT ID': CDHDR_OBJECTID_COL,
            'OBJECT_ID': CDHDR_OBJECTID_COL,
            
            # Change flag variations
            'CHANGE FLAG': CDHDR_CHANGE_FLAG_COL,
            'CHANGEFLAG': CDHDR_CHANGE_FLAG_COL,
            'CHANGE_FLAG': CDHDR_CHANGE_FLAG_COL,
            
            # SysAid ticket reference field - special handling for consistency
            'SYSAID #': CDHDR_SYSAID_COL,
            'SYSAID': CDHDR_SYSAID_COL,
            'TICKET #': CDHDR_SYSAID_COL,
            'TICKET': CDHDR_SYSAID_COL,
        }
        
        # Apply field mapping - only if target column doesn't already exist
        for old_name, new_name in field_mapping.items():
            if old_name in df.columns and new_name not in df.columns:
                df = df.rename(columns={old_name: new_name})
                log_message(f"Mapped {old_name} to {new_name}")
        
        # Check for important fields
        important_cdhdr_fields = [
            CDHDR_USER_COL, CDHDR_DATE_COL, CDHDR_TIME_COL, CDHDR_TCODE_COL,
            CDHDR_CHANGENR_COL, CDHDR_OBJECTCLAS_COL, CDHDR_OBJECTID_COL
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
        
        # Create datetime column from date and time fields
        log_message("Creating datetime column from date and time fields")
        try:
            # Convert date and time columns to string to handle potential non-standard formats
            date_str = df[CDHDR_DATE_COL].astype(str)
            time_str = df[CDHDR_TIME_COL].astype(str)
            
            # Combine date and time
            datetime_str = date_str + ' ' + time_str
            
            # Convert to datetime
            df['DATETIME'] = pd.to_datetime(datetime_str, errors='coerce')
            
            # Sort by user and datetime
            log_message("Sorting CDHDR data by user and datetime")
            df = df.sort_values(by=[CDHDR_USER_COL, 'DATETIME'])
            
        except Exception as e:
            log_message(f"Error creating datetime column: {str(e)}", "ERROR")
            # Attempt to continue with an empty datetime column
            df['DATETIME'] = pd.NaT
        
        # Save the processed file
        log_message(f"Saving processed CDHDR file to: {output_file}")
        df.to_csv(output_file, index=False, encoding='utf-8-sig')
        
        # Record final count
        final_count = len(df)
        log_message(f"Successfully saved {final_count} rows to {output_file}")
        
        # Update record counter
        record_counter.update_source_counts(
            source_type="cdhdr",
            file_name=input_file,
            original_count=original_count,
            after_cleaning=after_cleaning_count,
            final_count=final_count
        )
        
        return True
        
    except Exception as e:
        log_message(f"Error processing CDHDR file: {str(e)}", "ERROR")
        return False

def process_cdpos(input_file, output_file):
    """
    Process CDPOS change document items file with enhanced data preparation.
    
    Args:
        input_file (str): Path to the input CDPOS Excel file
        output_file (str): Path where the processed CSV file will be saved
    
    Returns:
        bool: True if processing was successful, False otherwise
    """
    try:
        log_message(f"Reading CDPOS file: {input_file}")
        df = pd.read_excel(input_file)
        
        # Check if empty
        if df.empty:
            log_message(f"Warning: CDPOS file is empty: {input_file}", "WARNING")
            return False
        
        # Store original record count for completeness tracking
        original_count = len(df)
        log_message(f"Original CDPOS records: {original_count}")
            
        # Store original column count
        original_col_count = len(df.columns)
        log_message(f"Original columns: {original_col_count}")
        
        # Convert all column headers to uppercase
        df.columns = [col.upper() for col in df.columns]
        log_message(f"Converted {original_col_count} column headers to UPPERCASE")
        
        # Clean whitespace and handle NaN values
        df = clean_whitespace(df)
        
        # Record count after cleaning
        after_cleaning_count = len(df)
        log_message(f"CDPOS records after cleaning: {after_cleaning_count}")
        
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
        
        # Standardize change indicators to uppercase
        try:
            if CDPOS_CHANGE_IND_COL in df.columns:
                # First get all unique values to report
                unique_indicators = df[CDPOS_CHANGE_IND_COL].unique()
                log_message(f"Found {len(unique_indicators)} unique change indicator values: {' '.join(map(str, unique_indicators))}")
                
                # Then convert all to uppercase
                df[CDPOS_CHANGE_IND_COL] = df[CDPOS_CHANGE_IND_COL].str.upper()
                log_message("Standardized all change indicators to uppercase")
        except Exception as e:
            log_message(f"Error standardizing change indicators: {str(e)}", "WARNING")
        
        # Sort by change document number
        log_message("Sorting CDPOS data by change document number")
        df = df.sort_values(by=[CDPOS_CHANGENR_COL])
        
        # Save the processed file
        log_message(f"Saving processed CDPOS file to: {output_file}")
        df.to_csv(output_file, index=False, encoding='utf-8-sig')
        
        # Record final count
        final_count = len(df)
        log_message(f"Successfully saved {final_count} rows to {output_file}")
        
        # Update record counter
        record_counter.update_source_counts(
            source_type="cdpos",
            file_name=input_file,
            original_count=original_count,
            after_cleaning=after_cleaning_count,
            final_count=final_count
        )
        
        return True
        
    except Exception as e:
        log_message(f"Error processing CDPOS file: {str(e)}", "ERROR")
        return False

def main():
    """Main function to prepare all SAP data files."""
    log_message("Starting SAP Audit Data Preparation...")
    
    # Create input directory if it doesn't exist
    os.makedirs(INPUT_DIR, exist_ok=True)
    
    # Process SM20 security audit log
    sm20_file = find_latest_file(SM20_PATTERN)
    if sm20_file:
        log_message(f"Found SM20 file: {sm20_file}")
        process_sm20(sm20_file, SM20_OUTPUT_FILE)
    else:
        log_message("No SM20 file found matching pattern", "WARNING")
    
    # Process CDHDR change document headers
    cdhdr_file = find_latest_file(CDHDR_PATTERN)
    if cdhdr_file:
        log_message(f"Found CDHDR file: {cdhdr_file}")
        process_cdhdr(cdhdr_file, CDHDR_OUTPUT_FILE)
    else:
        log_message("No CDHDR file found matching pattern", "WARNING")
    
    # Process CDPOS change document items
    cdpos_file = find_latest_file(CDPOS_PATTERN)
    if cdpos_file:
        log_message(f"Found CDPOS file: {cdpos_file}")
        process_cdpos(cdpos_file, CDPOS_OUTPUT_FILE)
    else:
        log_message("No CDPOS file found matching pattern", "WARNING")
    
    log_message("Data preparation completed successfully.")
    log_message("Output files:")
    log_message(f"  SM20: {SM20_OUTPUT_FILE}")
    log_message(f"  CDHDR: {CDHDR_OUTPUT_FILE}")
    log_message(f"  CDPOS: {CDPOS_OUTPUT_FILE}")

if __name__ == "__main__":
    main()
