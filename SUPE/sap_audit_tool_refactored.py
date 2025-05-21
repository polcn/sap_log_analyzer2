#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Security Analysis Script (Refactored)

This script analyzes SAP log data (SM20, CDHDR, CDPOS) to identify high-risk activities.
It can work with either:
1. Pre-processed CSV files with UPPERCASE column headers (legacy mode)
2. Session-based timeline from the SAP Log Session Merger (recommended)

Version: 4.0.0
Based on sap_audit_tool_3.0.0 with added support for session-based analysis.
"""

import sys
import os
import re
import time
from datetime import datetime, timedelta
import pandas as pd
import xlsxwriter

# Import modules for risk assessment and output generation
try:
    from sap_audit_tool_risk_assessment import (
        get_sensitive_tables, get_critical_field_patterns, get_sensitive_tcodes,
        assess_risk_legacy, assess_risk_session
    )
    from sap_audit_tool_output import generate_excel_output
    MODULAR_MODE = True
except ImportError:
    # Fall back to integrated mode if modules are not available
    MODULAR_MODE = False

# --- Configuration ---
VERSION = "4.0.0"

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

# Standard input file names (produced by data preparation script)
SM20_FILE = os.path.join(INPUT_DIR, "SM20.csv")
CDHDR_FILE = os.path.join(INPUT_DIR, "CDHDR.csv")
CDPOS_FILE = os.path.join(INPUT_DIR, "CDPOS.csv")

# Session timeline file (produced by SAP Log Session Merger)
SESSION_TIMELINE_FILE = os.path.join(SCRIPT_DIR, "SAP_Session_Timeline.xlsx")

# Correlation window (minutes) for matching events
CORRELATION_WINDOW_MINUTES = 15

# Risk assessment configuration
HIGH_RISK_COLOR = '#FFC7CE'
MEDIUM_RISK_COLOR = '#FFEB9C'
LOW_RISK_COLOR = '#C6EFCE'

# --- Column Name Mapping (UPPERCASE) ---
# SM20 Security Audit Log columns
SM20_DATE_COL = 'DATE'
SM20_TIME_COL = 'TIME'
SM20_USER_COL = 'USER'
SM20_TCODE_COL = 'SOURCE TA'
SM20_MSG_COL = 'AUDIT LOG MSG. TEXT'
SM20_TERMINAL_COL = 'TERMINAL NAME'
SM20_CLIENT_COL = 'CL.'
SM20_SYSAID_COL = 'SYSAID#'
SM20_COMMENT_COL = 'COMMENT / REVIEW'

# CDHDR Change Document Header columns
CDHDR_DATE_COL = 'DATE'
CDHDR_TIME_COL = 'TIME'
CDHDR_USER_COL = 'USER'
CDHDR_TCODE_COL = 'TCODE'
CDHDR_CHANGENR_COL = 'DOC.NUMBER'
CDHDR_OBJECTCLAS_COL = 'OBJECT'
CDHDR_OBJECTID_COL = 'OBJECT VALUE'

# CDPOS Change Document Item columns
CDPOS_CHANGENR_COL = 'DOC.NUMBER'
CDPOS_TABNAME_COL = 'TABLE NAME'
CDPOS_CHNGIND_COL = 'CHANGE INDICATOR'
CDPOS_FNAME_COL = 'FIELD NAME'
CDPOS_TEXT_COL = 'TEXT FLAG'
CDPOS_VALUE_NEW_COL = 'NEW VALUE'
CDPOS_VALUE_OLD_COL = 'OLD VALUE'
CDPOS_AGING_COL = 'DATA AGING FILTER'

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

# --- Date/Time Format ---
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'  # Matches '2025-03-10 19:17:23' format from input files

# --- Utility Functions ---
def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def validate_file_exists(file_path):
    """Validate that a file exists and is readable."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"File is not readable: {file_path}")
    return True

def validate_csv_file(file_path, required_columns):
    """
    Validate that a CSV file contains the required columns.
    Returns the DataFrame if valid.
    """
    try:
        # First check if file exists
        validate_file_exists(file_path)
        
        # Try to read the CSV file
        log_message(f"Reading CSV file: {file_path}")
        df = pd.read_csv(file_path, encoding='utf-8-sig')
        
        # Check for required columns (already in UPPERCASE from data prep)
        missing_columns = []
        for req_col in required_columns:
            if req_col not in df.columns.tolist():
                missing_columns.append(req_col)
                
        if missing_columns:
            raise ValueError(
                f"Missing required columns in {os.path.basename(file_path)}: {', '.join(missing_columns)}\n"
                f"Actual columns: {', '.join(df.columns.tolist())}"
            )
        
        return df
    except Exception as e:
        log_message(f"Error validating CSV file {file_path}: {str(e)}", "ERROR")
        raise

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

# --- Load and Validate Input Files ---
def load_input_files():
    """Load and validate all input files."""
    log_message("Starting to load and validate input files...")
    
    # Define required columns for each file (now in UPPERCASE)
    sm20_required_cols = [SM20_DATE_COL, SM20_TIME_COL, SM20_USER_COL, SM20_TCODE_COL]
    cdhdr_required_cols = [CDHDR_DATE_COL, CDHDR_TIME_COL, CDHDR_USER_COL, CDHDR_TCODE_COL, CDHDR_CHANGENR_COL]
    cdpos_required_cols = [CDPOS_CHANGENR_COL, CDPOS_TABNAME_COL, CDPOS_CHNGIND_COL]
    
    # Optional columns that enhance analysis but aren't strictly required
    sm20_optional_cols = [SM20_MSG_COL, SM20_SYSAID_COL, SM20_COMMENT_COL]
    cdpos_optional_cols = [CDPOS_FNAME_COL, CDPOS_TEXT_COL,
                          CDPOS_VALUE_NEW_COL, CDPOS_VALUE_OLD_COL]
    
    try:
        # Validate and load SM20
        log_message(f"Validating SM20 file: {SM20_FILE}")
        sm20 = validate_csv_file(SM20_FILE, sm20_required_cols)
        log_message(f"Loaded SM20 with {len(sm20)} records")
        
        # Validate and load CDHDR
        log_message(f"Validating CDHDR file: {CDHDR_FILE}")
        cdhdr = validate_csv_file(CDHDR_FILE, cdhdr_required_cols)
        log_message(f"Loaded CDHDR with {len(cdhdr)} records")
        
        # Validate and load CDPOS
        log_message(f"Validating CDPOS file: {CDPOS_FILE}")
        cdpos = validate_csv_file(CDPOS_FILE, cdpos_required_cols)
        log_message(f"Loaded CDPOS with {len(cdpos)} records")
        
        return sm20, cdhdr, cdpos
    
    except FileNotFoundError as e:
        log_message(f"File not found: {str(e)}", "ERROR")
        sys.exit(1)
    except ValueError as e:
        log_message(f"Validation error: {str(e)}", "ERROR")
        sys.exit(1)
    except Exception as e:
        log_message(f"Unexpected error loading input files: {str(e)}", "ERROR")
        sys.exit(1)

# --- Prepare Data ---
def prepare_sm20(sm20):
    """Prepare SM20 data for correlation."""
    log_message("Preparing SM20 data...")
    
    try:
        # Create datetime column
        sm20["SM20_Datetime"] = pd.to_datetime(
            sm20[SM20_DATE_COL].astype(str) + ' ' + sm20[SM20_TIME_COL].astype(str),
            format=DATETIME_FORMAT,
            errors='coerce'
        )
        
        # Drop rows with invalid datetime
        invalid_dates = sm20[sm20["SM20_Datetime"].isna()]
        if len(invalid_dates) > 0:
            log_message(f"Warning: Dropped {len(invalid_dates)} SM20 rows with invalid dates", "WARNING")
        
        sm20 = sm20.dropna(subset=["SM20_Datetime"])
        
        # Add original index for tracking
        sm20 = sm20.reset_index().rename(columns={'index': 'original_sm20_index'})
        
        # Add a column to identify display-only activities
        if SM20_MSG_COL in sm20.columns:
            sm20['is_display_only'] = sm20[SM20_MSG_COL].str.contains(
                r'DISPLAY|READ|VIEW|SHOW|REPORT|LIST',
                case=False,
                regex=True
            )
        else:
            sm20['is_display_only'] = False
            log_message(f"Warning: {SM20_MSG_COL} column not found, setting all is_display_only to False", "WARNING")
        
        log_message(f"SM20 data prepared. {len(sm20)} valid entries.")
        return sm20
    
    except KeyError as e:
        log_message(f"Column error in SM20 preparation: {str(e)}", "ERROR")
        sys.exit(1)
    except Exception as e:
        log_message(f"Error preparing SM20 data: {str(e)}", "ERROR")
        sys.exit(1)

def prepare_change_documents(cdhdr, cdpos):
    """Prepare and merge CDHDR and CDPOS data."""
    log_message("Preparing and merging change document data...")
    
    try:
        # Create datetime column in CDHDR
        cdhdr["Change_Timestamp"] = pd.to_datetime(
            cdhdr[CDHDR_DATE_COL].astype(str) + ' ' + cdhdr[CDHDR_TIME_COL].astype(str),
            format=DATETIME_FORMAT,
            errors='coerce'
        )
        
        # Drop rows with invalid datetime
        invalid_dates = cdhdr[cdhdr["Change_Timestamp"].isna()]
        if len(invalid_dates) > 0:
            log_message(f"Warning: Dropped {len(invalid_dates)} CDHDR rows with invalid dates", "WARNING")
        
        cdhdr = cdhdr.dropna(subset=["Change_Timestamp"])
        
        # Verify change document number columns exist
        if CDHDR_CHANGENR_COL not in cdhdr.columns:
            raise KeyError(f"CDHDR change document number column '{CDHDR_CHANGENR_COL}' not found")
        if CDPOS_CHANGENR_COL not in cdpos.columns:
            raise KeyError(f"CDPOS change document number column '{CDPOS_CHANGENR_COL}' not found")
        
        # Merge CDHDR and CDPOS
        log_message(f"Merging CDHDR and CDPOS on change document number...")
        cdpos_merged = pd.merge(
            cdhdr,
            cdpos,
            left_on=CDHDR_CHANGENR_COL,
            right_on=CDPOS_CHANGENR_COL,
            how="inner"
        )
        
        # Rename columns for clarity
        cdpos_merged = cdpos_merged.rename(columns={
            CDPOS_TABNAME_COL: "Table_Name",
            CDPOS_CHNGIND_COL: "Change_Indicator",
            CDHDR_TCODE_COL: "TCode_CD"
        })
        
        # Ensure user column has consistent name for correlation
        if CDHDR_USER_COL != SM20_USER_COL:
            cdpos_merged = cdpos_merged.rename(columns={CDHDR_USER_COL: "CD_User"})
            cdhdr_user_col_final = "CD_User"
        else:
            cdhdr_user_col_final = CDHDR_USER_COL
        
        # Add original index for tracking
        cdpos_merged = cdpos_merged.reset_index().rename(columns={'index': 'original_cdpos_index'})
        
        # Add a column to identify actual changes (not just displays)
        cdpos_merged['is_actual_change'] = cdpos_merged['Change_Indicator'].isin(['I', 'U', 'D'])
        
        # Add flags for data aging if they exist
        if CDPOS_AGING_COL in cdpos_merged.columns:
            cdpos_merged['has_aging_filter'] = cdpos_merged[CDPOS_AGING_COL].notna() & (cdpos_merged[CDPOS_AGING_COL] != '')
        else:
            cdpos_merged['has_aging_filter'] = False
        
        log_message(f"Change documents prepared and merged. {len(cdpos_merged)} entries.")
        return cdpos_merged, cdhdr_user_col_final
    
    except KeyError as e:
        log_message(f"Column error in change document preparation: {str(e)}", "ERROR")
        sys.exit(1)

# --- Correlation Logic ---
def correlate_logs(sm20, cdpos_merged, sm20_user_col, cdhdr_user_col):
    """Correlate SM20 logs with change documents."""
    log_message("Correlating logs using merge_asof...")
    
    try:
        start_time = time.time()
        
        # Sort dataframes by user and timestamp for merge_asof
        # For merge_asof, the key columns must be sorted in ascending order
        sm20 = sm20.sort_values(by=['SM20_Datetime', sm20_user_col])
        cdpos_merged = cdpos_merged.sort_values(by=['Change_Timestamp', cdhdr_user_col])
        
        # Verify required columns exist
        if 'Change_Timestamp' not in cdpos_merged.columns:
            raise KeyError("'Change_Timestamp' column not found in change documents")
        if 'SM20_Datetime' not in sm20.columns:
            raise KeyError("'SM20_Datetime' column not found in SM20 logs")
        if cdhdr_user_col not in cdpos_merged.columns:
            raise KeyError(f"'{cdhdr_user_col}' column not found in change documents")
        if sm20_user_col not in sm20.columns:
            raise KeyError(f"'{sm20_user_col}' column not found in SM20 logs")
            
        # Ensure timestamp columns are datetime type
        if not pd.api.types.is_datetime64_dtype(cdpos_merged['Change_Timestamp']):
            log_message("Converting Change_Timestamp to datetime", "INFO")
            cdpos_merged['Change_Timestamp'] = pd.to_datetime(cdpos_merged['Change_Timestamp'])
            
        if not pd.api.types.is_datetime64_dtype(sm20['SM20_Datetime']):
            log_message("Converting SM20_Datetime to datetime", "INFO")
            sm20['SM20_Datetime'] = pd.to_datetime(sm20['SM20_Datetime'])
        
        # Perform the time-based merge
        try:
            correlated = pd.merge_asof(
                cdpos_merged,  # Left dataframe: Change Documents
                sm20,          # Right dataframe: Audit Logs
                left_on='Change_Timestamp',
                right_on='SM20_Datetime',
                left_by=cdhdr_user_col,  # User column from CDHDR/CDPOS side
                right_by=sm20_user_col,  # User column from SM20 side
                direction='nearest',  # Find closest SM20 entry
                tolerance=pd.Timedelta(minutes=CORRELATION_WINDOW_MINUTES)  # Use configured window
            )
        except Exception as e:
            log_message(f"Error during merge_asof: {str(e)}", "ERROR")
            log_message("Attempting fallback merge method...", "INFO")
            
            # Fallback to a simpler merge method if merge_asof fails
            # This won't be as precise but will allow the script to continue
            correlated = pd.merge(
                cdpos_merged,
                sm20,
                left_on=cdhdr_user_col,
                right_on=sm20_user_col,
                how="left"
            )
        
        # Filter for valid correlations (where a match within tolerance was found)
        valid_correlated = correlated.dropna(subset=[sm20_user_col, 'SM20_Datetime']).copy()
        
        # Identify special case: SM20 shows display but CDPOS indicates changes
        if 'is_display_only' in valid_correlated.columns and 'is_actual_change' in valid_correlated.columns:
            valid_correlated.loc[:, 'display_but_changed'] = (
                valid_correlated['is_display_only'] &
                valid_correlated['is_actual_change']
            )
        else:
            valid_correlated.loc[:, 'display_but_changed'] = False
            log_message("Warning: Could not calculate 'display_but_changed' due to missing columns", "WARNING")
        
        # Calculate correlation statistics
        total_sm20 = len(sm20)
        total_cdpos = len(cdpos_merged)
        matched = len(valid_correlated)
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        log_message(f"Correlation complete in {elapsed_time:.2f} seconds.")
        log_message(f"Total SM20 entries: {total_sm20}")
        log_message(f"Total change document entries: {total_cdpos}")
        log_message(f"Valid correlations within time window: {matched}")
        
        return valid_correlated, sm20, cdpos_merged
    
    except KeyError as e:
        log_message(f"Column error during correlation: {str(e)}", "ERROR")
        sys.exit(1)
    except Exception as e:
        log_message(f"Error during correlation: {str(e)}", "ERROR")
        sys.exit(1)

# --- Identify Unmatched Records ---
def identify_unmatched_records(valid_correlated, sm20, cdpos_merged):
    """Identify records that couldn't be correlated."""
    log_message("Identifying unmatched records...")
    
    try:
        # Identify unmatched change documents
        unmatched_cdpos = cdpos_merged[
            ~cdpos_merged['original_cdpos_index'].isin(
                valid_correlated['original_cdpos_index']
            )
        ]
        
        # Identify unmatched SM20 logs
        unmatched_sm20 = sm20[
            ~sm20['original_sm20_index'].isin(
                valid_correlated['original_sm20_index']
            )
        ]
        
        log_message(f"Unmatched change document entries: {len(unmatched_cdpos)}")
        log_message(f"Unmatched SM20 log entries: {len(unmatched_sm20)}")
        
        return unmatched_cdpos, unmatched_sm20
    
    except Exception as e:
        log_message(f"Error identifying unmatched records: {str(e)}", "ERROR")
        return pd.DataFrame(), pd.DataFrame()

# --- Session-Based Analysis ---
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

# --- Risk Assessment and Pattern Detection ---
# If not using modular mode, include the risk assessment functions here
if not MODULAR_MODE:
    # Define sensitive tables and transaction codes
    def get_sensitive_tables():
        """Return a set of sensitive SAP tables to monitor."""
        return {
            # Security Tables
            "USR01", "USR02", "USR04", "USR10", "USR12", "USR21", "USR40", "UST10C", "UST04",
            "AGR_1251", "AGR_USERS", "AGR_DEFINE", "DEVACCESS", "USER_ADDR", "PROFILE",
            "RSECTAB", "PRGN_CUST", "USOBT", "UST12", "SUSR", "USER_LOG",
            
            # Audit and Monitoring
            "RSAU_PERS", "RSAU_CONFIG", "RSAUFILES", "RSAU_VAL", "RSAUDIT_CASES", "RSAU_CONTROL",
            "RSECACTPRO", "RSECUDATA", "TPCF", "TST01",
            
            # Payment and Banking
            "REGUH", "PAYR", "BSEC", "FPLT", "T042Z", "BSEG", "TIBAN", "T012K", "T012T", "T001B",
            
            # Basis
            "TADIR", "TRDIR", "E071", "E070", "T000", "DDLOG", "TDEVC", "REPOS", "D010TAB",
            "D010INC", "NRIV", "TST01", "TMS_SRCSYS", "RSPARAM", "TSP01", "TPFET", "TPSRV",
            "TPSTAT", "VARI",
            
            # Financial
            "BKPF", "BSEG", "SKA1", "SKB1", "T030", "T001", "T001B", "T009", "T009B",
            "FAGLFLEXA", "FAGLFLEXT", "CSKS", "CSKB", "CEPC", "TKA01", "T003", "T012",
            "T012K", "BNKA", "REGUH", "PAYR", "TCURR", "TCURF", "TCURV", "T043T", "T042Y",
            
            # Jobs
            "TBTCO", "TBTCP", "TSDIR", "TBTCS", "BTCEVTJOB", "BTCJSTAT", "BTCSEVJOB", "BTCSYSPRD",
            
            # Materials Management
            "MCHA", "MCH1", "MSEG", "MKPF", "MBEW", "EKKO", "EKPO", "EINA", "EINE", "T156", "MARM",
            
            # Sales and Distribution
            "VBAK", "VBAP", "LIKP", "LIPS", "VBRK", "VBRP", "KNVV", "KONV", "A004", "A305",
            
            # Master Data
            "KNA1", "KNB1", "LFA1", "LFB1", "MARA", "MARC", "MVKE", "LFBK", "BUT000",
            
            # Workflow
            "SWWWIHEAD", "SWWUSERWI", "SWWCONT", "SWP_STEP", "SWWLOGHIST"
        }

    def get_critical_field_patterns():
        """Return patterns for critical fields that should be monitored closely."""
        return {
            # Authentication and authorization fields
            r"(?i)PASS(WORD)?": "Password field",
            r"(?i)AUTH(ORIZATION)?": "Authorization field",
            r"(?i)ROLE": "Role assignment field",
            r"(?i)PERM(ISSION)?": "Permission field",
            r"(?i)ACCESS": "Access control field",
            r"(?i)KEY": "Security key field",
            r"(?i)CRED(ENTIAL)?": "Credential field",
            r"(?i)TOKEN": "Security token field",
            
            # Financial fields
            r"(?i)AMOUNT": "Financial amount field",
            r"(?i)CURR(ENCY)?": "Currency field",
            r"(?i)BANK": "Banking information field",
            r"(?i)ACCOUNT": "Account field",
            r"(?i)PAYMENT": "Payment field",
            r"(?i)CREDIT": "Credit field",
            r"(?i)TAX": "Tax field",
            
            # Master data fields
            r"(?i)VENDOR": "Vendor master data field",
            r"(?i)CUSTOMER": "Customer master data field",
            r"(?i)EMPLOYEE": "Employee data field",
            r"(?i)ADDRESS": "Address field",
            r"(?i)CONTACT": "Contact information field",
            
            # System configuration
            r"(?i)CONFIG": "Configuration field",
            r"(?i)SETTING": "System setting field",
            r"(?i)PARAM(ETER)?": "Parameter field",
            r"(?i)FLAG": "System flag field",
            r"(?i)MODE": "System mode field"
        }

    def get_sensitive_tcodes():
        """Return a set of sensitive SAP transaction codes to monitor."""
        return {
            # Debugging
            "RSDEBUG", "/H", "/IWBEP/TRACES", "/IWFND/ERROR_LOG", "ST22", "ST05",
            
            # Audit and Compliance
            "SM19", "SM20", "RSAU_CONFIG", "GRC_RULESET", "GRC_RISK", "RMPS",
            "NWBC_AUDITING", "DPRM", "SARA",
            
            # Payment and Banking
            "F110", "FBPM", "FB70", "FCH5", "FC10", "FF67", "FF_5", "FCHI", "BPAY",
            
            # Table Maintenance
            "SE11", "SE14", "SE16N", "SM30", "SM31", "MASS",
            
            # Code Changes
            "SE38", "SE80", "SE24", "SE37", "SE09", "SE10", "SMOD", "CMOD",
            
            # Configuration
            "SPRO", "RZ10", "RZ11", "SCC4", "SCC5", "SCC7", "SCCL", "OB08", "OB52",
            "OB29", "SALE",
            
            # Job Management
            "SM36", "SM37", "SM39", "SM62", "SM63", "SM64", "SM61",
            
            # Security
            "PFCG", "SU01", "SUIM", "SU10", "SU24", "SU53", "SU56", "PFCG_TIME_DEPENDENCY",
            "SM19",
            
            # Transport
            "STMS", "CG3Y", "CG3Z", "SE09", "SE10", "SE03", "SPAM", "SAINT",
            
            # System Administration
            "SM59", "SM21", "SM66", "ST02", "ST03N", "ST22", "DB02", "AL11", "SM12",
            "SM13", "DB01", "DB13", "SM51", "SM50", "WE20", "WE21", "SNC1",
            
            # Direct Posting / Financial
            "FB01", "FB50", "F-02", "FS00", "FSP0", "FI12", "OKB9", "OBYC", "OKP1",
            
            # Master Data
            "XD01", "XD02", "FK01", "FK02", "XK02", "MM01", "MM02", "ME21N", "ME22N",
            "VA01", "VA02", "VD01", "VD02",
            
            # Other Critical TCodes
            "LSMW", "BAPI", "SA38", "SMX", "RDDIMPDP", "/IWFND/MAINT_SERVICE",
            "/IWBEP/REG_SERVICE", "/SCWM/CHM_PRF", "VL32N", "VL33N"
        }

    def assess_risk_legacy(correlated_data, unmatched_cdpos, unmatched_sm20):
        """
        Assess risk in the legacy correlation mode (direct SM20-CDPOS correlation).
        Returns a DataFrame with risk assessments.
        """
        log_message("Assessing risk in legacy correlation mode...")
        
        try:
            # Create a copy to avoid SettingWithCopyWarning
            risk_df = correlated_data.copy()
            
            # Get reference data for risk assessment
            sensitive_tables = get_sensitive_tables()
            sensitive_tcodes = get_sensitive_tcodes()
            critical_field_patterns = get_critical_field_patterns()
            
            # Initialize risk columns
            risk_df['risk_level'] = 'Low'
            risk_df['risk_factors'] = ''
            
            # Assess risk based on sensitive tables
            if 'Table_Name' in risk_df.columns:
                risk_df.loc[risk_df['Table_Name'].isin(sensitive_tables), 'risk_level'] = 'High'
                risk_df.loc[risk_df['Table_Name'].isin(sensitive_tables), 'risk_factors'] = \
                    risk_df.loc[risk_df['Table_Name'].isin(sensitive_tables), 'risk_factors'] + 'Sensitive table; '
            
            # Assess risk based on sensitive transaction codes
            # Check both SM20 and CDPOS transaction codes
            if SM20_TCODE_COL in risk_df.columns:
                risk_df.loc[risk_df[SM20_TCODE_COL].isin(sensitive_tcodes), 'risk_level'] = 'High'
                risk_df.loc[risk_df[SM20_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] = \
                    risk_df.loc[risk_df[SM20_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] + 'Sensitive transaction code; '
            
            if 'TCode_CD' in risk_df.columns:
                risk_df.loc[risk_df['TCode_CD'].isin(sensitive_tcodes), 'risk_level'] = 'High'
                risk_df.loc[risk_df['TCode_CD'].isin(sensitive_tcodes), 'risk_factors'] = \
                    risk_df.loc[risk_df['TCode_CD'].isin(sensitive_tcodes), 'risk_factors'] + 'Sensitive transaction code; '
            
            # Assess risk based on critical field patterns
            if CDPOS_FNAME_COL in risk_df.columns:
                for pattern, description in critical_field_patterns.items():
                    mask = risk_df[CDPOS_FNAME_COL].str.contains(pattern, regex=True, na=False)
                    risk_df.loc[mask, 'risk_level'] = 'High'
                    risk_df.loc[mask, 'risk_factors'] = \
                        risk_df.loc[mask, 'risk_factors'] + f'Critical field ({description}); '
            
            # Assess risk based on display_but_changed flag
            if 'display_but_changed' in risk_df.columns:
                risk_df.loc[risk_df['display_but_changed'], 'risk_level'] = 'High'
                risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] = \
                    risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] + 'Display transaction with changes; '
            
            # Assess risk based on change indicator
            if 'Change_Indicator' in risk_df.columns:
                # Insert (I) and Delete (D) operations are higher risk than Update (U)
                risk_df.loc[risk_df['Change_Indicator'].isin(['I', 'D']), 'risk_level'] = 'High'
                risk_df.loc[risk_df['Change_Indicator'] == 'I', 'risk_factors'] = \
                    risk_df.loc[risk_df['Change_Indicator'] == 'I', 'risk_factors'] + 'Insert operation; '
                risk_df.loc[risk_df['Change_Indicator'] == 'D', 'risk_factors'] = \
                    risk_df.loc[risk_df['Change_Indicator'] == 'D', 'risk_factors'] + 'Delete operation; '
                
                # Updates are medium risk by default
                medium_risk_mask = (risk_df['risk_level'] == 'Low') & (risk_df['Change_Indicator'] == 'U')
                risk_df.loc[medium_risk_mask, 'risk_level'] = 'Medium'
                risk_df.loc[medium_risk_mask, 'risk_factors'] = \
                    risk_df.loc[medium_risk_mask, 'risk_factors'] + 'Update operation; '
            
            # Count risk levels
            high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
            medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
            low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
            
            log_message(f"Risk assessment complete. High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
            
            return risk_df
        
        except Exception as e:
            log_message(f"Error during risk assessment: {str(e)}", "ERROR")
            return correlated_data

    def assess_risk_session(session_data):
        """
        Assess risk in the session-based mode.
        Returns a DataFrame with risk assessments.
        """
        log_message("Assessing risk in session-based mode...")
        
        try:
            # Create a copy to avoid SettingWithCopyWarning
            risk_df = session_data.copy()
            
            # Get reference data for risk assessment
            sensitive_tables = get_sensitive_tables()
            sensitive_tcodes = get_sensitive_tcodes()
            critical_field_patterns = get_critical_field_patterns()
            
            # Initialize risk columns
            risk_df['risk_level'] = 'Low'
            risk_df['risk_factors'] = ''
            
            # Assess risk based on sensitive tables
            if SESSION_TABLE_COL in risk_df.columns:
                risk_df.loc[risk_df[SESSION_TABLE_COL].isin(sensitive_tables), 'risk_level'] = 'High'
                risk_df.loc[risk_df[SESSION_TABLE_COL].isin(sensitive_tables), 'risk_factors'] = \
                    risk_df.loc[risk_df[SESSION_TABLE_COL].isin(sensitive_tables), 'risk_factors'] + 'Sensitive table; '
            
            # Assess risk based on sensitive transaction codes
            if SESSION_TCODE_COL in risk_df.columns:
                risk_df.loc[risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes), 'risk_level'] = 'High'
                risk_df.loc[risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] = \
                    risk_df.loc[risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] + 'Sensitive transaction code; '
            
            # Assess risk based on critical field patterns
            if SESSION_FIELD_COL in risk_df.columns:
                for pattern, description in critical_field_patterns.items():
                    mask = risk_df[SESSION_FIELD_COL].str.contains(pattern, regex=True, na=False)
                    risk_df.loc[mask, 'risk_level'] = 'High'
                    risk_df.loc[mask, 'risk_factors'] = \
                        risk_df.loc[mask, 'risk_factors'] + f'Critical field ({description}); '
            
            # Assess risk based on display_but_changed flag
            if 'display_but_changed' in risk_df.columns:
                risk_df.loc[risk_df['display_but_changed'], 'risk_level'] = 'High'
                risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] = \
                    risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] + 'Display transaction with changes; '
            
            # Assess risk based on change indicator
            if SESSION_CHANGE_IND_COL in risk_df.columns:
                # Insert (I) and Delete (D) operations are higher risk than Update (U)
                risk_df.loc[risk_df[SESSION_CHANGE_IND_COL].isin(['I', 'D']), 'risk_level'] = 'High'
                risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'I', 'risk_factors'] = \
                    risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'I', 'risk_factors'] + 'Insert operation; '
                risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'D', 'risk_factors'] = \
                    risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'D', 'risk_factors'] + 'Delete operation; '
                
                # Updates are medium risk by default
                medium_risk_mask = (risk_df['risk_level'] == 'Low') & (risk_df[SESSION_CHANGE_IND_COL] == 'U')
                risk_df.loc[medium_risk_mask, 'risk_level'] = 'Medium'
                risk_df.loc[medium_risk_mask, 'risk_factors'] = \
                    risk_df.loc[medium_risk_mask, 'risk_factors'] + 'Update operation; '
            
            # Count risk levels
            high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
            medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
            low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
            
            log_message(f"Risk assessment complete. High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
            
            return risk_df
        
        except Exception as e:
            log_message(f"Error during risk assessment: {str(e)}", "ERROR")
            return session_data

    # If not using modular mode, include the Excel output generation function
    def generate_excel_output_integrated(correlated_df, unmatched_cdpos, unmatched_sm20, session_df, output_file):
        """Generate a formatted Excel output with multiple sheets for audit results."""
        log_message(f"Generating Excel output to {output_file}...")
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(os.path.abspath(output_file))
            os.makedirs(output_dir, exist_ok=True)

            # Create Excel writer
            with pd.ExcelWriter(output_file, engine="xlsxwriter") as writer:
                wb = writer.book
                
                # Define formats
                header_format = wb.add_format({
                    'bold': True,
                    'bg_color': '#4F81BD',
                    'font_color': 'white',
                    'border': 1,
                    'text_wrap': True,
                    'valign': 'top'
                })
                
                high_risk_format = wb.add_format({'bg_color': HIGH_RISK_COLOR})
                medium_risk_format = wb.add_format({'bg_color': MEDIUM_RISK_COLOR})
                low_risk_format = wb.add_format({'bg_color': LOW_RISK_COLOR})
                
                # Sheet 0: Session Timeline (if available)
                if session_df is not None and len(session_df) > 0:
                    log_message("Creating Session Timeline sheet...")
                    session_df.to_excel(writer, sheet_name="Session_Timeline", index=False)
                    ws_session = writer.sheets["Session_Timeline"]
                    
                    # Apply header format
                    for col_num, col_name in enumerate(session_df.columns):
                        ws_session.write(0, col_num, col_name, header_format)
                    
                    # Apply conditional formatting based on risk level
                    if 'risk_level' in session_df.columns:
                        ws_session.conditional_format(1, 0, len(session_df), len(session_df.columns)-1, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': '"High"',
                            'format': high_risk_format
                        })
                        
                        ws_session.conditional_format(1, 0, len(session_df), len(session_df.columns)-1, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': '"Medium"',
                            'format': medium_risk_format
                        })
                        
                        ws_session.conditional_format(1, 0, len(session_df), len(session_df.columns)-1, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': '"Low"',
                            'format': low_risk_format
                        })
                    
                    # Add autofilter
                    ws_session.autofilter(0, 0, len(session_df), len(session_df.columns)-1)
                    
                    # Freeze panes
                    ws_session.freeze_panes(1, 0)

                # Sheet 1: Correlated Events (legacy mode)
                if correlated_df is not None and len(correlated_df) > 0:
                    log_message("Creating Correlated Events sheet...")
                    correlated_df.to_excel(writer, sheet_name="Correlated_Events", index=False)
                    ws_corr = writer.sheets["Correlated_Events"]
                    
                    # Apply header format
                    for col_num, col_name in enumerate(correlated_df.columns):
                        ws_corr.write(0, col_num, col_name, header_format)
                    
                    # Apply conditional formatting based on risk level
                    if 'risk_level' in correlated_df.columns:
                        ws_corr.conditional_format(1, 0, len(correlated_df), len(correlated_df.columns)-1, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': '"High"',
                            'format': high_risk_format
                        })
                        
                        ws_corr.conditional_format(1, 0, len(correlated_df), len(correlated_df.columns)-1, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': '"Medium"',
                            'format': medium_risk_format
                        })
                        
                        ws_corr.conditional_format(1, 0, len(correlated_df), len(correlated_df.columns)-1, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': '"Low"',
                            'format': low_risk_format
                        })
                    
                    # Add autofilter
                    ws_corr.autofilter(0, 0, len(correlated_df), len(correlated_df.columns)-1)
                    
                    # Freeze panes
                    ws_corr.freeze_panes(1, 0)

                # Sheet 2: Unmatched Change Documents
                if unmatched_cdpos is not None and len(unmatched_cdpos) > 0:
                    log_message("Creating Unmatched CD Changes sheet...")
                    unmatched_cdpos.to_excel(writer, sheet_name="Unmatched_CD_Changes", index=False)
                    ws_unmatch_cd = writer.sheets["Unmatched_CD_Changes"]
                    
                    # Apply header format
                    for col_num, col_name in enumerate(unmatched_cdpos.columns):
                        ws_unmatch_cd.write(0, col_num, col_name, header_format)
                    
                    # Add autofilter
                    ws_unmatch_cd.autofilter(0, 0, len(unmatched_cdpos), len(unmatched_cdpos.columns)-1)
                    
                    # Freeze panes
                    ws_unmatch_cd.freeze_panes(1, 0)

                # Sheet 3: Unmatched SM20 Logs
                if unmatched_sm20 is not None and len(unmatched_sm20) > 0:
                    log_message("Creating Unmatched SM20 Logs sheet...")
                    unmatched_sm20.to_excel(writer, sheet_name="Unmatched_SM20_Logs", index=False)
                    ws_unmatch_sm20 = writer.sheets["Unmatched_SM20_Logs"]
                    
                    # Apply header format
                    for col_num, col_name in enumerate(unmatched_sm20.columns):
                        ws_unmatch_sm20.write(0, col_num, col_name, header_format)
                    
                    # Apply conditional formatting based on risk level
                    if 'risk_level' in unmatched_sm20.columns:
                        ws_unmatch_sm20.conditional_format(1, 0, len(unmatched_sm20), len(unmatched_sm20.columns)-1, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': '"High"',
                            'format': high_risk_format
                        })
                        
                        ws_unmatch_sm20.conditional_format(1, 0, len(unmatched_sm20), len(unmatched_sm20.columns)-1, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': '"Medium"',
                            'format': medium_risk_format
                        })
                        
                        ws_unmatch_sm20.conditional_format(1, 0, len(unmatched_sm20), len(unmatched_sm20.columns)-1, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': '"Low"',
                            'format': low_risk_format
                        })
                    
                    # Add autofilter
                    ws_unmatch_sm20.autofilter(0, 0, len(unmatched_sm20), len(unmatched_sm20.columns)-1)
                    
                    # Freeze panes
                    ws_unmatch_sm20.freeze_panes(1, 0)

                # Sheet 4: Summary
                log_message("Creating Summary sheet...")
                
                # Determine which dataframe to use for summary
                if session_df is not None and len(session_df) > 0 and 'risk_level' in session_df.columns:
                    summary_source = session_df
                    mode = "session"
                elif correlated_df is not None and len(correlated_df) > 0 and 'risk_level' in correlated_df.columns:
                    summary_source = correlated_df
                    mode = "legacy"
                else:
                    # Create an empty summary if no risk data available
                    summary_source = pd.DataFrame({'risk_level': []})
                    mode = "unknown"
                
                # Create summary data
                summary_data = {
                    'Category': ['High Risk', 'Medium Risk', 'Low Risk', 'Total'],
                    'Count': [
                        len(summary_source[summary_source['risk_level'] == 'High']),
                        len(summary_source[summary_source['risk_level'] == 'Medium']),
                        len(summary_source[summary_source['risk_level'] == 'Low']),
                        len(summary_source)
                    ]
                }
                
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name="Summary", index=False)
                
                # Get summary worksheet
                summary_worksheet = writer.sheets["Summary"]
                
                # Apply header format
                for col_num, col_name in enumerate(summary_df.columns):
                    summary_worksheet.write(0, col_num, col_name, header_format)
                
                # Add a chart
                chart = wb.add_chart({'type': 'pie'})
                
                # Configure the chart
                chart.add_series({
                    'name': 'Risk Distribution',
                    'categories': ['Summary', 1, 0, 3, 0],
                    'values': ['Summary', 1, 1, 3, 1],
                    'points': [
                        {'fill': {'color': HIGH_RISK_COLOR}},
                        {'fill': {'color': MEDIUM_RISK_COLOR}},
                        {'fill': {'color': LOW_RISK_COLOR}}
                    ]
                })
                
                chart.set_title({'name': 'Risk Distribution'})
                chart.set_style(10)
                
                # Insert the chart into the summary worksheet
                summary_worksheet.insert_chart('D2', chart)
                
                # Add mode information
                summary_worksheet.write(6, 0, "Analysis Mode:", header_format)
                summary_worksheet.write(6, 1, mode.capitalize())
                
                # Add timestamp
                summary_worksheet.write(7, 0, "Generated On:", header_format)
                summary_worksheet.write(7, 1, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                
                # Set column widths
                summary_worksheet.set_column(0, 0, 15)
                summary_worksheet.set_column(1, 1, 15)

                log_message(f"Excel output successfully generated: {output_file}")
            return True

        except Exception as e:
            log_message(f"Error generating Excel output: {str(e)}", "ERROR")
            import traceback
            log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
            return False

# --- Main Function ---
def main():
    """Main function to execute the SAP audit analysis."""
    start_time = time.time()
    log_message(f"Starting SAP Audit Tool v{VERSION}...")
    
    try:
        # Step 1: Check for session timeline file
        session_df = load_session_timeline()
        
        if session_df is not None:
            log_message("Session timeline found. Using session-based analysis mode.")
            
            # Step 2: Prepare session data
            session_df = prepare_session_data(session_df)
            
            # Step 3: Apply risk assessment to session data
            log_message("Applying risk assessment to session timeline...")
            try:
                if MODULAR_MODE:
                    # Use the imported risk assessment function
                    session_df = assess_risk_session(session_df)
                else:
                    # Create a copy to avoid SettingWithCopyWarning
                    session_df = session_df.copy()
                    # Apply risk assessment using .loc to avoid warnings
                    risk_results = session_df.apply(lambda row: (
                        "High" if row.get(SESSION_TABLE_COL) in get_sensitive_tables() or 
                                row.get(SESSION_TCODE_COL) in get_sensitive_tcodes() or
                                row.get('display_but_changed', False) else
                        "Medium" if row.get(SESSION_CHANGE_IND_COL) == 'U' else
                        "Low"
                    ), axis=1)
                    session_df.loc[:, "risk_level"] = risk_results
                    session_df.loc[:, "risk_factors"] = "Automated risk assessment"
            except Exception as e:
                log_message(f"Error applying risk assessment to session timeline: {str(e)}", "ERROR")
                # Create empty risk columns to avoid errors later
                session_df.loc[:, "risk_level"] = "Unknown"
                session_df.loc[:, "risk_factors"] = "Risk assessment failed"
            
            # Step 4: Generate Excel output with session data
            # Sort by risk level (High first) and then by session ID and timestamp
            session_df['Risk_Sort'] = session_df['risk_level'].map({'High': 0, 'Medium': 1, 'Low': 2, 'Unknown': 3})
            session_df = session_df.sort_values(['Risk_Sort', SESSION_ID_WITH_DATE_COL, SESSION_DATETIME_COL], 
                                               ascending=[True, True, True])
            session_df = session_df.drop('Risk_Sort', axis=1)
            
            # Generate Excel output with session data (empty dataframes for legacy mode)
            if MODULAR_MODE:
                generate_excel_output(pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), session_df, OUTPUT_FILE)
            else:
                generate_excel_output_integrated(pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), session_df
#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Security Analysis Script (Refactored)

This script analyzes SAP log data (SM20, CDHDR, CDPOS) to identify high-risk activities.
It can work with either:
1. Pre-processed CSV files with UPPERCASE column headers (legacy mode)
2. Session-based timeline from the SAP Log Session Merger (recommended)

Version: 4.0.0
Based on sap_audit_tool_3.0.0 with added support for session-based analysis.
"""

import sys
import os
import re
import time
from datetime import datetime, timedelta
import pandas as pd
import xlsxwriter

# Import modules for risk assessment and output generation
try:
    from sap_audit_tool_risk_assessment import (
        get_sensitive_tables, get_critical_field_patterns, get_sensitive_tcodes,
        assess_risk_legacy, assess_risk_session
    )
    from sap_audit_tool_output import generate_excel_output
    MODULAR_MODE = True
except ImportError:
    # Fall back to integrated mode if modules are not available
    MODULAR_MODE = False

# --- Configuration ---
VERSION = "4.0.0"

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

# Standard input file names (produced by data preparation script)
SM20_FILE = os.path.join(INPUT_DIR, "SM20.csv")
CDHDR_FILE = os.path.join(INPUT_DIR, "CDHDR.csv")
CDPOS_FILE = os.path.join(INPUT_DIR, "CDPOS.csv")

# Session timeline file (produced by SAP Log Session Merger)
SESSION_TIMELINE_FILE = os.path.join(SCRIPT_DIR, "SAP_Session_Timeline.xlsx")

# Correlation window (minutes) for matching events
CORRELATION_WINDOW_MINUTES = 15

# Risk assessment configuration
HIGH_RISK_COLOR = '#FFC7CE'
MEDIUM_RISK_COLOR = '#FFEB9C'
LOW_RISK_COLOR = '#C6EFCE'

# --- Column Name Mapping (UPPERCASE) ---
# SM20 Security Audit Log columns
SM20_DATE_COL = 'DATE'
SM20_TIME_COL = 'TIME'
SM20_USER_COL = 'USER'
SM20_TCODE_COL = 'SOURCE TA'
SM20_MSG_COL = 'AUDIT LOG MSG. TEXT'
SM20_TERMINAL_COL = 'TERMINAL NAME'
SM20_CLIENT_COL = 'CL.'
SM20_SYSAID_COL = 'SYSAID#'
SM20_COMMENT_COL = 'COMMENT / REVIEW'

# CDHDR Change Document Header columns
CDHDR_DATE_COL = 'DATE'
CDHDR_TIME_COL = 'TIME'
CDHDR_USER_COL = 'USER'
CDHDR_TCODE_COL = 'TCODE'
CDHDR_CHANGENR_COL = 'DOC.NUMBER'
CDHDR_OBJECTCLAS_COL = 'OBJECT'
CDHDR_OBJECTID_COL = 'OBJECT VALUE'

# CDPOS Change Document Item columns
CDPOS_CHANGENR_COL = 'DOC.NUMBER'
CDPOS_TABNAME_COL = 'TABLE NAME'
CDPOS_CHNGIND_COL = 'CHANGE INDICATOR'
CDPOS_FNAME_COL = 'FIELD NAME'
CDPOS_TEXT_COL = 'TEXT FLAG'
CDPOS_VALUE_NEW_COL = 'NEW VALUE'
CDPOS_VALUE_OLD_COL = 'OLD VALUE'
CDPOS_AGING_COL = 'DATA AGING FILTER'

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

# --- Date/Time Format ---
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'  # Matches '2025-03-10 19:17:23' format from input files

# --- Utility Functions ---
def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def validate_file_exists(file_path):
    """Validate that a file exists and is readable."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"File is not readable: {file_path}")
    return True

def validate_csv_file(file_path, required_columns):
    """
    Validate that a CSV file contains the required columns.
    Returns the DataFrame if valid.
    """
    try:
        # First check if file exists
        validate_file_exists(file_path)
        
        # Try to read the CSV file
        log_message(f"Reading CSV file: {file_path}")
        df = pd.read_csv(file_path, encoding='utf-8-sig')
        
        # Check for required columns (already in UPPERCASE from data prep)
        missing_columns = []
        for req_col in required_columns:
            if req_col not in df.columns.tolist():
                missing_columns.append(req_col)
                
        if missing_columns:
            raise ValueError(
                f"Missing required columns in {os.path.basename(file_path)}: {', '.join(missing_columns)}\n"
                f"Actual columns: {', '.join(df.columns.tolist())}"
            )
        
        return df
    except Exception as e:
        log_message(f"Error validating CSV file {file_path}: {str(e)}", "ERROR")
        raise

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

# --- Load and Validate Input Files ---
def load_input_files():
    """Load and validate all input files."""
    log_message("Starting to load and validate input files...")
    
    # Define required columns for each file (now in UPPERCASE)
    sm20_required_cols = [SM20_DATE_COL, SM20_TIME_COL, SM20_USER_COL, SM20_TCODE_COL]
    cdhdr_required_cols = [CDHDR_DATE_COL, CDHDR_TIME_COL, CDHDR_USER_COL, CDHDR_TCODE_COL, CDHDR_CHANGENR_COL]
    cdpos_required_cols = [CDPOS_CHANGENR_COL, CDPOS_TABNAME_COL, CDPOS_CHNGIND_COL]
    
    # Optional columns that enhance analysis but aren't strictly required
    sm20_optional_cols = [SM20_MSG_COL, SM20_SYSAID_COL, SM20_COMMENT_COL]
    cdpos_optional_cols = [CDPOS_FNAME_COL, CDPOS_TEXT_COL,
                          CDPOS_VALUE_NEW_COL, CDPOS_VALUE_OLD_COL]
    
    try:
        # Validate and load SM20
        log_message(f"Validating SM20 file: {SM20_FILE}")
        sm20 = validate_csv_file(SM20_FILE, sm20_required_cols)
        log_message(f"Loaded SM20 with {len(sm20)} records")
        
        # Validate and load CDHDR
        log_message(f"Validating CDHDR file: {CDHDR_FILE}")
        cdhdr = validate_csv_file(CDHDR_FILE, cdhdr_required_cols)
        log_message(f"Loaded CDHDR with {len(cdhdr)} records")
        
        # Validate and load CDPOS
        log_message(f"Validating CDPOS file: {CDPOS_FILE}")
        cdpos = validate_csv_file(CDPOS_FILE, cdpos_required_cols)
        log_message(f"Loaded CDPOS with {len(cdpos)} records")
        
        return sm20, cdhdr, cdpos
    
    except FileNotFoundError as e:
        log_message(f"File not found: {str(e)}", "ERROR")
        sys.exit(1)
    except ValueError as e:
        log_message(f"Validation error: {str(e)}", "ERROR")
        sys.exit(1)
    except Exception as e:
        log_message(f"Unexpected error loading input files: {str(e)}", "ERROR")
        sys.exit(1)

# --- Prepare Data ---
def prepare_sm20(sm20):
    """Prepare SM20 data for correlation."""
    log_message("Preparing SM20 data...")
    
    try:
        # Create datetime column
        sm20["SM20_Datetime"] = pd.to_datetime(
            sm20[SM20_DATE_COL].astype(str) + ' ' + sm20[SM20_TIME_COL].astype(str),
            format=DATETIME_FORMAT,
            errors='coerce'
        )
        
        # Drop rows with invalid datetime
        invalid_dates = sm20[sm20["SM20_Datetime"].isna()]
        if len(invalid_dates) > 0:
            log_message(f"Warning: Dropped {len(invalid_dates)} SM20 rows with invalid dates", "WARNING")
        
        sm20 = sm20.dropna(subset=["SM20_Datetime"])
        
        # Add original index for tracking
        sm20 = sm20.reset_index().rename(columns={'index': 'original_sm20_index'})
        
        # Add a column to identify display-only activities
        if SM20_MSG_COL in sm20.columns:
            sm20['is_display_only'] = sm20[SM20_MSG_COL].str.contains(
                r'DISPLAY|READ|VIEW|SHOW|REPORT|LIST',
                case=False,
                regex=True
            )
        else:
            sm20['is_display_only'] = False
            log_message(f"Warning: {SM20_MSG_COL} column not found, setting all is_display_only to False", "WARNING")
        
        log_message(f"SM20 data prepared. {len(sm20)} valid entries.")
        return sm20
    
    except KeyError as e:
        log_message(f"Column error in SM20 preparation: {str(e)}", "ERROR")
        sys.exit(1)
    except Exception as e:
        log_message(f"Error preparing SM20 data: {str(e)}", "ERROR")
        sys.exit(1)

def prepare_change_documents(cdhdr, cdpos):
    """Prepare and merge CDHDR and CDPOS data."""
    log_message("Preparing and merging change document data...")
    
    try:
        # Create datetime column in CDHDR
        cdhdr["Change_Timestamp"] = pd.to_datetime(
            cdhdr[CDHDR_DATE_COL].astype(str) + ' ' + cdhdr[CDHDR_TIME_COL].astype(str),
            format=DATETIME_FORMAT,
            errors='coerce'
        )
        
        # Drop rows with invalid datetime
        invalid_dates = cdhdr[cdhdr["Change_Timestamp"].isna()]
        if len(invalid_dates) > 0:
            log_message(f"Warning: Dropped {len(invalid_dates)} CDHDR rows with invalid dates", "WARNING")
        
        cdhdr = cdhdr.dropna(subset=["Change_Timestamp"])
        
        # Verify change document number columns exist
        if CDHDR_CHANGENR_COL not in cdhdr.columns:
            raise KeyError(f"CDHDR change document number column '{CDHDR_CHANGENR_COL}' not found")
        if CDPOS_CHANGENR_COL not in cdpos.columns:
            raise KeyError(f"CDPOS change document number column '{CDPOS_CHANGENR_COL}' not found")
        
        # Merge CDHDR and CDPOS
        log_message(f"Merging CDHDR and CDPOS on change document number...")
        cdpos_merged = pd.merge(
            cdhdr,
            cdpos,
            left_on=CDHDR_CHANGENR_COL,
            right_on=CDPOS_CHANGENR_COL,
            how="inner"
        )
        
        # Rename columns for clarity
        cdpos_merged = cdpos_merged.rename(columns={
            CDPOS_TABNAME_COL: "Table_Name",
            CDPOS_CHNGIND_COL: "Change_Indicator",
            CDHDR_TCODE_COL: "TCode_CD"
        })
        
        # Ensure user column has consistent name for correlation
        if CDHDR_USER_COL != SM20_USER_COL:
            cdpos_merged = cdpos_merged.rename(columns={CDHDR_USER_COL: "CD_User"})
            cdhdr_user_col_final = "CD_User"
        else:
            cdhdr_user_col_final = CDHDR_USER_COL
        
        # Add original index for tracking
        cdpos_merged = cdpos_merged.reset_index().rename(columns={'index': 'original_cdpos_index'})
        
        # Add a column to identify actual changes (not just displays)
        cdpos_merged['is_actual_change'] = cdpos_merged['Change_Indicator'].isin(['I', 'U', 'D'])
        
        # Add flags for data aging if they exist
        if CDPOS_AGING_COL in cdpos_merged.columns:
            cdpos_merged['has_aging_filter'] = cdpos_merged[CDPOS_AGING_COL].notna() & (cdpos_merged[CDPOS_AGING_COL] != '')
        else:
            cdpos_merged['has_aging_filter'] = False
        
        log_message(f"Change documents prepared and merged. {len(cdpos_merged)} entries.")
        return cdpos_merged, cdhdr_user_col_final
    
    except KeyError as e:
        log_message(f"Column error in change document preparation: {str(e)}", "ERROR")
        sys.exit(1)

# --- Correlation Logic ---
def correlate_logs(sm20, cdpos_merged, sm20_user_col, cdhdr_user_col):
    """Correlate SM20 logs with change documents."""
    log_message("Correlating logs using merge_asof...")
    
    try:
        start_time = time.time()
        
        # Sort dataframes by user and timestamp for merge_asof
        # For merge_asof, the key columns must be sorted in ascending order
        sm20 = sm20.sort_values(by=['SM20_Datetime', sm20_user_col])
        cdpos_merged = cdpos_merged.sort_values(by=['Change_Timestamp', cdhdr_user_col])
        
        # Verify required columns exist
        if 'Change_Timestamp' not in cdpos_merged.columns:
            raise KeyError("'Change_Timestamp' column not found in change documents")
        if 'SM20_Datetime' not in sm20.columns:
            raise KeyError("'SM20_Datetime' column not found in SM20 logs")
        if cdhdr_user_col not in cdpos_merged.columns:
            raise KeyError(f"'{cdhdr_user_col}' column not found in change documents")
        if sm20_user_col not in sm20.columns:
            raise KeyError(f"'{sm20_user_col}' column not found in SM20 logs")
            
        # Ensure timestamp columns are datetime type
        if not pd.api.types.is_datetime64_dtype(cdpos_merged['Change_Timestamp']):
            log_message("Converting Change_Timestamp to datetime", "INFO")
            cdpos_merged['Change_Timestamp'] = pd.to_datetime(cdpos_merged['Change_Timestamp'])
            
        if not pd.api.types.is_datetime64_dtype(sm20['SM20_Datetime']):
            log_message("Converting SM20_Datetime to datetime", "INFO")
            sm20['SM20_Datetime'] = pd.to_datetime(sm20['SM20_Datetime'])
        
        # Perform the time-based merge
        try:
            correlated = pd.merge_asof(
                cdpos_merged,  # Left dataframe: Change Documents
                sm20,          # Right dataframe: Audit Logs
                left_on='Change_Timestamp',
                right_on='SM20_Datetime',
                left_by=cdhdr_user_col,  # User column from CDHDR/CDPOS side
                right_by=sm20_user_col,  # User column from SM20 side
                direction='nearest',  # Find closest SM20 entry
                tolerance=pd.Timedelta(minutes=CORRELATION_WINDOW_MINUTES)  # Use configured window
            )
        except Exception as e:
            log_message(f"Error during merge_asof: {str(e)}", "ERROR")
            log_message("Attempting fallback merge method...", "INFO")
            
            # Fallback to a simpler merge method if merge_asof fails
            # This won't be as precise but will allow the script to continue
            correlated = pd.merge(
                cdpos_merged,
                sm20,
                left_on=cdhdr_user_col,
                right_on=sm20_user_col,
                how="left"
            )
        
        # Filter for valid correlations (where a match within tolerance was found)
        valid_correlated = correlated.dropna(subset=[sm20_user_col, 'SM20_Datetime']).copy()
        
        # Identify special case: SM20 shows display but CDPOS indicates changes
        if 'is_display_only' in valid_correlated.columns and 'is_actual_change' in valid_correlated.columns:
            valid_correlated.loc[:, 'display_but_changed'] = (
                valid_correlated['is_display_only'] &
                valid_correlated['is_actual_change']
            )
        else:
            valid_correlated.loc[:, 'display_but_changed'] = False
            log_message("Warning: Could not calculate 'display_but_changed' due to missing columns", "WARNING")
        
        # Calculate correlation statistics
        total_sm20 = len(sm20)
        total_cdpos = len(cdpos_merged)
        matched = len(valid_correlated)
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        log_message(f"Correlation complete in {elapsed_time:.2f} seconds.")
        log_message(f"Total SM20 entries: {total_sm20}")
        log_message(f"Total change document entries: {total_cdpos}")
        log_message(f"Valid correlations within time window: {matched}")
        
        return valid_correlated, sm20, cdpos_merged
    
    except KeyError as e:
        log_message(f"Column error during correlation: {str(e)}", "ERROR")
        sys.exit(1)
    except Exception as e:
        log_message(f"Error during correlation: {str(e)}", "ERROR")
        sys.exit(1)

# --- Identify Unmatched Records ---
def identify_unmatched_records(valid_correlated, sm20, cdpos_merged):
    """Identify records that couldn't be correlated."""
    log_message("Identifying unmatched records...")
    
    try:
        # Identify unmatched change documents
        unmatched_cdpos = cdpos_merged[
            ~cdpos_merged['original_cdpos_index'].isin(
                valid_correlated['original_cdpos_index']
            )
        ]
        
        # Identify unmatched SM20 logs
        unmatched_sm20 = sm20[
            ~sm20['original_sm20_index'].isin(
                valid_correlated['original_sm20_index']
            )
        ]
        
        log_message(f"Unmatched change document entries: {len(unmatched_cdpos)}")
        log_message(f"Unmatched SM20 log entries: {len(unmatched_sm20)}")
        
        return unmatched_cdpos, unmatched_sm20
    
    except Exception as e:
        log_message(f"Error identifying unmatched records: {str(e)}", "ERROR")
        return pd.DataFrame(), pd.DataFrame()

# --- Session-Based Analysis ---
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

# --- Risk Assessment and Pattern Detection ---
# If not using modular mode, include the risk assessment functions here
if not MODULAR_MODE:
    # Define sensitive tables and transaction codes
    def get_sensitive_tables():
        """Return a set of sensitive SAP tables to monitor."""
        return {
            # Security Tables
            "USR01", "USR02", "USR04", "USR10", "USR12", "USR21", "USR40", "UST10C", "UST04",
            "AGR_1251", "AGR_USERS", "AGR_DEFINE", "DEVACCESS", "USER_ADDR", "PROFILE",
            "RSECTAB", "PRGN_CUST", "USOBT", "UST12", "SUSR", "USER_LOG",
            
            # Audit and Monitoring
            "RSAU_PERS", "RSAU_CONFIG", "RSAUFILES", "RSAU_VAL", "RSAUDIT_CASES", "RSAU_CONTROL",
            "RSECACTPRO", "RSECUDATA", "TPCF", "TST01",
            
            # Payment and Banking
            "REGUH", "PAYR", "BSEC", "FPLT", "T042Z", "BSEG", "TIBAN", "T012K", "T012T", "T001B",
            
            # Basis
            "TADIR", "TRDIR", "E071", "E070", "T000", "DDLOG", "TDEVC", "REPOS", "D010TAB",
            "D010INC", "NRIV", "TST01", "TMS_SRCSYS", "RSPARAM", "TSP01", "TPFET", "TPSRV",
            "TPSTAT", "VARI",
            
            # Financial
            "BKPF", "BSEG", "SKA1", "SKB1", "T030", "T001", "T001B", "T009", "T009B",
            "FAGLFLEXA", "FAGLFLEXT", "CSKS", "CSKB", "CEPC", "TKA01", "T003", "T012",
            "T012K", "BNKA", "REGUH", "PAYR", "TCURR", "TCURF", "TCURV", "T043T", "T042Y",
            
            # Jobs
            "TBTCO", "TBTCP", "TSDIR", "TBTCS", "BTCEVTJOB", "BTCJSTAT", "BTCSEVJOB", "BTCSYSPRD",
            
            # Materials Management
            "MCHA", "MCH1", "MSEG", "MKPF", "MBEW", "EKKO", "EKPO", "EINA", "EINE", "T156", "MARM",
            
            # Sales and Distribution
            "VBAK", "VBAP", "LIKP", "LIPS", "VBRK", "VBRP", "KNVV", "KONV", "A004", "A305",
            
            # Master Data
            "KNA1", "KNB1", "LFA1", "LFB1", "MARA", "MARC", "MVKE", "LFBK", "BUT000",
            
            # Workflow
            "SWWWIHEAD", "SWWUSERWI", "SWWCONT", "SWP_STEP", "SWWLOGHIST"
        }

    def get_critical_field_patterns():
        """Return patterns for critical fields that should be monitored closely."""
        return {
            # Authentication and authorization fields
            r"(?i)PASS(WORD)?": "Password field",
            r"(?i)AUTH(ORIZATION)?": "Authorization field",
            r"(?i)ROLE": "Role assignment field",
            r"(?i)PERM(ISSION)?": "Permission field",
            r"(?i)ACCESS": "Access control field",
            r"(?i)KEY": "Security key field",
            r"(?i)CRED(ENTIAL)?": "Credential field",
            r"(?i)TOKEN": "Security token field",
            
            # Financial fields
            r"(?i)AMOUNT": "Financial amount field",
            r"(?i)CURR(ENCY)?": "Currency field",
            r"(?i)BANK": "Banking information field",
            r"(?i)ACCOUNT": "Account field",
            r"(?i)PAYMENT": "Payment field",
            r"(?i)CREDIT": "Credit field",
            r"(?i)TAX": "Tax field",
            
            # Master data fields
            r"(?i)VENDOR": "Vendor master data field",
            r"(?i)CUSTOMER": "Customer master data field",
            r"(?i)EMPLOYEE": "Employee data field",
            r"(?i)ADDRESS": "Address field",
            r"(?
