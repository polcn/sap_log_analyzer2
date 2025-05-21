#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Security Analysis Script

This script analyzes SAP log data (SM20, CDHDR, CDPOS) to identify high-risk activities 
performed by third-party vendors using firefighter IDs (FF_*). It correlates activities 
across different logs, evaluates their risk level, and produces a well-structured Excel 
output for audit review.

Based on log_correlate_4_2.py with enhanced risk assessment, error handling, and performance.
"""

import pandas as pd
from datetime import datetime, timedelta
import xlsxwriter
import sys
import os
import re
import time

# --- Configuration ---
# Version information
VERSION = "2.1.0"
# File paths - can be overridden via command line arguments in future versions
import os

# Get the script directory - print for debugging
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
print(f"Script directory: {SCRIPT_DIR}")
print(f"Current working directory: {os.getcwd()}")

# Use absolute paths
SM20_FILE = os.path.join(SCRIPT_DIR, "input", "feb_sm20_FF.xlsx")
CDHDR_FILE = os.path.join(SCRIPT_DIR, "input", "feb_CDHDR_FF.xlsx")
CDPOS_FILE = os.path.join(SCRIPT_DIR, "input", "feb_CDPOS_FF.xlsx")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "SAP_Audit_Report.xlsx")

# Print actual paths for debugging
print(f"SM20_FILE absolute path: {SM20_FILE}")
print(f"CDHDR_FILE absolute path: {CDHDR_FILE}")
print(f"CDPOS_FILE absolute path: {CDPOS_FILE}")

# Correlation window (minutes) for matching events
CORRELATION_WINDOW_MINUTES = 15

# Risk assessment configuration
HIGH_RISK_COLOR = '#FFC7CE'
MEDIUM_RISK_COLOR = '#FFEB9C'
LOW_RISK_COLOR = '#C6EFCE'

# Suspicious pattern detection thresholds
MAX_CHANGES_PER_USER_HOUR = 50  # Flag if a user makes more than this many changes in an hour
SUSPICIOUS_TIME_RANGES = [
    (0, 5),    # 12 AM - 5 AM
    (22, 24)   # 10 PM - 12 AM
]

# --- Column Name Mapping ---
# SM20 Security Audit Log columns (normalized to lowercase)
SM20_DATE_COL = 'date'
SM20_TIME_COL = 'time'
SM20_USER_COL = 'user'
SM20_TCODE_COL = 'source ta'
SM20_MSG_COL = 'audit log msg. text'  # Matches normalized column name
SM20_TERMINAL_COL = 'terminal name'   # Matches normalized 'terminal name' column
SM20_CLIENT_COL = 'cl.'               # Matches normalized 'cl.' column
SM20_TERMINAL_COL = 'Terminal'  # Optional, if available
SM20_CLIENT_COL = 'Client'  # Optional, if available
SM20_SYSAID_COL = 'sysaid#'  # Added SysAid ticket number
SM20_COMMENT_COL = 'comment / review'  # Added comment/review field

# CDHDR Change Document Header columns (normalized to lowercase)
CDHDR_DATE_COL = 'date'          # Matches 'Date      ' column
CDHDR_TIME_COL = 'time'          # Matches 'Time    ' column
CDHDR_USER_COL = 'user'          # Matches 'User  ' column
CDHDR_TCODE_COL = 'tcode'        # Matches 'TCode' column
CDHDR_CHANGENR_COL = 'doc.number'  # Matches 'Doc.Number' column
CDHDR_OBJECTCLAS_COL = 'object'    # Matches 'Object' column (normalized)
CDHDR_OBJECTID_COL = 'object value'

# CDPOS Change Document Item columns (normalized to lowercase)
CDPOS_CHANGENR_COL = 'doc.number'        # Matches 'Doc.Number'
CDPOS_TABNAME_COL = 'table name'        # Matches 'Table Name      '
CDPOS_CHNGIND_COL = 'change indicator'  # Matches 'Change Indicator'
CDPOS_FNAME_COL = 'field name'          # Matches 'Field Name         '
CDPOS_TEXT_COL = 'text flag'            # Matches 'Text flag'
CDPOS_VALUE_NEW_COL = 'new value'       # Matches 'New Value'
CDPOS_VALUE_OLD_COL = 'old value'       # Matches 'Old Value'
CDPOS_AGING_COL = 'data aging filter'   # Matches 'Data Aging Filter'

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

def validate_excel_file(file_path, required_columns):
    """
    Validate that an Excel file contains the required columns.
    Returns the DataFrame if valid.
    """
    try:
        # First check if file exists
        validate_file_exists(file_path)
        
        # Try to read the Excel file
        # Read and clean data
        df = pd.read_excel(file_path)
        df.columns = df.columns.str.strip()  # Remove whitespace
        df.columns = df.columns.str.lower()  # Normalize to lowercase
        
        # Normalize required columns to compare
        required_normalized = [col.strip().lower() for col in required_columns]
        
        # Check for required columns with case-insensitive comparison
        missing_columns = []
        for req_col in required_normalized:
            if req_col not in df.columns.str.lower().tolist():
                missing_columns.append(req_col)
                
        if missing_columns:
            raise ValueError(
                f"Missing required columns in {os.path.basename(file_path)}: {', '.join(missing_columns)}\n"
                f"Actual columns: {', '.join(df.columns.tolist())}"
            )
        
        return df
    except Exception as e:
        log_message(f"Error validating Excel file {file_path}: {str(e)}", "ERROR")
        raise

# --- Load and Validate Input Files ---
def load_input_files():
    """Load and validate all input files."""
    log_message("Starting to load and validate input files...")
    
    # Define required columns for each file
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
        log_message(f"File exists: {os.path.exists(SM20_FILE)}")
        log_message(f"File size: {os.path.getsize(SM20_FILE) if os.path.exists(SM20_FILE) else 'N/A'} bytes")
        sm20 = validate_excel_file(SM20_FILE, sm20_required_cols)
        log_message(f"Loaded SM20 with {len(sm20)} records")
        log_message(f"SM20 columns: {', '.join(sm20.columns.tolist())}")
        log_message(f"SM20 first few rows: {sm20.head(2).to_string()}")
        
        # Validate and load CDHDR
        log_message(f"Validating CDHDR file: {CDHDR_FILE}")
        log_message(f"File exists: {os.path.exists(CDHDR_FILE)}")
        log_message(f"File size: {os.path.getsize(CDHDR_FILE) if os.path.exists(CDHDR_FILE) else 'N/A'} bytes")
        cdhdr = validate_excel_file(CDHDR_FILE, cdhdr_required_cols)
        log_message(f"Loaded CDHDR with {len(cdhdr)} records")
        log_message(f"CDHDR columns: {', '.join(cdhdr.columns.tolist())}")
        log_message(f"CDHDR first few rows: {cdhdr.head(2).to_string()}")
        
        # Validate and load CDPOS
        log_message(f"Validating CDPOS file: {CDPOS_FILE}")
        log_message(f"File exists: {os.path.exists(CDPOS_FILE)}")
        log_message(f"File size: {os.path.getsize(CDPOS_FILE) if os.path.exists(CDPOS_FILE) else 'N/A'} bytes")
        cdpos = validate_excel_file(CDPOS_FILE, cdpos_required_cols)
        log_message(f"Loaded CDPOS with {len(cdpos)} records")
        log_message(f"CDPOS columns: {', '.join(cdpos.columns.tolist())}")
        log_message(f"CDPOS first few rows: {cdpos.head(2).to_string()}")
        
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
        # Clean column names
        sm20.columns = sm20.columns.str.strip()
        
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
        sm20['is_display_only'] = sm20[SM20_MSG_COL].str.contains(
            r'DISPLAY|READ|VIEW|SHOW|REPORT|LIST',
            case=False,
            regex=True
        )
        
        # Add SysAid ticket and Comment fields if they exist
        if SM20_SYSAID_COL in sm20.columns:
            sm20['has_sysaid'] = sm20[SM20_SYSAID_COL].notna() & (sm20[SM20_SYSAID_COL] != '')
        else:
            sm20['has_sysaid'] = False
            
        if SM20_COMMENT_COL in sm20.columns:
            sm20['has_comment'] = sm20[SM20_COMMENT_COL].notna() & (sm20[SM20_COMMENT_COL] != '')
        else:
            sm20['has_comment'] = False
        
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
        # Clean column names
        cdhdr.columns = cdhdr.columns.str.strip()
        cdpos.columns = cdpos.columns.str.strip()
        
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
        
        # Perform the time-based merge
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
        
        # Filter for valid correlations (where a match within tolerance was found)
        valid_correlated = correlated.dropna(subset=[sm20_user_col, 'SM20_Datetime']).copy()
        
        # Identify special case: SM20 shows display but CDPOS indicates changes
        valid_correlated.loc[:, 'display_but_changed'] = (
            valid_correlated['is_display_only'] &
            valid_correlated['is_actual_change']
        )
        
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

# --- Risk Assessment and Pattern Detection ---
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
        "FAGLFLEXA", "FAGLFLEXT", "CSKS", "CSKB", "CEPС", "TKA01", "T003", "T012",
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
        "SWWWIHEAD", "SWWUSERWI", "SWWCONT", "SWP_STEP", "SWWLOGHIST",
        
        # Cannabis Industry (if applicable)
        "AUSP", "OBJK", "INOB", "KLAH", "KSSK",
        
        # Add any custom Z-tables that are sensitive for your organization
        # "Z_SENSITIVE_TABLE1", "Z_SENSITIVE_TABLE2"
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

def detect_critical_field_changes(field_name, old_value, new_value):
    """
    Detect if a change involves a critical field based on patterns.
    Returns a tuple of (is_critical, description) if critical, otherwise (False, "").
    """
    if not field_name:
        return False, ""
        
    patterns = get_critical_field_patterns()
    
    for pattern, description in patterns.items():
        if re.search(pattern, field_name):
            return True, f"Critical {description} modified"
            
    return False, ""

def detect_suspicious_timing(timestamp):


def expanded_risk_tag_sm20(row):
    """Risk tagging for unmatched SM20 records (no correlated CDPOS change)."""
    """
    Risk tagging for unmatched SM20 records (no correlated CDPOS change).
    """
    tcode = str(row.get(SM20_TCODE_COL, "")).strip().upper()
    msg = str(row.get(SM20_MSG_COL, "")).strip().upper()
    timestamp = row.get("SM20_Datetime")
    sysaid = str(row.get(SM20_SYSAID_COL, "")).strip() if SM20_SYSAID_COL in row else ""
    comment = str(row.get(SM20_COMMENT_COL, "")).strip() if SM20_COMMENT_COL in row else ""

    sensitive_tcodes = get_sensitive_tcodes()
    is_sensitive_tcode = tcode in sensitive_tcodes

    # Check if suspicious time
    suspicious_time, time_desc = detect_suspicious_timing(timestamp)

    # Heuristics
    if is_sensitive_tcode:
        rationale = f"Sensitive TCode '{tcode}' used with no correlated change document."
        if suspicious_time:
            rationale += f" {time_desc}."
        if sysaid:
            rationale += f" SysAid#: {sysaid}."
        if comment:
            rationale += f" Comment: {comment[:100]}"
        return "Medium", rationale

    if suspicious_time:
        rationale = f"Activity occurred at suspicious hour using TCode '{tcode}'."
        if msg:
            rationale += f" Msg: {msg[:100]}"
        return "Low", rationale

    return "Low", f"No correlated change document. TCode: '{tcode}', Msg: {msg[:100]}"
    """
    Detect if an activity occurred during suspicious hours.
    Returns a tuple of (is_suspicious, description) if suspicious, otherwise (False, "").
    """
    if not timestamp:
        return False, ""
        
    hour = timestamp.hour
    
    for start_hour, end_hour in SUSPICIOUS_TIME_RANGES:
        if start_hour <= hour < end_hour:
            return True, f"Activity occurred during suspicious hours ({hour:02d}:00)"
            
    return False, ""

def expanded_risk_tag(row):
    """
    Enhanced risk tagging function that evaluates activities based on predefined criteria.
    Returns a tuple of (Risk Level, Risk Rationale).
    """
    # Get values using standardized column names
    table = str(row.get("Table_Name", "")).strip().upper()
    tcode_cd = str(row.get("TCode_CD", "")).strip().upper()  # TCode from CDHDR
    tcode_sm20 = str(row.get(SM20_TCODE_COL, "")).strip().upper()  # TCode from SM20
    msg = str(row.get(SM20_MSG_COL, "")).strip().upper() if SM20_MSG_COL in row else ""  # Message from SM20
    chng = str(row.get("Change_Indicator", "")).strip().upper()  # Change indicator from CDPOS
    chg_doc_num = row.get(CDHDR_CHANGENR_COL, 'N/A')  # Change Document number for rationale
    
    # Get additional fields if they exist
    sysaid = str(row.get(SM20_SYSAID_COL, "")).strip() if SM20_SYSAID_COL in row else ""
    comment = str(row.get(SM20_COMMENT_COL, "")).strip() if SM20_COMMENT_COL in row else ""
    field_name = str(row.get(CDPOS_FNAME_COL, "")).strip() if CDPOS_FNAME_COL in row else ""
    new_value = str(row.get(CDPOS_VALUE_NEW_COL, "")).strip() if CDPOS_VALUE_NEW_COL in row else ""
    old_value = str(row.get(CDPOS_VALUE_OLD_COL, "")).strip() if CDPOS_VALUE_OLD_COL in row else ""
    data_aging = str(row.get(CDPOS_AGING_COL, "")).strip() if CDPOS_AGING_COL in row else ""
    
    # Get timestamp for suspicious timing detection
    timestamp = row.get('Change_Timestamp', None)
    
    # Special case detection
    display_but_changed = row.get('display_but_changed', False)
    
    # Determine primary TCode (prefer SM20 TCode if available, else CDHDR TCode)
    tcode = tcode_sm20 if pd.notna(tcode_sm20) and tcode_sm20 != '' else tcode_cd
    
    # Get sensitive tables and tcodes
    sensitive_tables = get_sensitive_tables()
    sensitive_tcodes = get_sensitive_tcodes()
    
    # Change indicators from CDPOS (U=Update, I=Insert, D=Delete, E=Single Field Doc)
    is_chg = chng in ("I", "E", "D", "U")
    
    # Check for Debugging activity
    debug_patterns = ["DEBUG", "DEBUGG", "TRACE", "BREAK", "WATCHPOINT"]
    debug = any(pattern in msg for pattern in debug_patterns) or "RSDEBUG" in tcode or (pd.notna(tcode) and tcode.startswith("/H"))
    
    # Check for sensitive table and tcode
    is_sensitive_table = table in sensitive_tables
    is_sensitive_tcode = tcode in sensitive_tcodes
    
    # Check for RFC calls
    rfc_patterns = ["RFC CALL", "RFC/", "FUNCTION", "BAPI"]
    is_rfc_activity = any(pattern in msg for pattern in rfc_patterns) or (pd.notna(tcode_cd) and tcode_cd.startswith("RFC /")) or tcode == "SM59"
    
    # Check for direct DB changes
    direct_db_tcodes = {"SE11", "SE14", "SE16N", "SM30", "SM31", "MASS"}
    is_direct_db_change = tcode in direct_db_tcodes and is_chg
    
    # Check for system configuration changes
    config_tcodes = {"SPRO", "RZ10", "RZ11", "SCC4", "SALE"}
    is_config_change = tcode in config_tcodes and is_chg
    
    # Check for code modification
    code_mod_tcodes = {"SE38", "SE80", "SE24", "SE37", "SE09", "SE10", "SMOD", "CMOD"}
    is_code_mod = tcode in code_mod_tcodes and is_chg
    
    # Check for job scheduling changes
    job_tcodes = {"SM36", "SM37", "SM39", "SM62", "SM63", "SM64"}
    is_job_change = tcode in job_tcodes and is_chg
    
    # Check for security changes
    security_tcodes = {"PFCG", "SU01", "SUIM", "SU10", "SU24", "SU53", "SU56", "PFCG_TIME_DEPENDENCY"}
    is_security_change = tcode in security_tcodes and is_chg
    
    # --- Risk Logic ---
    # Special case: SM20 shows display but CDPOS indicates changes
    if display_but_changed:
        details = f"CRITICAL: SM20 shows display-only activity but change documents indicate actual changes (type '{chng}') to table '{table}'"
        details += f" via TCode '{tcode}'. ChgDoc: {chg_doc_num}."
        if field_name and (new_value or old_value):
            details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
        if sysaid:
            details += f" SysAid#: {sysaid}"
            if risk_factors:
                details += f" [{', '.join(risk_factors)}]"
            details += "."
        details += " This mismatch requires investigation."
        return "High", details
    
    if is_chg:  # Only assess risk if a change indicator is present
        if debug:
            details = f"Debugging potentially used during change (type '{chng}') to table '{table}'"
            details += f" via TCode '{tcode}'. ChgDoc: {chg_doc_num}."
            if msg:
                details += f" SM20 Msg: {msg[:100]}"
            if sysaid:
                details += f" SysAid#: {sysaid}."
            return "High", details
        
        if is_rfc_activity:
            details = f"RFC activity associated with change (type '{chng}') to table '{table}'"
            details += f" via Function/TCode '{tcode_cd}'. ChgDoc: {chg_doc_num}."
            if field_name and (new_value or old_value):
                details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
            if msg:
                details += f" SM20 Msg: {msg[:100]}"
            if sysaid:
                details += f" SysAid#: {sysaid}."
            return "High", details
        
        if is_sensitive_table:
            # Increase risk level for certain critical tables
            critical_tables = {"USR01", "USR02", "AGR_USERS", "BKPF", "BSEG", "REGUH", "PAYR"}
            if table in critical_tables:
                details = f"CRITICAL sensitive table '{table}' changed (type '{chng}')"
                details += f" via TCode '{tcode}'. ChgDoc: {chg_doc_num}."
                if field_name and (new_value or old_value):
                    details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
                if sysaid:
                    details += f" SysAid#: {sysaid}."
                if comment:
                    details += f" Comment: {comment[:100]}"
                return "High", details
            
            details = f"Sensitive table '{table}' changed (type '{chng}')"
            details += f" via TCode '{tcode}'. ChgDoc: {chg_doc_num}."
            if field_name and (new_value or old_value):
                details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
            if sysaid:
                details += f" SysAid#: {sysaid}."
            return "High", details
        
        if is_sensitive_tcode:
            # Downgrade risk if it's just generic maintenance on non-sensitive table
            if tcode in direct_db_tcodes and not is_sensitive_table:
                details = f"Generic maintenance TCode '{tcode}' used for change (type '{chng}') to non-sensitive table '{table}'"
                details += f". ChgDoc: {chg_doc_num}."
                if field_name and (new_value or old_value):
                    details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
                return "Medium", details
            # Downgrade monitoring TCodes unless specific message indicates sensitive action
            elif tcode in {"SM20", "SM21", "ST03N"} and (not msg or ("CHANGE" not in msg and "DELETE" not in msg and "CREATE" not in msg)):
                details = f"Monitoring TCode '{tcode}' usage recorded. Change type '{chng}' on table '{table}'"
                if table_key:
                    details += f" with key '{table_key}'"
                details += f". ChgDoc: {chg_doc_num}. Unlikely sensitive change."
                return "Low", details
            else:
                # Flag sensitive TCode usage when change occurs
                details = f"Sensitive TCode '{tcode}' used for change (type '{chng}') to table '{table}'"
                details += f". ChgDoc: {chg_doc_num}."
                if field_name and (new_value or old_value):
                    details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
                if sysaid:
                    details += f" SysAid#: {sysaid}."
                return "High", details
        
        # Explicit check for direct changes AFTER sensitive table/TCode checks
        if is_direct_db_change and not is_sensitive_table and not is_sensitive_tcode:  # Avoid double-reporting
            details = f"Potential direct table change (type '{chng}') to '{table}'"
            details += f" via TCode '{tcode}'. ChgDoc: {chg_doc_num}."
            if field_name and (new_value or old_value):
                details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
            if sysaid:
                details += f" SysAid#: {sysaid}."
            return "High", details
        
        if is_config_change:
            details = f"System configuration change via TCode '{tcode}' affecting table '{table}'"
            details += f". ChgDoc: {chg_doc_num}."
            if field_name and (new_value or old_value):
                details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
            if sysaid:
                details += f" SysAid#: {sysaid}."
            return "High", details
        
        if is_code_mod:
            details = f"Code modification activity via TCode '{tcode}' affecting table '{table}'"
            details += f". ChgDoc: {chg_doc_num}."
            if field_name and (new_value or old_value):
                details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
            if sysaid:
                details += f" SysAid#: {sysaid}."
            return "High", details
        
        if is_job_change:
            details = f"Job scheduling change via TCode '{tcode}' affecting table '{table}'"
            details += f". ChgDoc: {chg_doc_num}."
            if field_name and (new_value or old_value):
                details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
            if sysaid:
                details += f" SysAid#: {sysaid}."
            return "High", details
        
        if is_security_change:
            details = f"Security configuration change via TCode '{tcode}' affecting table '{table}'"
            details += f". ChgDoc: {chg_doc_num}."
            if field_name and (new_value or old_value):
                details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
            if sysaid:
                details += f" SysAid#: {sysaid}."
            return "High", details
        
        # If change occurred but none of the above high/medium risk conditions met
        if not is_sensitive_table and not is_sensitive_tcode and not is_direct_db_change and not is_rfc_activity and not debug:
            details = f"Change (type '{chng}') via TCode '{tcode}' to table '{table}'"
            details += f". (Table/TCode not listed as sensitive, no other High risk factors). ChgDoc: {chg_doc_num}."
            if field_name and (new_value or old_value):
                details += f" Field '{field_name}' changed from '{old_value}' to '{new_value}'."
            if sysaid:
                details += f" SysAid#: {sysaid}."
            return "Medium", details
    
    # Default to Low risk if no change indicator or doesn't meet other criteria
    details = f"Activity via TCode '{tcode}' on table '{table}'"
    details += f". Change indicator: '{chng}'. ChgDoc: {chg_doc_num}. Does not meet High/Medium change criteria."
    if sysaid:
        details += f" SysAid#: {sysaid}."
    return "Low", details

# --- Excel Output Generation ---
def generate_excel_output(correlated_df, unmatched_cdpos, unmatched_sm20, output_file):
    """Generate a formatted Excel workbook with the analysis results."""
    log_message(f"Generating Excel output to {output_file}...")
    
    try:
        with pd.ExcelWriter(output_file, engine="xlsxwriter") as writer:
            # Get workbook and create formats
            wb = writer.book
            
            # Define formats
            header_fmt = wb.add_format({
                'bold': True,
                'bg_color': '#D9E1F2',
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
            
            risk_fmt_high = wb.add_format({
                'bold': False,
                'font_color': '#9C0006',
                'bg_color': '#FFC7CE',
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
            
            risk_fmt_medium = wb.add_format({
                'bold': False,
                'font_color': '#9C6500',
                'bg_color': '#FFEB9C',
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
            
            risk_fmt_low = wb.add_format({
                'font_color': '#006100',
                'bg_color': '#C6EFCE',
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
            
            default_fmt = wb.add_format({
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
            
            # --- Sheet 1: Correlated Events ---
            log_message("Creating Correlated Events sheet...")
            correlated_df.to_excel(writer, sheet_name="Correlated_Events", index=False)
            ws_corr = writer.sheets["Correlated_Events"]
            
            # Apply header format and set column widths
            for i, col in enumerate(correlated_df.columns):
                width = max(len(str(col)) + 2, 15)  # Minimum width 15
                if "Rationale" in col: width = 80
                elif "Msg" in col or "Comment" in col: width = 60
                elif col in ("Change_Timestamp", "SM20_Datetime"): width = 20
                elif col == "Table_Name": width = 25
                elif col == "Table Key": width = 30
                elif col == "SysAid#": width = 15
                elif col == "Risk Level": width = 10
                ws_corr.set_column(i, i, width)  # Set width
                ws_corr.write(0, i, col, header_fmt)  # Write header with format
            
            # Apply conditional formatting for risk levels
            try:
                # Find column indices
                risk_level_col_idx = correlated_df.columns.get_loc("Risk Level")
                rationale_col_idx = correlated_df.columns.get_loc("Risk Rationale")
                
                # Apply formats row by row based on Risk Level
                for row_num in range(len(correlated_df)):
                    level = correlated_df.iloc[row_num]['Risk Level']
                    fmt = default_fmt  # Start with default format
                    if level == 'High': fmt = risk_fmt_high
                    elif level == 'Medium': fmt = risk_fmt_medium
                    elif level == 'Low': fmt = risk_fmt_low
                    
                    # Apply the format to the Risk Level and Rationale columns
                    ws_corr.write(row_num + 1, risk_level_col_idx, level, fmt)
                    ws_corr.write(row_num + 1, rationale_col_idx,
                                 correlated_df.iloc[row_num]['Risk Rationale'], fmt)
            except KeyError as e:
                log_message(f"Warning: Column 'Risk Level' or 'Risk Rationale' not found for formatting - {e}", "WARNING")
            except Exception as fmt_e:
                log_message(f"Warning: Error applying risk formatting - {fmt_e}", "WARNING")
            
            # Add autofilter and freeze panes
            ws_corr.autofilter(0, 0, len(correlated_df), len(correlated_df.columns) - 1)
            ws_corr.freeze_panes(1, 0)  # Freeze header row
            
            # --- Sheet 2: Unmatched Change Documents ---
            log_message("Creating Unmatched Change Documents sheet...")
            unmatched_cdpos.to_excel(writer, sheet_name="Unmatched_CD_Changes", index=False)
            ws_unmatch_cd = writer.sheets["Unmatched_CD_Changes"]
            
            # Apply header format and set column widths
            for i, col in enumerate(unmatched_cdpos.columns):
                width = max(len(str(col)) + 2, 15)
                if "Timestamp" in col: width = 20
                elif "Table_Name" in col: width = 25
                ws_unmatch_cd.set_column(i, i, width)
                ws_unmatch_cd.write(0, i, col, header_fmt)
            
            # Add autofilter and freeze panes
            ws_unmatch_cd.autofilter(0, 0, len(unmatched_cdpos), len(unmatched_cdpos.columns) - 1)
            ws_unmatch_cd.freeze_panes(1, 0)
            
            # --- Sheet 3: Unmatched SM20 Logs ---
            log_message("Creating Unmatched SM20 Logs sheet...")
            unmatched_sm20.to_excel(writer, sheet_name="Unmatched_SM20_Logs", index=False)
            ws_unmatch_sm20 = writer.sheets["Unmatched_SM20_Logs"]
            
            # Apply header format and set column widths
            for i, col in enumerate(unmatched_sm20.columns):
                width = max(len(str(col)) + 2, 15)
                if "Datetime" in col: width = 20
                elif "Msg" in col: width = 60
                ws_unmatch_sm20.set_column(i, i, width)
                ws_unmatch_sm20.write(0, i, col, header_fmt)
            
            # Add autofilter and freeze panes
            ws_unmatch_sm20.autofilter(0, 0, len(unmatched_sm20), len(unmatched_sm20.columns) - 1)
            ws_unmatch_sm20.freeze_panes(1, 0)
        
        log_message(f"Excel output successfully generated: {output_file}")
        return True
    
    except Exception as e:
        log_message(f"Error generating Excel output: {str(e)}", "ERROR")
        return False

# --- Main Function ---
def main():
    """Main function to execute the SAP audit analysis."""
    start_time = time.time()
    log_message("Starting SAP Audit Tool...")
    
    try:
        # Step 1: Load and validate input files
        sm20, cdhdr, cdpos = load_input_files()
        
        # Step 2: Prepare data
        sm20_prepared = prepare_sm20(sm20)
        cdpos_merged, cdhdr_user_col = prepare_change_documents(cdhdr, cdpos)
        
        # Step 3: Correlate logs
        correlated_df, sm20_for_unmatched, cdpos_for_unmatched = correlate_logs(
            sm20_prepared, cdpos_merged, SM20_USER_COL, cdhdr_user_col
        )
        
        # Step 4: Identify unmatched records
        unmatched_cdpos, unmatched_sm20 = identify_unmatched_records(
            correlated_df, sm20_for_unmatched, cdpos_for_unmatched
        )

        log_message("Applying risk assessment to unmatched SM20 logs...")
        unmatched_sm20[["Risk Level", "Risk Rationale"]] = unmatched_sm20.apply(
            expanded_risk_tag_sm20, axis=1, result_type="expand"
        )
        
        # Step 5: Apply risk assessment
        log_message("Applying risk assessment to correlated events...")
        correlated_df[["Risk Level", "Risk Rationale"]] = correlated_df.apply(
            expanded_risk_tag, axis=1, result_type="expand"
        )
        
        # Count risk levels
        risk_counts = correlated_df["Risk Level"].value_counts()
        log_message(f"Risk assessment complete. Found {risk_counts.get('High', 0)} high, "
                   f"{risk_counts.get('Medium', 0)} medium, and {risk_counts.get('Low', 0)} low risk events.")
        
        # Step 6: Generate Excel output
        # Sort by risk level (High first) and then by timestamp
        correlated_df['Risk_Sort'] = correlated_df['Risk Level'].map({'High': 0, 'Medium': 1, 'Low': 2})
        correlated_df = correlated_df.sort_values(['Risk_Sort', 'Change_Timestamp'], ascending=[True, False])
        correlated_df = correlated_df.drop('Risk_Sort', axis=1)
        
        generate_excel_output(correlated_df, unmatched_cdpos, unmatched_sm20, OUTPUT_FILE)
        
        # Calculate and display execution time
        elapsed_time = time.time() - start_time
        log_message(f"Analysis complete in {elapsed_time:.2f} seconds.")
        
        return True
    
    except Exception as e:
        log_message(f"Unexpected error in main execution: {str(e)}", "ERROR")
        return False

# --- Script Entry Point ---
if __name__ == "__main__":
    # Print actual paths being used
    print(f"Using the following files:")
    print(f"SM20 file: {os.path.abspath(SM20_FILE)}")
    print(f"CDHDR file: {os.path.abspath(CDHDR_FILE)}")
    print(f"CDPOS file: {os.path.abspath(CDPOS_FILE)}")
    print(f"Output file: {os.path.abspath(OUTPUT_FILE)}")
    
    # Create input directory if it doesn't exist
    input_dir = os.path.join(SCRIPT_DIR, 'input')
    os.makedirs(input_dir, exist_ok=True)
    
    # Add a banner
    print("\n" + "="*80)
    print(" SAP AUDIT TOOL - ENHANCED SECURITY ANALYSIS ".center(80, "*"))
    print(" Analyzes SM20, CDHDR, and CDPOS logs for high-risk activities ".center(80))
    print("="*80 + "\n")
    
    main()
    
    print("\nAnalysis complete. Results saved to:", os.path.abspath(OUTPUT_FILE))
