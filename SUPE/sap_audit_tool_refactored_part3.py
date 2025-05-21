#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Security Analysis Script (Refactored) - Part 3: Data Loading and Preparation
"""

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
