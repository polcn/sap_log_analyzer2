#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Security Analysis Script (Refactored) - Part 4: Correlation and Session Analysis
"""

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
