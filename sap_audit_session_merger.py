#!/usr/bin/env python3
"""
SAP Audit Tool - Session Merger Module

This module combines SM20, CDHDR, and CDPOS logs into a unified user session timeline.
It creates a chronological view of SAP user activity for internal audit purposes.

Key features:
- Assigns session IDs based on SysAid ticket numbers (or user+date when SysAid is unavailable)
- Preserves all relevant fields from each source
- Joins CDHDR with CDPOS to show field-level changes
- Creates a formatted Excel output with color-coding by source

This refactored version uses the centralized configuration and utility modules
for improved maintainability, error handling, and consistency.
"""

import os
import sys
import pandas as pd
from datetime import datetime, timedelta

# Import configuration and utilities
from sap_audit_config import PATHS, COLUMNS, SETTINGS, SYSAID
from sap_audit_utils import (
    log_message, log_section, log_error, log_stats,
    handle_exception, validate_required_columns, validate_data_quality,
    clean_whitespace, find_latest_file
)

# =========================================================================
# DATA PROCESSING BASE CLASS
# =========================================================================

class DataSourceProcessor:
    """Base class for data source processors in the session merger."""
    
    def __init__(self, source_type):
        """
        Initialize a data source processor.
        
        Args:
            source_type (str): Type of data source (SM20, CDHDR, CDPOS)
        """
        self.source_type = source_type.upper()
        self.column_map = COLUMNS.get(source_type.lower(), {})
    
    def load_data(self, file_path):
        """
        Load data from a CSV file.
        
        Args:
            file_path (str): Path to the CSV file
            
        Returns:
            pd.DataFrame: Loaded data or empty DataFrame if error
        """
        try:
            log_message(f"Loading {self.source_type} file: {file_path}")
            df = pd.read_csv(file_path, encoding=SETTINGS["encoding"])
            log_message(f"Loaded {len(df)} rows from {self.source_type}")
            return df
        except Exception as e:
            log_error(e, f"Error loading {file_path}")
            return pd.DataFrame()
    
    def standardize_column_names(self, df):
        """
        Standardize column names to uppercase.
        
        Args:
            df (pd.DataFrame): DataFrame to process
            
        Returns:
            pd.DataFrame: DataFrame with standardized column names
        """
        if df.empty:
            return df
            
        original_columns = df.columns.tolist()
        df.columns = [col.strip().upper() for col in df.columns]
        
        if len(set(df.columns)) < len(original_columns):
            # Handle duplicate column names
            col_list = df.columns.tolist()
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
            df.columns = renamed_cols
        
        return df
    
    def add_source_identifier(self, df):
        """
        Add source identifier column to DataFrame.
        
        Args:
            df (pd.DataFrame): DataFrame to process
            
        Returns:
            pd.DataFrame: DataFrame with source column added
        """
        df = df.copy()
        df['Source'] = self.source_type
        return df
    
    def process(self, file_path):
        """
        Process the data source - to be implemented by subclasses.
        
        Args:
            file_path (str): Path to the data file
            
        Returns:
            pd.DataFrame: Processed data
        """
        raise NotImplementedError("Subclasses must implement process()")

# =========================================================================
# SM20 PROCESSOR
# =========================================================================

class SM20Processor(DataSourceProcessor):
    """Processor for SM20 security audit log data."""
    
    def __init__(self):
        """Initialize SM20 processor."""
        super().__init__("SM20")
    
    @handle_exception
    def validate_sm20_data(self, df):
        """
        Validate SM20 data before processing.
        
        Args:
            df (pd.DataFrame): DataFrame containing SM20 data
            
        Returns:
            tuple: (is_valid, missing_columns)
        """
        required_columns = [
            self.column_map["user"], 
            self.column_map["date"], 
            self.column_map["time"]
        ]
        return validate_required_columns(df, required_columns, "SM20")
    
    @handle_exception
    def create_datetime_column(self, df):
        """
        Create datetime column from date and time fields.
        
        Args:
            df (pd.DataFrame): DataFrame containing date and time columns
            
        Returns:
            pd.DataFrame: DataFrame with datetime column added
        """
        if df.empty:
            return df
            
        # Make a copy to avoid SettingWithCopyWarning
        df = df.copy()
        
        # Ensure date and time columns exist
        if self.column_map["date"] not in df.columns or self.column_map["time"] not in df.columns:
            log_message(f"Missing date/time columns in {self.source_type} data", "WARNING")
            return df
        
        # Create datetime column
        log_message("Creating datetime column from date and time fields")
        
        try:
            # Ensure both columns are strings
            df[self.column_map["date"]] = df[self.column_map["date"]].astype(str)
            df[self.column_map["time"]] = df[self.column_map["time"]].astype(str)
            
            # Create datetime values
            df['Datetime'] = pd.to_datetime(
                df[self.column_map["date"]] + ' ' + df[self.column_map["time"]],
                errors='coerce'
            )
            
            # Check for NaT values
            nat_count = df['Datetime'].isna().sum()
            if nat_count > 0:
                log_message(f"Warning: {nat_count} rows have invalid date/time in {self.source_type}", "WARNING")
            
            # Drop rows with invalid datetime
            before_count = len(df)
            df = df.dropna(subset=['Datetime'])
            after_count = len(df)
            
            if before_count > after_count:
                log_message(f"Dropped {before_count - after_count} {self.source_type} rows with invalid datetime", "WARNING")
        except Exception as e:
            log_error(e, f"Error creating datetime column for {self.source_type}")
        
        return df
    
    @handle_exception
    def process(self, file_path):
        """
        Process SM20 data.
        
        Args:
            file_path (str): Path to the SM20 CSV file
            
        Returns:
            pd.DataFrame: Processed SM20 data
        """
        # Load data
        df = self.load_data(file_path)
        
        # Validate data
        is_valid, missing_columns = self.validate_sm20_data(df)
        if not is_valid:
            log_message(f"{self.source_type} data validation failed", "WARNING")
            # Continue with best effort
        
        # Clean and standardize
        df = self.standardize_column_names(df)
        df = clean_whitespace(df)
        df = validate_data_quality(df, self.source_type)
        
        # Create datetime column
        df = self.create_datetime_column(df)
        
        # Add source identifier
        df = self.add_source_identifier(df)
        
        # Sort data
        log_message(f"Sorting {self.source_type} data by user and datetime")
        if not df.empty and "Datetime" in df.columns and self.column_map["user"] in df.columns:
            df = df.sort_values(by=[self.column_map["user"], "Datetime"])
        
        log_message(f"Processed {len(df)} {self.source_type} records")
        return df

# =========================================================================
# CDHDR PROCESSOR
# =========================================================================

class CDHDRProcessor(DataSourceProcessor):
    """Processor for CDHDR change document header data."""
    
    def __init__(self):
        """Initialize CDHDR processor."""
        super().__init__("CDHDR")
    
    @handle_exception
    def validate_cdhdr_data(self, df):
        """
        Validate CDHDR data before processing.
        
        Args:
            df (pd.DataFrame): DataFrame containing CDHDR data
            
        Returns:
            tuple: (is_valid, missing_columns)
        """
        required_columns = [
            self.column_map["user"], 
            self.column_map["date"], 
            self.column_map["time"],
            self.column_map["change_number"]
        ]
        return validate_required_columns(df, required_columns, "CDHDR")
    
    @handle_exception
    def create_datetime_column(self, df):
        """
        Create datetime column from date and time fields for CDHDR.
        
        Args:
            df (pd.DataFrame): DataFrame containing date and time columns
            
        Returns:
            pd.DataFrame: DataFrame with datetime column added
        """
        if df.empty:
            return df
            
        # Make a copy to avoid SettingWithCopyWarning
        df = df.copy()
        
        # Check if the date and time columns exist
        if self.column_map["date"] not in df.columns or self.column_map["time"] not in df.columns:
            # Look for similarly named columns
            date_cols = [col for col in df.columns if 'DATE' in col and not col.endswith('_1') and not col.endswith('_2')]
            time_cols = [col for col in df.columns if 'TIME' in col and not col.endswith('_1') and not col.endswith('_2')]
            
            if date_cols and time_cols:
                log_message(f"Using alternative columns: Date={date_cols[0]}, Time={time_cols[0]}")
                date_col = date_cols[0]
                time_col = time_cols[0]
            elif 'DATETIME' in df.columns:
                log_message("Using pre-existing DATETIME column")
                df['Datetime'] = pd.to_datetime(df['DATETIME'], errors='coerce')
                df = df.dropna(subset=['Datetime'])
                return df
            else:
                log_message(f"Cannot find date/time columns in {self.source_type} data", "WARNING")
                return df
        else:
            date_col = self.column_map["date"]
            time_col = self.column_map["time"]
        
        # Create datetime column with better error handling
        try:
            log_message("Creating datetime column from date and time fields")
            
            # Ensure both columns are strings
            df[date_col] = df[date_col].astype(str)
            df[time_col] = df[time_col].astype(str)
            
            # Create datetime values
            df['Datetime'] = pd.to_datetime(
                df[date_col] + ' ' + df[time_col],
                errors='coerce'
            )
            
            # Check for NaT values
            nat_count = df['Datetime'].isna().sum()
            if nat_count > 0:
                log_message(f"Warning: {nat_count} rows have invalid date/time in {self.source_type}", "WARNING")
            
            # Drop rows with invalid datetime
            before_count = len(df)
            df = df.dropna(subset=['Datetime'])
            after_count = len(df)
            
            if before_count > after_count:
                log_message(f"Dropped {before_count - after_count} {self.source_type} rows with invalid datetime", "WARNING")
        except Exception as e:
            log_error(e, f"Error creating datetime column for {self.source_type}")
        
        return df
    
    @handle_exception
    def process(self, file_path):
        """
        Process CDHDR data.
        
        Args:
            file_path (str): Path to the CDHDR CSV file
            
        Returns:
            pd.DataFrame: Processed CDHDR data
        """
        # Load data
        df = self.load_data(file_path)
        
        # Validate data
        is_valid, missing_columns = self.validate_cdhdr_data(df)
        if not is_valid:
            log_message(f"{self.source_type} data validation failed", "WARNING")
            # Continue with best effort
        
        # Clean and standardize
        df = self.standardize_column_names(df)
        df = clean_whitespace(df)
        df = validate_data_quality(df, self.source_type)
        
        # Create datetime column
        df = self.create_datetime_column(df)
        
        # Add source identifier
        df = self.add_source_identifier(df)
        
        # Sort data
        log_message(f"Sorting {self.source_type} data by user and datetime")
        if not df.empty and "Datetime" in df.columns and self.column_map["user"] in df.columns:
            df = df.sort_values(by=[self.column_map["user"], "Datetime"])
        
        log_message(f"Processed {len(df)} {self.source_type} records")
        return df

# =========================================================================
# CDPOS PROCESSOR
# =========================================================================

class CDPOSProcessor(DataSourceProcessor):
    """Processor for CDPOS change document item data."""
    
    def __init__(self):
        """Initialize CDPOS processor."""
        super().__init__("CDPOS")
    
    @handle_exception
    def validate_cdpos_data(self, df):
        """
        Validate CDPOS data before processing.
        
        Args:
            df (pd.DataFrame): DataFrame containing CDPOS data
            
        Returns:
            tuple: (is_valid, missing_columns)
        """
        required_columns = [
            self.column_map["change_number"],
            self.column_map["table_name"],
            self.column_map["field_name"],
            self.column_map["change_indicator"]
        ]
        return validate_required_columns(df, required_columns, "CDPOS")
    
    @handle_exception
    def standardize_change_indicators(self, df):
        """
        Standardize change indicators to uppercase.
        
        Args:
            df (pd.DataFrame): DataFrame containing change indicators
            
        Returns:
            pd.DataFrame: DataFrame with standardized change indicators
        """
        if df.empty or self.column_map["change_indicator"] not in df.columns:
            return df
            
        # Make a copy to avoid SettingWithCopyWarning
        df = df.copy()
        
        # Check if column has data
        if df[self.column_map["change_indicator"]].isna().all():
            return df
            
        # Get unique values before standardization
        unique_values = df[self.column_map["change_indicator"]].dropna().unique()
        log_message(f"Found {len(unique_values)} unique change indicator values: {' '.join(unique_values)}")
        
        # Standardize to uppercase
        df[self.column_map["change_indicator"]] = df[self.column_map["change_indicator"]].astype(str).str.upper()
        log_message("Standardized all change indicators to uppercase")
        
        return df
    
    @handle_exception
    def process(self, file_path):
        """
        Process CDPOS data.
        
        Args:
            file_path (str): Path to the CDPOS CSV file
            
        Returns:
            pd.DataFrame: Processed CDPOS data
        """
        # Load data
        df = self.load_data(file_path)
        
        # Validate data
        is_valid, missing_columns = self.validate_cdpos_data(df)
        if not is_valid:
            log_message(f"{self.source_type} data validation failed", "WARNING")
            # Continue with best effort
        
        # Clean and standardize
        df = self.standardize_column_names(df)
        df = clean_whitespace(df)
        df = validate_data_quality(df, self.source_type)
        
        # Standardize change indicators
        df = self.standardize_change_indicators(df)
        
        # Add source identifier
        df = self.add_source_identifier(df)
        
        # Sort data by change document number
        if not df.empty and self.column_map["change_number"] in df.columns:
            log_message(f"Sorting {self.source_type} data by change document number")
            df = df.sort_values(by=[self.column_map["change_number"]])
        
        log_message(f"Processed {len(df)} {self.source_type} records")
        return df

# =========================================================================
# MERGER FUNCTIONS
# =========================================================================

class SessionMerger:
    """Main class for merging SAP logs into a unified session timeline."""
    
    def __init__(self):
        """Initialize session merger."""
        self.sm20_processor = SM20Processor()
        self.cdhdr_processor = CDHDRProcessor()
        self.cdpos_processor = CDPOSProcessor()
        
        # Column mappings for output
        self.session_cols = COLUMNS["session"]
        
        # Define fields to exclude
        self.exclude_fields = SETTINGS["exclude_fields"]
    
    @handle_exception
    def find_sysaid_column(self, df):
        """
        Find the best column to use for SysAid ticket numbers.
        
        Args:
            df (pd.DataFrame): DataFrame to search for SysAid columns
            
        Returns:
            str or None: Column name to use for SysAid tickets
        """
        for col in SYSAID["column_options"]:
            if col in df.columns:
                # Check if the column has any non-empty values
                if df[col].notna().any() and (df[col] != '').any():
                    log_message(f"Using '{col}' as SysAid ticket reference column")
                    return col
        
        # Case-insensitive search if strict matching fails
        if SETTINGS["column_renaming"]["case_sensitive"] is False:
            df_cols_lower = [c.upper() for c in df.columns]
            for col in SYSAID["column_options"]:
                if col.upper() in df_cols_lower:
                    idx = df_cols_lower.index(col.upper())
                    col_name = df.columns[idx]
                    log_message(f"Using '{col_name}' as SysAid ticket reference column (case-insensitive match)")
                    return col_name
        
        log_message("No SysAid ticket column found with data", "WARNING")
        return None
    
    @handle_exception
    def standardize_sysaid_references(self, df, sysaid_col):
        """
        Standardize SysAid ticket references to a consistent format.
        
        Args:
            df (pd.DataFrame): DataFrame containing SysAid references
            sysaid_col (str): Column containing SysAid references
            
        Returns:
            pd.DataFrame: DataFrame with standardized SysAid references
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
    
    @handle_exception
    def assign_session_ids_by_sysaid(self, df, sysaid_col, time_col, session_col='Session ID'):
        """
        Assign session IDs based on SysAid ticket numbers.
        
        Args:
            df (pd.DataFrame): DataFrame containing session data
            sysaid_col (str): Column name for SysAid ticket numbers
            time_col (str): Column name for datetime
            session_col (str): Output column name for session IDs
            
        Returns:
            pd.DataFrame: DataFrame with session IDs assigned
        """
        if len(df) == 0:
            return df
            
        # Make a copy to avoid SettingWithCopyWarning
        df = df.sort_values(by=[sysaid_col, time_col]).copy()
        
        # Create a standardized SysAid value
        df['_temp_sysaid'] = df[sysaid_col].astype(str)
        df.loc[df['_temp_sysaid'].isin(['nan', 'None', '']), '_temp_sysaid'] = 'UNKNOWN'
        df['_temp_sysaid'] = df['_temp_sysaid'].str.strip().str.upper()
        
        # Sort SysAid numbers by their first occurrence timestamp
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
    
    @handle_exception
    def assign_session_ids_by_user_date(self, df, user_col, time_col, session_col='Session ID'):
        """
        Legacy method: Assign session IDs based on user and calendar date.
        
        Args:
            df (pd.DataFrame): DataFrame containing session data
            user_col (str): Column name for user
            time_col (str): Column name for datetime
            session_col (str): Output column name for session IDs
            
        Returns:
            pd.DataFrame: DataFrame with session IDs assigned
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
    
    @handle_exception
    def assign_session_ids(self, df, user_col, time_col, session_col='Session ID', sysaid_col=None):
        """
        Assign session IDs to rows, using SysAid ticket numbers if available.
        
        Args:
            df (pd.DataFrame): DataFrame containing session data
            user_col (str): Column name for user
            time_col (str): Column name for datetime
            session_col (str): Output column name for session IDs
            sysaid_col (str, optional): Column name for SysAid ticket numbers
            
        Returns:
            pd.DataFrame: DataFrame with session IDs assigned
        """
        if len(df) == 0:
            return df
        
        # If sysaid_col is not specified, try to find it
        if sysaid_col is None:
            sysaid_col = self.find_sysaid_column(df)
        
        # If we found a SysAid column with data, use it for grouping
        if sysaid_col is not None:
            log_message(f"Assigning session IDs based on SysAid ticket numbers from column: {sysaid_col}")
            return self.assign_session_ids_by_sysaid(df, sysaid_col, time_col, session_col)
        else:
            # Check if SysAid integration is required in config
            from sap_audit_config import CONFIG
            if CONFIG.get("enable_sysaid", True):
                # Only raise error if SysAid is required
                error_msg = "CRITICAL ERROR: No SysAid column found. SysAid integration is required for processing."
                log_message(error_msg, "ERROR")
                raise ValueError(error_msg)
            else:
                # If SysAid integration is disabled, fall back to user+date method
                log_message("SysAid integration disabled, using user+date for session IDs", "INFO")
                return self.assign_session_ids_by_user_date(df, user_col, time_col, session_col)
    
    @handle_exception
    def merge_cdhdr_cdpos(self, cdhdr, cdpos):
        """
        Merge CDHDR with CDPOS data.
        
        Args:
            cdhdr (pd.DataFrame): CDHDR data
            cdpos (pd.DataFrame): CDPOS data
            
        Returns:
            pd.DataFrame: Merged data
        """
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
            log_message("Adding placeholder datetime to CDPOS records")
            cdpos['Datetime'] = pd.to_datetime('today')
            cdpos['User'] = 'SYSTEM'  # Default user as placeholder
            cdpos['Source'] = 'CDPOS'
            return cdpos
            
        # If only CDHDR has data, return it as is
        if len(cdhdr) > 0 and len(cdpos) == 0:
            log_message(f"CDPOS is empty but CDHDR has {len(cdhdr)} records. Using CDHDR directly.")
            return cdhdr
        
        # Check if the expected columns exist in CDHDR
        cdhdr_cols = [
            COLUMNS["cdhdr"]["object"],
            COLUMNS["cdhdr"]["object_id"],
            COLUMNS["cdhdr"]["change_number"]
        ]
        
        cdpos_cols = [
            COLUMNS["cdpos"]["change_number"],
            COLUMNS["cdpos"]["table_name"]
        ]
        
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
        
        # Merge on change document number as per requirements
        try:
            merged = pd.merge(
                cdhdr,
                cdpos,
                left_on=COLUMNS["cdhdr"]["change_number"],
                right_on=COLUMNS["cdpos"]["change_number"],
                how='left'
            )
            
            # Update source for rows with CDPOS data
            if COLUMNS["cdpos"]["table_name"] in merged.columns:
                merged.loc[merged[COLUMNS["cdpos"]["table_name"]].notna(), 'Source'] = 'CDPOS'
                log_message(f"Successfully merged CDPOS data: {sum(merged['Source'] == 'CDPOS')} CDPOS records")
            else:
                log_message(f"Warning: {COLUMNS['cdpos']['table_name']} not found in merged data", "WARNING")
            
            return merged
        except Exception as e:
            log_error(e, f"Error merging CDHDR with CDPOS")
            # Return the original CDHDR data if merge fails
            return cdhdr

    @handle_exception
    def prepare_sm20_for_timeline(self, sm20):
        """
        Prepare SM20 data for the unified timeline.
        
        Args:
            sm20 (pd.DataFrame): SM20 data
            
        Returns:
            pd.DataFrame: Prepared SM20 data
        """
        if sm20.empty:
            return pd.DataFrame()
            
        # Make a copy to avoid SettingWithCopyWarning
        sm20_subset = sm20.copy()
        
        # Filter out excluded fields
        for field in self.exclude_fields:
            if field in sm20_subset.columns:
                sm20_subset = sm20_subset.drop(columns=[field])
        
        # Create a mapping dictionary for renaming columns to standardized names
        sm20_cols = COLUMNS["sm20"]
        session_cols = self.session_cols
        
        rename_map = {
            sm20_cols["user"]: session_cols["user"],
            sm20_cols["tcode"]: session_cols["tcode"],
            sm20_cols["message"]: session_cols["description"],
            sm20_cols["event"]: "Event",
            sm20_cols["abap_source"]: "ABAP_Source",
            sm20_cols["note"]: "Note",
            # Variable field standardized names for debug detection
            sm20_cols.get("var_first", "FIRST VARIABLE VALUE FOR EVENT"): "Variable_First",
            sm20_cols.get("var_2", "VARIABLE 2"): "Variable_2",
            sm20_cols.get("var_3", "VARIABLE 3"): "Variable_3",
            sm20_cols.get("var_data", "VARIABLE DATA FOR MESSAGE"): "Variable_Data"
        }
        
        # Only include keys that exist in the dataframe
        rename_map = {k: v for k, v in rename_map.items() if k in sm20_subset.columns}
        sm20_subset = sm20_subset.rename(columns=rename_map)
        
        # Add empty columns for fields not in SM20
        empty_columns = [
            "Object", "Object_ID", "Doc_Number", "Change_Flag", 
            "Table", "Table_Key", "Field", "Change_Indicator", 
            "Text_Flag", "Old_Value", "New_Value"
        ]
        
        for col in empty_columns:
            if col not in sm20_subset.columns:
                sm20_subset[col] = None
        
        return sm20_subset
    
    @handle_exception
    def prepare_cdpos_for_timeline(self, cdhdr_cdpos):
        """
        Prepare CDHDR/CDPOS data for the unified timeline.
        
        Args:
            cdhdr_cdpos (pd.DataFrame): Merged CDHDR/CDPOS data
            
        Returns:
            pd.DataFrame: Prepared CDHDR/CDPOS data
        """
        if cdhdr_cdpos.empty:
            return pd.DataFrame()
            
        # Make a copy to avoid SettingWithCopyWarning
        cdhdr_subset = cdhdr_cdpos.copy()
        
        # Filter out excluded fields
        for field in self.exclude_fields:
            if field in cdhdr_subset.columns:
                cdhdr_subset = cdhdr_subset.drop(columns=[field])
        
        # Create a mapping dictionary for renaming columns to standardized names
        cdhdr_cols = COLUMNS["cdhdr"]
        cdpos_cols = COLUMNS["cdpos"]
        session_cols = self.session_cols
        
        rename_map = {
            cdhdr_cols["user"]: session_cols["user"],
            cdhdr_cols["tcode"]: session_cols["tcode"],
            cdhdr_cols["object"]: session_cols["object"],
            cdhdr_cols["object_id"]: session_cols["object_id"],
            cdhdr_cols["change_number"]: session_cols["doc_number"],
            cdhdr_cols.get("change_flag", "CHANGE FLAG FOR APPLICATION OBJECT"): "Change_Flag",
            cdpos_cols["table_name"]: session_cols["table"],
            cdpos_cols["table_key"]: "Table_Key",
            cdpos_cols["field_name"]: session_cols["field"],
            cdpos_cols["change_indicator"]: session_cols["change_indicator"],
            cdpos_cols.get("text_flag", "TEXT FLAG"): "Text_Flag",
            cdpos_cols["value_old"]: session_cols["old_value"],
            cdpos_cols["value_new"]: session_cols["new_value"]
        }
        
        # Only include keys that exist in the dataframe
        rename_map = {k: v for k, v in rename_map.items() if k in cdhdr_subset.columns}
        cdhdr_subset = cdhdr_subset.rename(columns=rename_map)
        
        # Add Description column (combine object info)
        if session_cols["object"] in cdhdr_subset.columns and session_cols["object_id"] in cdhdr_subset.columns:
            cdhdr_subset[session_cols["description"]] = cdhdr_subset.apply(
                lambda x: f"Changed {x[session_cols['object']]} {x[session_cols['object_id']]}" 
                          if pd.notna(x[session_cols['object']]) else "", 
                axis=1
            )
        
        # Add empty columns for SM20 fields not in CDHDR/CDPOS
        for col in ["Event", "ABAP_Source", "Note"]:
            if col not in cdhdr_subset.columns:
                cdhdr_subset[col] = None
        
        return cdhdr_subset
    
    @handle_exception
    def combine_timeline_sources(self, sm20_timeline, cdpos_timeline):
        """
        Combine SM20 and CDPOS records safely.
        
        Args:
            sm20_timeline (pd.DataFrame): Prepared SM20 data
            cdpos_timeline (pd.DataFrame): Prepared CDPOS data
            
        Returns:
            pd.DataFrame: Combined timeline
        """
        # If both are empty, return empty DataFrame
        if sm20_timeline.empty and cdpos_timeline.empty:
            log_message("No data to combine", "WARNING")
            return pd.DataFrame()
            
        # If only one has data, return it
        if sm20_timeline.empty:
            return cdpos_timeline
        if cdpos_timeline.empty:
            return sm20_timeline
        
        # Record counts before combining
        sm20_count = len(sm20_timeline)
        cdpos_count = len(cdpos_timeline)
        
        # Create list of all column names from both DataFrames
        all_columns = list(set(sm20_timeline.columns) | set(cdpos_timeline.columns))
        
        # Create empty DataFrame with all columns
        combined_data = []
        
        # Add SM20 data
        for _, row in sm20_timeline.iterrows():
            row_dict = {}
            for col in all_columns:
                row_dict[col] = row[col] if col in sm20_timeline.columns else None
            combined_data.append(row_dict)
        
        # Add CDPOS data
        for _, row in cdpos_timeline.iterrows():
            row_dict = {}
            for col in all_columns:
                row_dict[col] = row[col] if col in cdpos_timeline.columns else None
            combined_data.append(row_dict)
        
        # Create new DataFrame
        timeline = pd.DataFrame(combined_data)
        
        # Validate record counts - SM20 + CDPOS = Total
        expected_count = sm20_count + cdpos_count
        actual_count = len(timeline)
        
        if actual_count != expected_count:
            log_message(f"WARNING: Record count mismatch - Expected: {expected_count}, Actual: {actual_count}", "WARNING")
        else:
            log_message(f"Record count validation passed: {actual_count} records match expected total")
        
        return timeline
    
    @handle_exception
    def sort_timeline(self, timeline):
        """
        Sort the unified timeline.
        
        Args:
            timeline (pd.DataFrame): Combined timeline
            
        Returns:
            pd.DataFrame: Sorted timeline
        """
        if timeline.empty:
            return timeline
            
        # Extract numeric part of session ID for proper numerical sorting
        if self.session_cols["id"] in timeline.columns:
            timeline['Session_Num'] = timeline[self.session_cols["id"]].str.extract(r'S(\d+)').astype(int)
            
            # Sort by session number and datetime
            timeline = timeline.sort_values(by=['Session_Num', 'Datetime'])
            
            # Drop the temporary column used for sorting
            timeline = timeline.drop(columns=['Session_Num'])
        else:
            # Fall back to sorting by datetime only
            log_message("Session ID column not found, sorting by datetime only", "WARNING")
            timeline = timeline.sort_values(by=['Datetime'])
        
        # Reset index
        timeline = timeline.reset_index(drop=True)
        
        return timeline
    
    @handle_exception
    def create_unified_timeline(self, sm20, cdhdr_cdpos):
        """
        Create a unified timeline from all sources with proper session assignment.
        
        Args:
            sm20 (pd.DataFrame): SM20 data
            cdhdr_cdpos (pd.DataFrame): Merged CDHDR/CDPOS data
            
        Returns:
            pd.DataFrame: Unified timeline
        """
        log_section("Creating Unified Timeline")
        
        # If we have no data, return empty DataFrame
        if (sm20 is None or sm20.empty) and (cdhdr_cdpos is None or cdhdr_cdpos.empty):
            log_message("No data available for timeline creation", "WARNING")
            return pd.DataFrame()
        
        # Process SM20 records
        if sm20 is not None and not sm20.empty:
            sm20_timeline = self.prepare_sm20_for_timeline(sm20)
            log_message(f"Prepared {len(sm20_timeline)} SM20 records for timeline")
        else:
            sm20_timeline = pd.DataFrame()
        
        # Process CDHDR/CDPOS records
        if cdhdr_cdpos is not None and not cdhdr_cdpos.empty:
            cdpos_timeline = self.prepare_cdpos_for_timeline(cdhdr_cdpos)
            log_message(f"Prepared {len(cdpos_timeline)} CDPOS records for timeline")
        else:
            cdpos_timeline = pd.DataFrame()
        
        # Combine records safely
        timeline = self.combine_timeline_sources(sm20_timeline, cdpos_timeline)
        
        # If we still have no data, return empty DataFrame
        if timeline.empty:
            log_message("No data available after combining sources", "WARNING")
            return timeline
        
        # Find and standardize SysAid ticket numbers if present
        sysaid_col = self.find_sysaid_column(timeline)
        if sysaid_col:
            log_message(f"Found SysAid column: {sysaid_col}")
            timeline = self.standardize_sysaid_references(timeline, sysaid_col)
        
        # Assign session IDs
        log_message("Assigning session IDs to combined timeline...")
        timeline = self.assign_session_ids(timeline, self.session_cols["user"], "Datetime", sysaid_col=sysaid_col)
        
        # Sort timeline
        timeline = self.sort_timeline(timeline)
        
        log_message(f"Unified timeline created with {len(timeline)} total records")
        
        # Generate source statistics
        try:
            source_counts = timeline['Source'].value_counts().to_dict()
            log_stats("Records by source", source_counts)
        except Exception as e:
            log_message(f"Warning: Unable to generate source statistics: {str(e)}", "WARNING")
        
        return timeline
    
    @handle_exception
    def generate_excel_output(self, timeline, output_file):
        """
        Generate a formatted Excel output with the timeline.
        
        Args:
            timeline (pd.DataFrame): Unified timeline
            output_file (str): Path to save Excel output
            
        Returns:
            bool: True if successful, False otherwise
        """
        if timeline.empty:
            log_message("No data to output", "WARNING")
            return False
            
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(os.path.abspath(output_file))
            os.makedirs(output_dir, exist_ok=True)
            
            # Create a copy of the timeline for output
            output_timeline = timeline.copy()
            
            # Reorder columns to put Session ID with Date first
            cols = output_timeline.columns.tolist()
            if self.session_cols["id_with_date"] in cols and self.session_cols["id"] in cols:
                cols.remove(self.session_cols["id_with_date"])
                cols.insert(0, self.session_cols["id_with_date"])
                # Remove the original Session ID column
                cols.remove(self.session_cols["id"])
                output_timeline = output_timeline[cols]
            
            log_message(f"Writing {len(output_timeline)} records to Excel output")
            
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
                    self.session_cols["id_with_date"]: 20,
                    "Source": 8,
                    self.session_cols["user"]: 12,
                    "Datetime": 18,
                    "Event": 15,
                    self.session_cols["tcode"]: 10,
                    "ABAP_Source": 15,
                    self.session_cols["description"]: 40,
                    "Note": 20,
                    self.session_cols["object"]: 15,
                    self.session_cols["object_id"]: 15,
                    self.session_cols["doc_number"]: 12,
                    "Change_Flag": 15,
                    self.session_cols["table"]: 15,
                    "Table_Key": 20,
                    self.session_cols["field"]: 20,
                    self.session_cols["change_indicator"]: 10,
                    "Text_Flag": 10,
                    self.session_cols["old_value"]: 25,
                    self.session_cols["new_value"]: 25
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
            log_error(e, f"Error generating Excel output")
            return False
    
    @handle_exception
    def merge_sessions(self):
        """
        Main method to merge all data sources into a unified timeline.
        
        This method is called by the AuditController to perform the session merging step.
        It processes all data sources and returns the merged timeline DataFrame.
        
        Returns:
            pd.DataFrame: Unified session timeline, or None if processing failed
        """
        start_time = datetime.now()
        log_section("Starting Session Merger")
        
        try:
            # For tests/integration, look for CSV files in test_input directory first (these are created by DataPrepManager)
            input_dir = os.path.dirname(PATHS['sm20_input'])
            
            # Step 1: Load and process SM20 data
            sm20_csv_path = os.path.join(input_dir, 'SM20.csv')
            if os.path.exists(sm20_csv_path):
                log_message(f"Processing SM20 data from CSV: {sm20_csv_path}")
                sm20 = self.sm20_processor.process(sm20_csv_path)
            else:
                log_message(f"Processing SM20 data from original source: {PATHS['sm20_input']}")
                sm20 = self.sm20_processor.process(PATHS["sm20_input"])
            
            # Step 2: Load and process CDHDR data
            cdhdr_csv_path = os.path.join(input_dir, 'CDHDR.csv')
            if os.path.exists(cdhdr_csv_path):
                log_message(f"Processing CDHDR data from CSV: {cdhdr_csv_path}")
                cdhdr = self.cdhdr_processor.process(cdhdr_csv_path)
            else:
                log_message(f"Processing CDHDR data from original source: {PATHS['cdhdr_input']}")
                cdhdr = self.cdhdr_processor.process(PATHS["cdhdr_input"])
            
            # Step 3: Load and process CDPOS data
            cdpos_csv_path = os.path.join(input_dir, 'CDPOS.csv')
            if os.path.exists(cdpos_csv_path):
                log_message(f"Processing CDPOS data from CSV: {cdpos_csv_path}")
                cdpos = self.cdpos_processor.process(cdpos_csv_path)
            else:
                log_message(f"Processing CDPOS data from original source: {PATHS['cdpos_input']}")
                cdpos = self.cdpos_processor.process(PATHS["cdpos_input"])
            
            # Step 4: Merge CDHDR with CDPOS
            log_message("Merging CDHDR with CDPOS data")
            cdhdr_cdpos = self.merge_cdhdr_cdpos(cdhdr, cdpos)
            
            # Step 5: Create unified timeline
            timeline = self.create_unified_timeline(sm20, cdhdr_cdpos)
            
            if timeline is None or timeline.empty:
                log_message("No data to output after processing.", "WARNING")
                return None
                
            # Calculate elapsed time
            elapsed_time = (datetime.now() - start_time).total_seconds()
            log_message(f"Session merging complete in {elapsed_time:.2f} seconds.")
            log_message(f"Created timeline with {len(timeline)} total records")
            
            return timeline
        
        except Exception as e:
            log_error(e, "Error in session merging")
            return None
            
    @handle_exception
    def process(self):
        """
        Legacy method to process all data sources and create timeline with Excel output.
        
        This method is maintained for backward compatibility with direct script execution.
        For integration with the controller, use merge_sessions() instead.
        
        Returns:
            bool: True if processing successful, False otherwise
        """
        start_time = datetime.now()
        log_section("Starting SAP Log Session Merger")
        
        try:
            # Use the main merge_sessions method to get the timeline
            timeline = self.merge_sessions()
            
            if timeline is None or timeline.empty:
                log_message("No data to output after processing.", "WARNING")
                return False
                
            # Generate Excel output
            output_file = PATHS["session_timeline"]
            success = self.generate_excel_output(timeline, output_file)
            
            # Calculate elapsed time
            elapsed_time = (datetime.now() - start_time).total_seconds()
            log_message(f"Processing complete in {elapsed_time:.2f} seconds.")
            
            if success:
                log_message(f"Session timeline saved to: {os.path.abspath(output_file)}")
                print(f"\nSession timeline saved to: {os.path.abspath(output_file)}")
            
            return success
        
        except Exception as e:
            log_error(e, "Error in main execution")
            return False

# =========================================================================
# MAIN FUNCTION
# =========================================================================

@handle_exception
def main():
    """Main function to execute the SAP log session merger."""
    merger = SessionMerger()
    return merger.process()

# =========================================================================
# SCRIPT ENTRY POINT
# =========================================================================

if __name__ == "__main__":
    # Add a banner
    banner = "\n" + "="*80 + "\n"
    banner += " SAP LOG SESSION MERGER ".center(80, "*") + "\n"
    banner += " Creates a unified session timeline from SAP logs ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)
    
    main()
