#!/usr/bin/env python3
"""
SAP Audit Data Preparation Module

This module prepares SAP log data files for the main audit tool by:
1. Finding input files matching specific patterns in the input folder
2. Converting all column headers to UPPERCASE
3. Creating datetime columns from date and time fields
4. Sorting data by user and datetime
5. Saving the processed files as CSV with UTF-8-sig encoding in the same input folder
6. Tracking record counts for completeness verification

The module implements the Factory pattern for data source processing,
with specialized processors for each data source type (SM20, CDHDR, CDPOS).
Each processor handles validation, transformation, and output generation.
"""

import os
import sys
import glob
import pandas as pd
from datetime import datetime, timedelta

# Import configuration and utilities
from sap_audit_config import PATHS, COLUMNS, PATTERNS, SETTINGS
from sap_audit_utils import (
    log_message, log_error, log_section, log_stats,
    handle_exception, validate_required_columns, validate_data_quality,
    clean_whitespace, find_latest_file
)

# Import the record counter
from sap_audit_record_counts import record_counter

# =========================================================================
# DATA SOURCE PROCESSOR BASE CLASS
# =========================================================================

class DataSourceProcessor:
    """
    Base class for data source processors.
    
    This class provides the common functionality for processing different 
    types of data sources (SM20, CDHDR, CDPOS). It defines the interface
    that all data source processors must implement.
    """
    
    def __init__(self, source_type):
        """
        Initialize a data source processor.
        
        Args:
            source_type: Type of data source (sm20, cdhdr, cdpos)
        """
        self.source_type = source_type
        
    def find_input_file(self):
        """
        Find the most recent file matching the pattern for this source.
        
        Returns:
            Path to the most recent file, or None if no matches
        """
        pattern = PATTERNS.get(self.source_type)
        return find_latest_file(pattern)
        
    def process(self, input_file, output_file):
        """
        Process the data source - to be implemented by subclasses.
        
        Args:
            input_file: Path to the input file
            output_file: Path where the processed file will be saved
            
        Returns:
            bool: True if processing was successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement process()")
    
    def read_source_file(self, input_file):
        """
        Read a source file with appropriate error handling.
        
        Args:
            input_file: Path to the input file
            
        Returns:
            DataFrame with the source data, or None if error occurred
        """
        try:
            log_message(f"Reading {self.source_type.upper()} file: {input_file}")
            df = pd.read_excel(input_file)
            
            # Check if empty
            if df.empty:
                log_message(f"Warning: {self.source_type.upper()} file is empty: {input_file}", "WARNING")
                return None
                
            # Store original record count for completeness tracking
            original_count = len(df)
            log_message(f"Original {self.source_type.upper()} records: {original_count}")
                
            # Store original column count
            original_col_count = len(df.columns)
            log_message(f"Original columns: {original_col_count}")
            
            return df
        except Exception as e:
            log_error(e, f"Error reading {self.source_type.upper()} file")
            return None
    
    def standardize_columns(self, df):
        """
        Standardize column names to uppercase.
        
        Args:
            df: DataFrame to standardize
            
        Returns:
            DataFrame with standardized column names
        """
        if df is None or df.empty:
            return df
            
        # Store original column count
        original_col_count = len(df.columns)
        
        # Convert all column headers to uppercase
        df.columns = [col.strip().upper() for col in df.columns]
        log_message(f"Converted {original_col_count} column headers to UPPERCASE")
        
        return df
    
    def create_datetime_column(self, df, date_col, time_col):
        """
        Create datetime column from date and time fields.
        
        Args:
            df: DataFrame to modify
            date_col: Column name containing date
            time_col: Column name containing time
            
        Returns:
            DataFrame with added datetime column
        """
        if df is None or df.empty:
            return df
            
        log_message("Creating datetime column from date and time fields")
        try:
            # Convert date and time columns to string to handle potential non-standard formats
            date_str = df[date_col].astype(str)
            time_str = df[time_col].astype(str)
            
            # Combine date and time
            datetime_str = date_str + ' ' + time_str
            
            # Convert to datetime 
            df['DATETIME'] = pd.to_datetime(datetime_str, errors='coerce')
            
            return df
            
        except Exception as e:
            log_error(e, "Error creating datetime column")
            # Attempt to continue with an empty datetime column
            df['DATETIME'] = pd.NaT
            return df
    
    def apply_field_mapping(self, df, field_mapping):
        """
        Apply field name mapping to standardize column names.
        
        Args:
            df: DataFrame to modify
            field_mapping: Dictionary of {old_name: new_name} mappings
            
        Returns:
            DataFrame with standardized column names
        """
        if df is None or df.empty or not field_mapping:
            return df
            
        # Apply field mapping - only if target column doesn't already exist
        for old_name, new_name in field_mapping.items():
            if old_name in df.columns and new_name not in df.columns:
                df = df.rename(columns={old_name: new_name})
                log_message(f"Mapped {old_name} to {new_name}")
        
        return df
    
    def add_missing_columns(self, df, required_columns):
        """
        Add empty columns for any missing required fields.
        
        Args:
            df: DataFrame to modify
            required_columns: List of required column names
            
        Returns:
            DataFrame with all required columns
        """
        if df is None or df.empty:
            return df
            
        # Add empty columns for any missing fields to ensure consistent schema
        for field in required_columns:
            if field not in df.columns:
                log_message(f"Warning: Important field '{field}' not found in {self.source_type.upper()} data - adding empty column", "WARNING")
                df[field] = ""  # Add empty column
        
        return df
    
    def remove_excluded_fields(self, df):
        """
        Remove excluded fields from the DataFrame.
        
        Args:
            df: DataFrame to modify
            
        Returns:
            DataFrame with excluded fields removed
        """
        if df is None or df.empty:
            return df
            
        # Filter out excluded fields
        for field in SETTINGS["exclude_fields"]:
            if field in df.columns:
                log_message(f"Removing excluded field '{field}' from {self.source_type.upper()} data")
                df = df.drop(columns=[field])
        
        return df
    
    def save_processed_file(self, df, output_file):
        """
        Save the processed DataFrame to CSV.
        
        Args:
            df: DataFrame to save
            output_file: Path to save the file
            
        Returns:
            bool: True if save was successful, False otherwise
        """
        if df is None or df.empty:
            log_message(f"Cannot save empty DataFrame to {output_file}", "WARNING")
            return False
            
        try:
            log_message(f"Saving processed {self.source_type.upper()} file to: {output_file}")
            df.to_csv(output_file, index=False, encoding=SETTINGS["encoding"])
            
            # Record final count
            final_count = len(df)
            log_message(f"Successfully saved {final_count} rows to {output_file}")
            return True
        except Exception as e:
            log_error(e, f"Error saving to {output_file}")
            return False

# =========================================================================
# SM20 PROCESSOR IMPLEMENTATION
# =========================================================================

class SM20Processor(DataSourceProcessor):
    """
    Processor for SM20 security audit log files.
    
    Handles the specific requirements for processing SM20 data, including:
    - Dynamic field mapping for different SAP export formats
    - SysAid ticket reference preservation
    - Creating datetime from date and time fields
    - Sorting by user and datetime
    """
    
    def __init__(self):
        """Initialize the SM20 processor."""
        super().__init__("sm20")
        
    def validate_sm20_data(self, df):
        """
        Validate SM20 data before processing.
        
        Args:
            df: DataFrame containing SM20 data
            
        Returns:
            tuple: (is_valid, missing_columns)
        """
        if df is None or df.empty:
            return False, []
            
        # Required columns from config
        required_columns = [
            COLUMNS["sm20"]["user"],
            COLUMNS["sm20"]["date"],
            COLUMNS["sm20"]["time"],
            COLUMNS["sm20"]["event"]
        ]
        
        return validate_required_columns(df, required_columns, "SM20")
    
    def get_sm20_field_mapping(self):
        """
        Get field mapping for SM20 columns that may have different names.
        
        Returns:
            Dictionary mapping alternate column names to standard names
        """
        # Map to standardized column names from config
        standard_cols = COLUMNS["sm20"]
        
        # This is based on SAP's dynamic column behavior where field labels 
        # can change based on GUI layout, language, and kernel patch level
        return {
            # User column variations
            'USERNAME': standard_cols["user"],
            'USER NAME': standard_cols["user"],
            'USER_NAME': standard_cols["user"],
            
            # Alternative date/time columns
            'LOG_DATE': standard_cols["date"],
            'LOG_TIME': standard_cols["time"],
            
            # Event variations
            'EVENT_TYPE': standard_cols["event"],
            
            # Transaction code variations
            'TRANSACTION': standard_cols["tcode"],
            'TCODE': standard_cols["tcode"],
            'TRANSACTION CODE': standard_cols["tcode"],
            
            # ABAP source code variations
            'PROGRAM': standard_cols["abap_source"],
            
            # Message text variations
            'MSG. TEXT': standard_cols["message"],
            'MESSAGE': standard_cols["message"],
            'MESSAGE TEXT': standard_cols["message"],

            # Variable field variations - based on SAP export behavior
            # First variable
            'FIRST VARIABLE': standard_cols["var_first"],
            'VARIABLE 1': standard_cols["var_first"],
            'VARIABLE_1': standard_cols["var_first"],
            'VARIABLE1': standard_cols["var_first"],
            'VAR1': standard_cols["var_first"],
            
            # Second variable/data field
            'VARIABLE 2': standard_cols["var_2"],
            'VARIABLE_2': standard_cols["var_2"],
            'VARIABLE2': standard_cols["var_2"],
            'VAR2': standard_cols["var_2"],
            
            # Variable data field - contains important debugging details
            'VARIABLE DATA': standard_cols["var_data"],
            'VARIABLE_DATA': standard_cols["var_data"],
            'VARIABLEDATA': standard_cols["var_data"],
            'VARIABLE DATA FOR MESSAGE': standard_cols["var_data"],
            'VARIABLE_D': standard_cols["var_data"],
            'VARIABLED': standard_cols["var_data"],
            
            # Third variable field - can be VARIABLE 3 in some extracts
            'VARIABLE 3': standard_cols["var_data"],
            'VARIABLE_3': standard_cols["var_data"],
            'VARIABLE3': standard_cols["var_data"],
            'VAR3': standard_cols["var_data"],
            
            # SysAid ticket reference field - enhanced mapping to capture more variations
            'SYSAID #': standard_cols["sysaid"],
            'SYSAID#': standard_cols["sysaid"],
            'SYSAID': standard_cols["sysaid"],
            'TICKET #': standard_cols["sysaid"],
            'TICKET#': standard_cols["sysaid"],
            'TICKET': standard_cols["sysaid"],
            'CHANGE REQUEST': standard_cols["sysaid"],
            'CHANGE_REQUEST': standard_cols["sysaid"],
            'CR': standard_cols["sysaid"],
            'SR': standard_cols["sysaid"],
            'CR #': standard_cols["sysaid"],
            'SR #': standard_cols["sysaid"],
        }
    
    @handle_exception
    def process(self, input_file, output_file):
        """
        Process SM20 security audit log file with enhanced data preparation.
        
        Args:
            input_file: Path to the input SM20 Excel file
            output_file: Path where the processed CSV file will be saved
        
        Returns:
            bool: True if processing was successful, False otherwise
        """
        # Read the source file
        df = self.read_source_file(input_file)
        if df is None:
            return False
        
        # Store original record count for completeness tracking
        original_count = len(df)
        
        # Standardize column names
        df = self.standardize_columns(df)
        
        # Clean whitespace and handle NaN values
        df = clean_whitespace(df)
        
        # Record count after cleaning
        after_cleaning_count = len(df)
        log_message(f"SM20 records after cleaning: {after_cleaning_count}")
        
        # Apply field mapping for different SAP export formats
        field_mapping = self.get_sm20_field_mapping()
        df = self.apply_field_mapping(df, field_mapping)
        
        # Validate required columns are present
        is_valid, missing_columns = self.validate_sm20_data(df)
        if not is_valid:
            log_message(f"SM20 data validation failed. Missing columns: {', '.join(missing_columns)}", "ERROR")
            # Continue with best effort approach
        
        # Run data quality validation
        df = validate_data_quality(df, "SM20")
        
        # Add missing required columns if any
        required_columns = [
            COLUMNS["sm20"]["user"], 
            COLUMNS["sm20"]["date"], 
            COLUMNS["sm20"]["time"], 
            COLUMNS["sm20"]["event"],
            COLUMNS["sm20"]["tcode"], 
            COLUMNS["sm20"]["message"], 
            COLUMNS["sm20"]["var_first"],
            COLUMNS["sm20"]["var_2"], 
            COLUMNS["sm20"]["var_data"]
        ]
        df = self.add_missing_columns(df, required_columns)
        
        # Remove excluded fields
        df = self.remove_excluded_fields(df)
        
        # Create datetime column from date and time fields
        df = self.create_datetime_column(df, COLUMNS["sm20"]["date"], COLUMNS["sm20"]["time"])
        
        # Sort by user and datetime
        log_message("Sorting SM20 data by user and datetime")
        df = df.sort_values(by=[COLUMNS["sm20"]["user"], 'DATETIME'])
        
        # Save the processed file
        success = self.save_processed_file(df, output_file)
        
        if success:
            # Update record counter
            record_counter.update_source_counts(
                source_type="sm20",
                file_name=input_file,
                original_count=original_count,
                after_cleaning=after_cleaning_count,
                final_count=len(df)
            )
            return True
        else:
            return False

# =========================================================================
# CDHDR PROCESSOR IMPLEMENTATION
# =========================================================================

class CDHDRProcessor(DataSourceProcessor):
    """
    Processor for CDHDR change document header files.
    
    Handles the specific requirements for processing CDHDR data, including:
    - Field mapping for different SAP export formats
    - SysAid ticket reference preservation
    - Creating datetime from date and time fields
    - Sorting by user and datetime
    """
    
    def __init__(self):
        """Initialize the CDHDR processor."""
        super().__init__("cdhdr")
        
    def validate_cdhdr_data(self, df):
        """
        Validate CDHDR data before processing.
        
        Args:
            df: DataFrame containing CDHDR data
            
        Returns:
            tuple: (is_valid, missing_columns)
        """
        if df is None or df.empty:
            return False, []
            
        # Required columns from config
        required_columns = [
            COLUMNS["cdhdr"]["user"],
            COLUMNS["cdhdr"]["date"],
            COLUMNS["cdhdr"]["time"],
            COLUMNS["cdhdr"]["change_number"]
        ]
        
        return validate_required_columns(df, required_columns, "CDHDR")
    
    def get_cdhdr_field_mapping(self):
        """
        Get field mapping for CDHDR columns that may have different names.
        
        Returns:
            Dictionary mapping alternate column names to standard names
        """
        # Map to standardized column names from config
        standard_cols = COLUMNS["cdhdr"]
        
        # Based on SAP's variable field dynamics across different exports
        return {
            # Transaction code variations
            'TRANSACTION': standard_cols["tcode"],
            'TRANSACTION CODE': standard_cols["tcode"],
            'TRANSACTION_CODE': standard_cols["tcode"],
            
            # User name variations
            'USERNAME': standard_cols["user"],
            'USER NAME': standard_cols["user"],
            'USER_NAME': standard_cols["user"],
            
            # Change document number variations
            'CHANGE DOC.': standard_cols["change_number"],
            'CHANGE DOCUMENT': standard_cols["change_number"],
            'CHANGEDOCUMENT': standard_cols["change_number"],
            'CHANGE NUMBER': standard_cols["change_number"],
            'CHANGENUMBER': standard_cols["change_number"],
            
            # Object class variations
            'OBJECTCLASS': standard_cols["object"],
            'OBJECT CLASS': standard_cols["object"],
            'OBJECT_CLASS': standard_cols["object"],
            
            # Object ID variations
            'OBJECTID': standard_cols["object_id"],
            'OBJECT ID': standard_cols["object_id"],
            'OBJECT_ID': standard_cols["object_id"],
            
            # Change flag variations
            'CHANGE FLAG': standard_cols["change_flag"],
            'CHANGEFLAG': standard_cols["change_flag"],
            'CHANGE_FLAG': standard_cols["change_flag"],
            
            # SysAid ticket reference field variations
            'SYSAID #': standard_cols["sysaid"],
            'SYSAID#': standard_cols["sysaid"],
            'SYSAID': standard_cols["sysaid"],
            'TICKET #': standard_cols["sysaid"],
            'TICKET#': standard_cols["sysaid"],
            'TICKET': standard_cols["sysaid"],
            'CHANGE REQUEST': standard_cols["sysaid"],
            'CHANGE_REQUEST': standard_cols["sysaid"],
            'CR': standard_cols["sysaid"],
            'SR': standard_cols["sysaid"],
            'CR #': standard_cols["sysaid"],
            'SR #': standard_cols["sysaid"],
        }
    
    @handle_exception
    def process(self, input_file, output_file):
        """
        Process CDHDR change document header file with enhanced data preparation.
        
        Args:
            input_file: Path to the input CDHDR Excel file
            output_file: Path where the processed CSV file will be saved
        
        Returns:
            bool: True if processing was successful, False otherwise
        """
        # Read the source file
        df = self.read_source_file(input_file)
        if df is None:
            return False
        
        # Store original record count for completeness tracking
        original_count = len(df)
        
        # Standardize column names
        df = self.standardize_columns(df)
        
        # Clean whitespace and handle NaN values
        df = clean_whitespace(df)
        
        # Record count after cleaning
        after_cleaning_count = len(df)
        log_message(f"CDHDR records after cleaning: {after_cleaning_count}")
        
        # Apply field mapping for different SAP export formats
        field_mapping = self.get_cdhdr_field_mapping()
        df = self.apply_field_mapping(df, field_mapping)
        
        # Validate required columns are present
        is_valid, missing_columns = self.validate_cdhdr_data(df)
        if not is_valid:
            log_message(f"CDHDR data validation failed. Missing columns: {', '.join(missing_columns)}", "ERROR")
            # Continue with best effort approach
        
        # Run data quality validation
        df = validate_data_quality(df, "CDHDR")
        
        # Add missing required columns if any
        required_columns = [
            COLUMNS["cdhdr"]["user"], 
            COLUMNS["cdhdr"]["date"], 
            COLUMNS["cdhdr"]["time"], 
            COLUMNS["cdhdr"]["tcode"],
            COLUMNS["cdhdr"]["change_number"], 
            COLUMNS["cdhdr"]["object"], 
            COLUMNS["cdhdr"]["object_id"]
        ]
        df = self.add_missing_columns(df, required_columns)
        
        # Remove excluded fields
        df = self.remove_excluded_fields(df)
        
        # Create datetime column from date and time fields
        df = self.create_datetime_column(df, COLUMNS["cdhdr"]["date"], COLUMNS["cdhdr"]["time"])
        
        # Sort by user and datetime
        log_message("Sorting CDHDR data by user and datetime")
        df = df.sort_values(by=[COLUMNS["cdhdr"]["user"], 'DATETIME'])
        
        # Save the processed file
        success = self.save_processed_file(df, output_file)
        
        if success:
            # Update record counter
            record_counter.update_source_counts(
                source_type="cdhdr",
                file_name=input_file,
                original_count=original_count,
                after_cleaning=after_cleaning_count,
                final_count=len(df)
            )
            return True
        else:
            return False

# =========================================================================
# CDPOS PROCESSOR IMPLEMENTATION
# =========================================================================

class CDPOSProcessor(DataSourceProcessor):
    """
    Processor for CDPOS change document item files.
    
    Handles the specific requirements for processing CDPOS data, including:
    - Standardizing change indicators
    - Preserving table keys and field names
    - Sorting by change document number
    """
    
    def __init__(self):
        """Initialize the CDPOS processor."""
        super().__init__("cdpos")
        
    def validate_cdpos_data(self, df):
        """
        Validate CDPOS data before processing.
        
        Args:
            df: DataFrame containing CDPOS data
            
        Returns:
            tuple: (is_valid, missing_columns)
        """
        if df is None or df.empty:
            return False, []
            
        # Required columns from config
        required_columns = [
            COLUMNS["cdpos"]["change_number"],
            COLUMNS["cdpos"]["table_name"],
            COLUMNS["cdpos"]["field_name"],
            COLUMNS["cdpos"]["change_indicator"]
        ]
        
        return validate_required_columns(df, required_columns, "CDPOS")
    
    def standardize_change_indicators(self, df):
        """
        Standardize change indicators to uppercase.
        
        Args:
            df: DataFrame to standardize
            
        Returns:
            DataFrame with standardized change indicators
        """
        if df is None or df.empty:
            return df
            
        change_ind_col = COLUMNS["cdpos"]["change_indicator"]
        
        try:
            if change_ind_col in df.columns:
                # First get all unique values to report
                unique_indicators = df[change_ind_col].unique()
                log_message(f"Found {len(unique_indicators)} unique change indicator values: {' '.join(map(str, unique_indicators))}")
                
                # Then convert all to uppercase
                df[change_ind_col] = df[change_ind_col].str.upper()
                log_message("Standardized all change indicators to uppercase")
        except Exception as e:
            log_error(e, "Error standardizing change indicators")
        
        return df
    
    @handle_exception
    def process(self, input_file, output_file):
        """
        Process CDPOS change document items file with enhanced data preparation.
        
        Args:
            input_file: Path to the input CDPOS Excel file
            output_file: Path where the processed CSV file will be saved
        
        Returns:
            bool: True if processing was successful, False otherwise
        """
        # Read the source file
        df = self.read_source_file(input_file)
        if df is None:
            return False
        
        # Store original record count for completeness tracking
        original_count = len(df)
        
        # Standardize column names
        df = self.standardize_columns(df)
        
        # Clean whitespace and handle NaN values
        df = clean_whitespace(df)
        
        # Record count after cleaning
        after_cleaning_count = len(df)
        log_message(f"CDPOS records after cleaning: {after_cleaning_count}")
        
        # Validate required columns are present
        is_valid, missing_columns = self.validate_cdpos_data(df)
        if not is_valid:
            log_message(f"CDPOS data validation failed. Missing columns: {', '.join(missing_columns)}", "ERROR")
            # Continue with best effort approach
        
        # Run data quality validation
        df = validate_data_quality(df, "CDPOS")
        
        # Add missing required columns if any
        required_columns = [
            COLUMNS["cdpos"]["change_number"],
            COLUMNS["cdpos"]["table_name"], 
            COLUMNS["cdpos"]["table_key"],
            COLUMNS["cdpos"]["field_name"], 
            COLUMNS["cdpos"]["change_indicator"], 
            COLUMNS["cdpos"]["text_flag"],
            COLUMNS["cdpos"]["value_new"], 
            COLUMNS["cdpos"]["value_old"]
        ]
        df = self.add_missing_columns(df, required_columns)
        
        # Remove excluded fields
        df = self.remove_excluded_fields(df)
        
        # Standardize change indicators
        df = self.standardize_change_indicators(df)
        
        # Sort by change document number
        log_message("Sorting CDPOS data by change document number")
        df = df.sort_values(by=[COLUMNS["cdpos"]["change_number"]])
        
        # Save the processed file
        success = self.save_processed_file(df, output_file)
        
        if success:
            # Update record counter
            record_counter.update_source_counts(
                source_type="cdpos",
                file_name=input_file,
                original_count=original_count,
                after_cleaning=after_cleaning_count,
                final_count=len(df)
            )
            return True
        else:
            return False

# =========================================================================
# DATA PREPARATION MANAGER
# =========================================================================

class DataPrepManager:
    """
    Manager class for data preparation processes.
    
    This class orchestrates the preparation of all SAP data files by:
    1. Finding appropriate input files for each data source
    2. Processing them using specialized processors
    3. Tracking success/failure of each step
    4. Reporting on results
    
    It acts as a facade for the various data processors, providing
    a unified interface for the controller to interact with.
    """
    
    def __init__(self, config=None):
        """
        Initialize the data preparation manager.
        
        Args:
            config: Optional configuration dictionary that can override
                   default settings and paths.
        """
        self.config = config or {}
        self.paths = PATHS.copy()
        
        # Override paths if specified in config
        if config and "paths" in config:
            for key, value in config["paths"].items():
                self.paths[key] = value
                
        # Initialize processors
        self.processors = {
            "sm20": SM20Processor(),
            "cdhdr": CDHDRProcessor(),
            "cdpos": CDPOSProcessor()
        }
        
        # Results tracking
        self.results = {}
    
    def process_input_files(self):
        """
        Process all SAP data input files.
        
        This is the main entry point for the data preparation stage.
        It orchestrates the processing of all data sources and 
        tracks success/failure for each.
        
        Returns:
            bool: True if all processors completed successfully, 
                  False if any processor failed.
        """
        log_section("Starting SAP Audit Data Preparation")
        
        # Create input directory if it doesn't exist
        os.makedirs(self.paths["input_dir"], exist_ok=True)
        
        # Reset results
        self.results = {}
        
        # Process each data source
        for source_type, processor in self.processors.items():
            input_file = processor.find_input_file()
            if input_file:
                log_message(f"Found {source_type.upper()} file: {input_file}")
                output_file = os.path.join(self.paths["input_dir"], f"{source_type.upper()}.csv")
                self.results[source_type] = processor.process(input_file, output_file)
            else:
                log_message(f"No {source_type.upper()} file found matching pattern", "WARNING")
                self.results[source_type] = False
        
        # Log overall success/failure
        successful = sum(1 for result in self.results.values() if result)
        log_message(f"Data preparation completed. {successful} of {len(self.processors)} sources processed successfully.")
        
        # List output files
        log_message("Output files:")
        for source_type in self.processors.keys():
            output_file = os.path.join(self.paths["input_dir"], f"{source_type.upper()}.csv")
            if self.results.get(source_type, False):
                log_message(f"  {source_type.upper()}: {output_file}")
        
        return all(self.results.values())
    
    def get_results(self):
        """
        Get the processing results.
        
        Returns:
            dict: Dictionary of results for each processor
        """
        return self.results.copy()

# =========================================================================
# MAIN FUNCTION
# =========================================================================

@handle_exception
def main():
    """Main function to prepare all SAP data files."""
    # Create data prep manager
    manager = DataPrepManager()
    
    # Run data preparation
    success = manager.process_input_files()
    
    return success

if __name__ == "__main__":
    main()
