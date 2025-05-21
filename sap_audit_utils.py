#!/usr/bin/env python3
"""
SAP Audit Tool - Utility Module

This module provides centralized utility functions for the SAP Audit Tool including:
1. Enhanced logging with multiple output options
2. Standardized error handling 
3. Data validation functions
4. Common formatting operations

By centralizing these utilities, we ensure consistent behavior across all modules
and make maintenance and updates easier.
"""

import os
import sys
import json
import traceback
import logging
from datetime import datetime
import pandas as pd
import numpy as np

# Import configuration
try:
    from sap_audit_config import PATHS, COLUMNS, SETTINGS, VERSION
except ImportError:
    # Fallback if config module is not available
    print("Warning: Could not import configuration. Using default values.")
    SETTINGS = {"debug": False, "encoding": "utf-8-sig"}
    PATHS = {"log_dir": os.path.dirname(os.path.abspath(__file__))}
    VERSION = "Unknown"

# =========================================================================
# LOGGING SETUP
# =========================================================================

# Create logs directory if it doesn't exist
LOG_DIR = os.path.join(PATHS.get("script_dir", os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Define log file with timestamp
current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(LOG_DIR, f"sap_audit_{current_time}.log")

# Configure logger
logger = logging.getLogger("sap_audit")
logger.setLevel(logging.DEBUG if SETTINGS.get("debug", False) else logging.INFO)

# File handler
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)  # Always debug level for file
file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_format)
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # Info level for console
console_format = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', 
                                  datefmt='%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(console_format)
logger.addHandler(console_handler)

# =========================================================================
# LOGGING FUNCTIONS
# =========================================================================

def setup_logging(verbose=False, log_file=None):
    """
    Setup and configure logging for the application.
    
    Args:
        verbose: Set to True for DEBUG level logging
        log_file: Optional custom log file path
        
    Returns:
        logger: Configured logging object
    """
    global logger, LOG_FILE
    
    # Reset handlers if already configured
    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
    
    # Set log level based on verbose flag
    logger.setLevel(logging.DEBUG if verbose or SETTINGS.get("debug", False) else logging.INFO)
    
    # Use custom log file if provided
    if log_file:
        LOG_FILE = log_file
    
    # File handler
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)  # Always debug level for file
    file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_format = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', 
                                      datefmt='%Y-%m-%d %H:%M:%S')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    return logger

def log_message(message, level="INFO"):
    """
    Log a message with timestamp and level.
    
    This function provides a simple interface for logging with both console output
    and file logging. It's backward compatible with the original log_message function
    while adding structured logging capabilities.
    
    Args:
        message: The message to log
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    # Map string level to logging level
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    
    log_level = level_map.get(level.upper(), logging.INFO)
    
    # Log using the configured logger
    logger.log(log_level, message)

def log_error(error, message=None, print_traceback=True):
    """
    Log an error with optional traceback.
    
    Args:
        error: The exception object
        message: Optional contextual message
        print_traceback: Whether to include the traceback in the log
    """
    if message:
        log_message(f"{message}: {str(error)}", "ERROR")
    else:
        log_message(f"Error: {str(error)}", "ERROR")
        
    if print_traceback:
        log_message(f"Stack trace: {traceback.format_exc()}", "DEBUG")

def log_section(section_name):
    """
    Log a section header to make logs more readable.
    
    Args:
        section_name: Name of the process section
    """
    separator = "=" * 80
    log_message(separator)
    log_message(f" {section_name} ".center(78, "-"))
    log_message(separator)

def log_stats(description, stats_dict):
    """
    Log statistics in a structured format.
    
    Args:
        description: Description of the statistics
        stats_dict: Dictionary of statistic names and values
    """
    log_message(f"Statistics: {description}")
    for key, value in stats_dict.items():
        log_message(f"  - {key}: {value}")

# =========================================================================
# ERROR HANDLING FUNCTIONS
# =========================================================================

def handle_exception(function):
    """
    Decorator for handling exceptions in functions.
    
    This decorator wraps a function to catch exceptions, log them,
    and return a default value if specified.
    
    Args:
        function: The function to wrap
        
    Returns:
        Wrapped function with exception handling
    """
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception as e:
            log_error(e, f"Error in {function.__name__}")
            
            # Check if the function has a default return value specified
            if hasattr(function, 'default_return'):
                return function.default_return
            
            # Default behaviors based on function name patterns
            if function.__name__.startswith('load_'):
                return None
            elif function.__name__.startswith('process_'):
                return False
            else:
                # Re-raise the exception
                raise
    
    return wrapper

def validate_required_columns(df, required_columns, source_name):
    """
    Validate that a DataFrame contains all required columns.
    
    Args:
        df: DataFrame to validate
        required_columns: List of required column names
        source_name: Name of the data source for error messages
        
    Returns:
        (bool, list): Tuple of (is_valid, missing_columns)
    """
    if df is None or df.empty:
        log_message(f"Empty DataFrame for {source_name}", "WARNING")
        return False, []
        
    # Check for required columns
    missing_columns = [col for col in required_columns if col not in df.columns]
    
    if missing_columns:
        log_message(f"Missing required columns in {source_name}: {', '.join(missing_columns)}", "WARNING")
        return False, missing_columns
    
    return True, []

def validate_data_quality(df, source_name):
    """
    Perform data quality checks on a DataFrame.
    
    Args:
        df: DataFrame to validate
        source_name: Name of the data source for error messages
        
    Returns:
        DataFrame with quality issues flagged
    """
    if df is None or df.empty:
        log_message(f"Empty DataFrame for {source_name}", "WARNING")
        return df
    
    # Count NaN values in each column
    null_counts = df.isna().sum()
    columns_with_nulls = null_counts[null_counts > 0]
    
    if not columns_with_nulls.empty:
        log_message(f"Columns with null values in {source_name}:", "WARNING")
        for col, count in columns_with_nulls.items():
            percentage = 100 * count / len(df)
            log_message(f"  - {col}: {count} nulls ({percentage:.2f}%)", "WARNING")
    
    # Flag duplicate rows if any
    duplicate_count = df.duplicated().sum()
    if duplicate_count > 0:
        percentage = 100 * duplicate_count / len(df)
        log_message(f"Found {duplicate_count} duplicate rows ({percentage:.2f}%) in {source_name}", "WARNING")
    
    return df

# =========================================================================
# DATA TRANSFORMATION FUNCTIONS
# =========================================================================

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

def standardize_column_values(df, column, standardize_case=True, strip_whitespace=True):
    """
    Standardize values in a specific column.
    
    Args:
        df: The DataFrame to modify
        column: Column name to standardize
        standardize_case: Whether to convert to uppercase
        strip_whitespace: Whether to strip whitespace
        
    Returns:
        DataFrame with standardized values
    """
    if column not in df.columns:
        return df
    
    # Make a copy to avoid SettingWithCopyWarning
    df = df.copy()
    
    # Ensure values are strings
    df[column] = df[column].astype(str)
    
    # Strip whitespace
    if strip_whitespace:
        df[column] = df[column].str.strip()
    
    # Convert to uppercase
    if standardize_case:
        df[column] = df[column].str.upper()
    
    # Replace 'nan', 'none', etc.
    df[column] = df[column].replace(['NAN', 'NONE', 'NULL', 'NA'], '')
    
    return df

# =========================================================================
# FORMATTING FUNCTIONS
# =========================================================================

def format_field_info(field_value, field_descriptions):
    """
    Format field information with description if available.
    
    Args:
        field_value: The field name/value
        field_descriptions: Dictionary of field descriptions
        
    Returns:
        Formatted field info string
    """
    if not isinstance(field_value, str) or pd.isna(field_value) or field_value.strip() == "":
        return "unknown"
        
    field_value = field_value.strip()
    field_desc = field_descriptions.get(field_value.upper(), "")
    
    if field_desc:
        return f"{field_value} ({field_desc.split(' - ')[0]})"
    else:
        return field_value

def format_tcode_info(tcode, common_tcode_descriptions, sensitive_tcode_descriptions):
    """
    Format transaction code information with description if available.
    
    Args:
        tcode: The transaction code
        common_tcode_descriptions: Dictionary of common TCode descriptions
        sensitive_tcode_descriptions: Dictionary of sensitive TCode descriptions
        
    Returns:
        Formatted TCode info string
    """
    if not isinstance(tcode, str) or pd.isna(tcode) or tcode.strip() == "":
        return "unknown"
        
    tcode = tcode.strip()
    tcode_desc = common_tcode_descriptions.get(tcode.upper(), 
                 sensitive_tcode_descriptions.get(tcode.upper(), ""))
    
    if tcode_desc:
        return f"{tcode} ({tcode_desc.split(' - ')[0]})"
    else:
        return tcode

def format_table_info(table, common_table_descriptions, sensitive_table_descriptions):
    """
    Format table information with description if available.
    
    Args:
        table: The table name
        common_table_descriptions: Dictionary of common table descriptions
        sensitive_table_descriptions: Dictionary of sensitive table descriptions
        
    Returns:
        Formatted table info string
    """
    if not isinstance(table, str) or pd.isna(table) or table.strip() == "":
        return "unknown"
        
    table = table.strip()
    table_desc = common_table_descriptions.get(table.upper(), 
                sensitive_table_descriptions.get(table.upper(), ""))
    
    if table_desc:
        return f"{table} ({table_desc.split(' - ')[0]})"
    else:
        return table

def format_event_code_info(event_code, event_descriptions):
    """
    Format event code information with description if available.
    
    Args:
        event_code: The event code value
        event_descriptions: Dictionary of event code descriptions
        
    Returns:
        Formatted event code info string
    """
    if not isinstance(event_code, str) or pd.isna(event_code) or event_code.strip() == "":
        return "unknown"
        
    event_code = event_code.strip()
    event_desc = event_descriptions.get(event_code.upper(), "")
    
    if event_desc:
        return f"{event_code} ({event_desc.split(' - ')[0]})"
    else:
        return event_code

# =========================================================================
# UTILITY FUNCTIONS
# =========================================================================

def find_latest_file(pattern):
    """
    Find the most recent file matching the pattern.
    
    Args:
        pattern: Glob pattern to match files
        
    Returns:
        Path to the most recent file, or None if no matches
    """
    import glob
    
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)

def ensure_directory(path):
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path to create
        
    Returns:
        bool: True if directory exists/was created, False on error
    """
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        log_error(e, f"Failed to create directory: {path}")
        return False

def save_json(data, filepath):
    """
    Save data to a JSON file with error handling.
    
    Args:
        data: Data to save (must be JSON serializable)
        filepath: Path to save the file
        
    Returns:
        bool: True if successful, False on error
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        log_error(e, f"Failed to save JSON to {filepath}")
        return False

def load_json(filepath, default=None):
    """
    Load data from a JSON file with error handling.
    
    Args:
        filepath: Path to the JSON file
        default: Default value to return if file not found or invalid
        
    Returns:
        Loaded data or default value on error
    """
    try:
        if not os.path.exists(filepath):
            return default
            
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log_error(e, f"Failed to load JSON from {filepath}")
        return default

# Testing function
if __name__ == "__main__":
    print(f"SAP Audit Utilities Module v{VERSION}")
    log_message("Testing log message - INFO level")
    log_message("This is a warning", "WARNING")
    log_message("This is an error", "ERROR")
    
    try:
        # Test exception handling
        raise ValueError("Test exception")
    except Exception as e:
        log_error(e, "Caught test exception")
    
    print(f"Log file created at: {LOG_FILE}")
