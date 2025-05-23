#!/usr/bin/env python3
"""
SAP Audit Tool - Utility Functions

This module provides common utility functions used across the SAP Audit Tool modules.
These include logging functions, exception handling, data cleaning, and validation.
"""

import sys
import os
import glob
import traceback
import pandas as pd
import numpy as np
from datetime import datetime
from functools import wraps
from typing import Tuple, List, Dict, Any, Optional, Callable

def log_message(message, level="INFO"):
    """
    Log a message with timestamp and level.
    
    Args:
        message: The message to log
        level: The log level (INFO, WARNING, ERROR, DEBUG)
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def log_section(section_name):
    """
    Log a section header for better visual separation in logs.
    
    Args:
        section_name: The name of the section
    """
    print("\n" + "="*80)
    print(f" {section_name} ".center(80, "-"))
    print("="*80 + "\n")

def log_error(exception, message=None):
    """
    Log an exception with traceback.
    
    Args:
        exception: The exception object
        message: Optional context message
    """
    if message:
        log_message(f"{message}: {str(exception)}", "ERROR")
    else:
        log_message(f"Error: {str(exception)}", "ERROR")
    
    # Get and log the traceback
    tb_lines = traceback.format_exception(type(exception), exception, exception.__traceback__)
    print("".join(tb_lines))

def handle_exception(func):
    """
    Decorator for exception handling in class methods.
    
    Args:
        func: The function to wrap
        
    Returns:
        Wrapped function that handles exceptions
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log_error(e, f"Error in {func.__name__}")
            
            # Return appropriate default value based on function's return annotation
            return_annotation = func.__annotations__.get('return', None)
            if return_annotation is bool:
                return False
            elif return_annotation is pd.DataFrame:
                return pd.DataFrame()
            elif return_annotation is dict:
                return {}
            elif return_annotation is list:
                return []
            else:
                return None
                
    return wrapper

def clean_whitespace(df):
    """
    Clean whitespace in string columns of a DataFrame.
    
    Args:
        df: DataFrame to clean
        
    Returns:
        Cleaned DataFrame
    """
    # Create a copy to avoid SettingWithCopyWarning
    df_clean = df.copy()
    
    # Only process string columns
    string_cols = df_clean.select_dtypes(include=['object']).columns
    
    for col in string_cols:
        # Skip columns that are not strings
        if pd.api.types.is_string_dtype(df_clean[col]):
            try:
                # Strip whitespace and handle NaN
                df_clean[col] = df_clean[col].astype(str).str.strip()
                df_clean[col] = df_clean[col].replace('nan', '')
            except Exception as e:
                log_message(f"Error cleaning column {col}: {str(e)}", "WARNING")
                
    return df_clean

def validate_required_columns(df, required_columns, context=""):
    """
    Validate that a DataFrame contains all required columns.
    
    Args:
        df: DataFrame to validate
        required_columns: List of required column names
        context: Optional context for error messages
        
    Returns:
        Tuple of (bool, list) where bool indicates success and list contains missing columns
    """
    if context:
        context_str = f" for {context}"
    else:
        context_str = ""
        
    if df is None:
        log_message(f"Cannot validate columns{context_str}: DataFrame is None", "ERROR")
        return False, required_columns
        
    missing_columns = [col for col in required_columns if col not in df.columns]
    
    if missing_columns:
        log_message(f"Missing required columns{context_str}: {', '.join(missing_columns)}", "WARNING")
        return False, missing_columns
        
    return True, []
    
def standardize_column_names(df, column_mappings, case_sensitive=False):
    """
    Standardize column names based on mappings.
    
    Args:
        df: DataFrame to process
        column_mappings: Dictionary of {standard_name: [possible_variations]}
        case_sensitive: Whether to match column names case-sensitively
        
    Returns:
        DataFrame with standardized column names
    """
    df_copy = df.copy()
    original_columns = df_copy.columns.tolist()
    column_mapping = {}
    
    for standard_name, variations in column_mappings.items():
        for var in variations:
            # Case-insensitive matching
            if not case_sensitive:
                matches = [col for col in original_columns if col.upper() == var.upper()]
                if matches:
                    column_mapping[matches[0]] = standard_name
            # Case-sensitive matching
            else:
                if var in original_columns:
                    column_mapping[var] = standard_name
                    
    # Rename columns based on mapping
    if column_mapping:
        df_copy = df_copy.rename(columns=column_mapping)
        log_message(f"Standardized {len(column_mapping)} column names")
        
    return df_copy

def format_datetime(dt, format=None):
    """
    Format a datetime object or string to a standard format.
    
    Args:
        dt: Datetime object or string
        format: Optional output format
        
    Returns:
        Formatted datetime string
    """
    if format is None:
        format = "%Y-%m-%d %H:%M:%S"
        
    if isinstance(dt, str):
        try:
            # Try to parse the string to datetime first
            dt = pd.to_datetime(dt)
        except:
            return dt
            
    try:
        return dt.strftime(format)
    except:
        return str(dt)

def add_timestamp_column(df, date_col, time_col, output_col="Datetime"):
    """
    Add a proper datetime column from separate date and time columns.
    
    Args:
        df: DataFrame to process
        date_col: Name of the date column
        time_col: Name of the time column
        output_col: Name for the output column
        
    Returns:
        DataFrame with added timestamp column
    """
    if date_col not in df.columns or time_col not in df.columns:
        log_message(f"Cannot create timestamp: missing {date_col} or {time_col} column", "WARNING")
        return df
        
    try:
        df_copy = df.copy()
        # Convert to string first to handle different formats
        date_str = df_copy[date_col].astype(str)
        time_str = df_copy[time_col].astype(str)
        
        # Combine date and time
        df_copy[output_col] = pd.to_datetime(date_str + ' ' + time_str, errors='coerce')
        
        # Check for NaT values
        nat_count = df_copy[output_col].isna().sum()
        if nat_count > 0:
            log_message(f"Warning: {nat_count} rows have invalid date/time values", "WARNING")
            
        return df_copy
    except Exception as e:
        log_error(e, "Error creating datetime column")
        return df

def log_stats(data_or_context, context_or_data=None):
    """
    Log statistical information about a DataFrame or dictionary.
    
    This flexible function can handle different types of inputs:
    1. (DataFrame, context_string): Log statistics about a DataFrame with optional context
    2. (context_string, dictionary): Log key-value statistics from a dictionary with a context

    Args:
        data_or_context: Either a DataFrame to analyze or a context string
        context_or_data: Either a context string or a dictionary of statistics
    """
    # Determine which parameter is which based on types
    if isinstance(data_or_context, pd.DataFrame):
        # Case 1: First parameter is DataFrame, second is context string
        df = data_or_context
        context = context_or_data or ""
        
        if df is None or df.empty:
            log_message(f"Cannot log stats for empty DataFrame{' for ' + context if context else ''}", "WARNING")
            return
            
        context_str = f" for {context}" if context else ""
        
        # Basic statistics
        total_rows = len(df)
        total_cols = len(df.columns)
        memory_usage = df.memory_usage(deep=True).sum() / (1024 * 1024)  # in MB
        
        log_message(f"DataFrame Statistics{context_str}:")
        log_message(f"  - Records: {total_rows}")
        log_message(f"  - Columns: {total_cols}")
        log_message(f"  - Memory Usage: {memory_usage:.2f} MB")
        
        # Missing values
        missing_values = df.isna().sum().sum()
        if missing_values > 0:
            missing_pct = (missing_values / (total_rows * total_cols)) * 100
            log_message(f"  - Missing Values: {missing_values} ({missing_pct:.2f}%)")
            
            # Columns with most missing values
            cols_with_missing = df.columns[df.isna().any()].tolist()
            if cols_with_missing:
                top_missing = df[cols_with_missing].isna().sum().sort_values(ascending=False).head(3)
                log_message(f"  - Top columns with missing values: {', '.join([f'{col} ({count})' for col, count in top_missing.items()])}")
        
        # Duplicate rows
        duplicate_rows = df.duplicated().sum()
        if duplicate_rows > 0:
            duplicate_pct = (duplicate_rows / total_rows) * 100
            log_message(f"  - Duplicate Rows: {duplicate_rows} ({duplicate_pct:.2f}%)")
            
    elif isinstance(data_or_context, str):
        # Case 2: First parameter is context string, second is dictionary
        context = data_or_context
        data_dict = context_or_data
        
        if not isinstance(data_dict, dict):
            log_message(f"Cannot log stats for non-dictionary data for context '{context}'", "WARNING")
            return
            
        if not data_dict:
            log_message(f"No statistics data available for '{context}'", "WARNING")
            return
            
        log_message(f"Statistics for {context}:")
        for key, value in data_dict.items():
            log_message(f"  - {key}: {value}")
    
    else:
        # Handle other cases or provide a useful error
        log_message(f"Invalid data type for log_stats: {type(data_or_context).__name__}", "WARNING")

def validate_data_quality(df, context=""):
    """
    Perform data quality checks on a DataFrame.
    
    Args:
        df: DataFrame to validate
        context: Optional context for error messages
        
    Returns:
        The DataFrame, possibly with quality issues fixed
    """
    if df is None or df.empty:
        log_message(f"Cannot validate empty DataFrame{' for ' + context if context else ''}", "WARNING")
        return df
        
    df_result = df.copy()
    context_str = f" for {context}" if context else ""
    
    # Check for and handle missing values
    missing_count = df_result.isna().sum().sum()
    if missing_count > 0:
        log_message(f"Found {missing_count} missing values{context_str}", "WARNING")
        
        # Replace missing values with empty strings for object columns
        for col in df_result.select_dtypes(include=['object']).columns:
            null_count = df_result[col].isna().sum()
            if null_count > 0:
                log_message(f"  - Replacing {null_count} NaN values with empty strings in column '{col}'")
                df_result[col] = df_result[col].fillna('')
        
        # For numeric columns, we leave NaN values as is to maintain data integrity
        # but we log which columns have them
        numeric_cols_with_na = [
            col for col in df_result.select_dtypes(include=['number']).columns
            if df_result[col].isna().any()
        ]
        
        if numeric_cols_with_na:
            log_message(f"  - Warning: Numeric columns with NaN values: {', '.join(numeric_cols_with_na)}", "WARNING")
    
    # Check for duplicate rows
    duplicate_count = df_result.duplicated().sum()
    if duplicate_count > 0:
        log_message(f"Found {duplicate_count} duplicate rows{context_str}", "WARNING")
        log_message("  - Keeping duplicate rows as they may represent valid repeated events")
    
    # Handle problematic whitespace in string columns
    string_cols = df_result.select_dtypes(include=['object']).columns
    for col in string_cols:
        # First make sure we're dealing with string data
        # Convert column to string type safely, but only if it's an object type column
        if df_result[col].dtype == 'object':
            # Check for non-string objects and convert to strings
            has_non_string = False
            for val in df_result[col].dropna().head(10):  # Check a few values
                if not isinstance(val, str):
                    has_non_string = True
                    break
                    
            if has_non_string:
                # Convert to string type before applying string operations
                try:
                    df_result[col] = df_result[col].astype(str)
                except Exception as e:
                    log_message(f"  - Warning: Could not convert column '{col}' to string: {str(e)}", "WARNING")
                    continue  # Skip this column
            
            try:
                # Replace any non-breaking spaces with regular spaces
                unusual_count = df_result[col].str.contains('\xa0', na=False).sum()
                if unusual_count > 0:
                    log_message(f"  - Replacing non-breaking spaces in {unusual_count} rows of column '{col}'")
                    df_result[col] = df_result[col].str.replace('\xa0', ' ', regex=False)
                    
                # Remove leading/trailing spaces
                leading_trailing_count = (df_result[col].str.len() != df_result[col].str.strip().str.len()).sum()
                if leading_trailing_count > 0:
                    log_message(f"  - Removing leading/trailing whitespace in {leading_trailing_count} rows of column '{col}'")
                    df_result[col] = df_result[col].str.strip()
            except Exception as e:
                log_message(f"  - Warning: String operation failed on column '{col}': {str(e)}", "WARNING")
    
    return df_result

def find_latest_file(pattern, directory=None):
    """
    Find the most recent file matching the given pattern.
    
    Args:
        pattern: Glob pattern to match files
        directory: Directory to search in (optional, uses pattern as is if not provided)
        
    Returns:
        Path to the latest file or None if no files match
    """
    try:
        if directory:
            # If directory is provided, join it with the pattern
            search_pattern = os.path.join(directory, pattern)
        else:
            # Otherwise, use the pattern as is
            search_pattern = pattern
            
        # Get all matching files
        matching_files = glob.glob(search_pattern)
        
        if not matching_files:
            log_message(f"No files found matching pattern: {search_pattern}", "WARNING")
            return None
        
        # Find the most recent file by modification time
        latest_file = max(matching_files, key=os.path.getmtime)
        
        # Get modification time for logging
        mod_time = os.path.getmtime(latest_file)
        mod_time_str = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
        
        log_message(f"Found latest file: {latest_file} (Modified: {mod_time_str})")
        return latest_file
        
    except Exception as e:
        log_error(e, f"Error finding latest file for pattern {pattern}")
        return None

def format_field_info(field_name, field_descriptions=None):
    """
    Format field name with description if available.
    
    Args:
        field_name: Name of the field
        field_descriptions: Optional dictionary of field descriptions
        
    Returns:
        Formatted field info string
    """
    if not field_name or pd.isna(field_name) or field_name == "":
        return "unknown field"
        
    # Clean up field name
    field_name = str(field_name).strip()
    
    if not field_descriptions:
        return field_name
        
    # Look up description - try uppercase version first
    description = field_descriptions.get(field_name.upper(), "")
    
    # If no description found, try as-is
    if not description:
        description = field_descriptions.get(field_name, "")
    
    # If description found, format it
    if description:
        # Extract just the first part of the description (before any dash)
        short_desc = description.split(" - ")[0]
        return f"{field_name} ({short_desc})"
    
    return field_name

def format_tcode_info(tcode, common_descriptions=None, sensitive_descriptions=None):
    """
    Format transaction code with description if available.
    
    Args:
        tcode: Transaction code
        common_descriptions: Optional dictionary of common tcode descriptions
        sensitive_descriptions: Optional dictionary of sensitive tcode descriptions
        
    Returns:
        Formatted tcode info string
    """
    if not tcode or pd.isna(tcode) or tcode == "":
        return "unknown"
        
    # Clean up tcode
    tcode = str(tcode).strip()
    
    # If no descriptions provided, just return tcode
    if not common_descriptions and not sensitive_descriptions:
        return tcode
        
    # Look for description - first in sensitive, then in common
    description = ""
    if sensitive_descriptions:
        description = sensitive_descriptions.get(tcode.upper(), "")
        
    if not description and common_descriptions:
        description = common_descriptions.get(tcode.upper(), "")
    
    # If description found, format it
    if description:
        # Extract just the first part of the description (before any dash)
        short_desc = description.split(" - ")[0]
        return f"{tcode} ({short_desc})"
    
    return tcode

def format_table_info(table, common_descriptions=None, sensitive_descriptions=None):
    """
    Format table name with description if available.
    
    Args:
        table: Table name
        common_descriptions: Optional dictionary of common table descriptions
        sensitive_descriptions: Optional dictionary of sensitive table descriptions
        
    Returns:
        Formatted table info string
    """
    if not table or pd.isna(table) or table == "":
        return "unknown table"
        
    # Clean up table name
    table = str(table).strip()
    
    # If no descriptions provided, just return table name
    if not common_descriptions and not sensitive_descriptions:
        return table
        
    # Look for description - first in sensitive, then in common
    description = ""
    if sensitive_descriptions:
        description = sensitive_descriptions.get(table.upper(), "")
        
    if not description and common_descriptions:
        description = common_descriptions.get(table.upper(), "")
    
    # If description found, format it
    if description:
        # Extract just the first part of the description (before any dash)
        short_desc = description.split(" - ")[0]
        return f"{table} ({short_desc})"
    
    return table

def format_event_code_info(event_code, event_descriptions=None):
    """
    Format SAP event code with description if available.
    
    Args:
        event_code: SAP event code
        event_descriptions: Optional dictionary of event code descriptions
        
    Returns:
        Formatted event code info string
    """
    if not event_code or pd.isna(event_code) or event_code == "":
        return "unknown event"
        
    # Clean up event code
    event_code = str(event_code).strip().upper()
    
    # If no descriptions provided, just return event code
    if not event_descriptions:
        return event_code
        
    # Look for description
    description = event_descriptions.get(event_code, "")
    
    # If description found, format it
    if description:
        # Extract just the first part of the description (before any dash)
        short_desc = description.split(" - ")[0] if " - " in description else description
        return f"{event_code} ({short_desc})"
    
    return event_code

def standardize_column_values(df, column, mapping, default=""):
    """
    Standardize values in a column based on a mapping dictionary.
    
    Args:
        df: DataFrame to modify
        column: Column name to standardize
        mapping: Dictionary mapping {original_value: standardized_value}
        default: Default value for unmapped entries
        
    Returns:
        DataFrame with standardized column values
    """
    if column not in df.columns:
        return df
        
    df_copy = df.copy()
    
    # Apply mapping with case-insensitive lookup
    df_copy[column] = df_copy[column].apply(
        lambda x: mapping.get(str(x).strip().upper(), default) if pd.notna(x) else default
    )
    
    return df_copy
