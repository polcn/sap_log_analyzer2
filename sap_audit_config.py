#!/usr/bin/env python3
"""
SAP Audit Tool - Configuration Module

This module centralizes all configuration parameters for the SAP Audit Tool.
It provides:
1. File paths and directory locations
2. Column name mappings
3. Default settings for data processing
4. Documentation of configuration parameters

This centralized approach makes it easier to:
- Maintain consistent settings across all modules
- Document configuration parameters in one place
- Make changes to settings without modifying multiple files
- Ensure new team members can quickly understand configuration

USAGE:
  from sap_audit_config import (
      PATHS,         # Directory and file paths
      COLUMNS,       # Column name mappings for different data sources
      SETTINGS,      # Processing settings and thresholds
      PATTERNS,      # File name patterns for data source files
      VERSION        # Current version of the tool
  )
"""

import os
import sys
from datetime import datetime

# =========================================================================
# VERSION INFORMATION
# =========================================================================
VERSION = "4.5.0"  # Updated with Configuration Module (May 2025)
VERSION_INFO = {
    "major": 4,
    "minor": 5,
    "patch": 0,
    "release_date": "May 2025",
    "features": [
        "Centralized configuration",
        "Enhanced SysAid integration",
        "Improved error handling",
        "Better logging and reporting"
    ]
}

# =========================================================================
# DIRECTORY AND FILE PATHS
# =========================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

PATHS = {
    "script_dir": SCRIPT_DIR,
    "input_dir": os.path.join(SCRIPT_DIR, "input"),
    "output_dir": os.path.join(SCRIPT_DIR, "output"),
    "cache_dir": os.path.join(SCRIPT_DIR, "cache"),
    
    # Input files (processed by data prep)
    "sm20_input": os.path.join(SCRIPT_DIR, "input", "SM20.csv"),
    "cdhdr_input": os.path.join(SCRIPT_DIR, "input", "CDHDR.csv"),
    "cdpos_input": os.path.join(SCRIPT_DIR, "input", "CDPOS.csv"),
    "sysaid_input": os.path.join(SCRIPT_DIR, "input", "SysAid.xlsx"),
    
    # Reference data files for analysis enhancement
    "tcodes_reference": os.path.join(SCRIPT_DIR, "input", "TCodes.csv"),
    "tables_reference": os.path.join(SCRIPT_DIR, "input", "Tables.csv"),
    "events_reference": os.path.join(SCRIPT_DIR, "input", "Events.csv"),
    "high_risk_tcodes": os.path.join(SCRIPT_DIR, "input", "HighRiskTCodes.csv"),
    "high_risk_tables": os.path.join(SCRIPT_DIR, "input", "HighRiskTables.csv"),
    
    # Output files
    "session_timeline": os.path.join(SCRIPT_DIR, "SAP_Session_Timeline.xlsx"),
    "audit_report": os.path.join(SCRIPT_DIR, "output", "SAP_Audit_Report.xlsx"),
    
    # Cache files
    "sysaid_session_cache": os.path.join(SCRIPT_DIR, "cache", "sysaid_session_map.json"),
    "record_counts_file": os.path.join(SCRIPT_DIR, "cache", "record_counts.json")
}

# Create necessary directories
for dir_path in [PATHS["input_dir"], PATHS["output_dir"], PATHS["cache_dir"]]:
    os.makedirs(dir_path, exist_ok=True)

# =========================================================================
# INPUT FILE PATTERNS
# =========================================================================
PATTERNS = {
    "sm20": os.path.join(PATHS["input_dir"], "*_sm20_*.xlsx"),
    "cdhdr": os.path.join(PATHS["input_dir"], "*_cdhdr_*.xlsx"),
    "cdpos": os.path.join(PATHS["input_dir"], "*_cdpos_*.xlsx"),
    "sysaid": os.path.join(PATHS["input_dir"], "*sysaid*.xlsx")
}

# =========================================================================
# COLUMN MAPPINGS
# =========================================================================
COLUMNS = {
    # SM20 Security Audit Log columns (UPPERCASE)
    "sm20": {
        "user": "USER",
        "date": "DATE",
        "time": "TIME",
        "event": "EVENT",
        "tcode": "SOURCE TA",
        "abap_source": "ABAP SOURCE",
        "message": "AUDIT LOG MSG. TEXT",
        "note": "NOTE",
        "sysaid": "SYSAID#",
        # Debugging fields
        "var_first": "FIRST VARIABLE VALUE FOR EVENT",
        "var_2": "VARIABLE 2",
        "var_3": "VARIABLE 3",
        "var_data": "VARIABLE DATA FOR MESSAGE"
    },
    
    # CDHDR Change Document Header columns (UPPERCASE)
    "cdhdr": {
        "user": "USER",
        "date": "DATE",
        "time": "TIME",
        "tcode": "TCODE",
        "change_number": "DOC.NUMBER",
        "object": "OBJECT",
        "object_id": "OBJECT VALUE",
        "change_flag": "CHANGE FLAG FOR APPLICATION OBJECT",
        "sysaid": "SYSAID#"
    },
    
    # CDPOS Change Document Item columns (UPPERCASE)
    "cdpos": {
        "change_number": "DOC.NUMBER",
        "table_name": "TABLE NAME",
        "table_key": "TABLE KEY",
        "field_name": "FIELD NAME",
        "change_indicator": "CHANGE INDICATOR",
        "text_flag": "TEXT FLAG",
        "value_new": "NEW VALUE",
        "value_old": "OLD VALUE"
    },
    
    # Session Timeline columns (standardized names)
    "session": {
        "id": "Session ID", 
        "id_with_date": "Session ID with Date",
        "user": "User",
        "datetime": "Datetime",
        "source": "Source",
        "tcode": "TCode",
        "table": "Table",
        "field": "Field",
        "change_indicator": "Change_Indicator",
        "old_value": "Old_Value",
        "new_value": "New_Value",
        "description": "Description",
        "object": "Object",
        "object_id": "Object_ID",
        "doc_number": "Doc_Number",
        "sysaid": "SYSAID #"
    }
}

# =========================================================================
# SYSAID MAPPING OPTIONS
# =========================================================================
SYSAID = {
    # Common column names for SysAid ticket numbers in source data
    "column_options": [
        'SYSAID#', 'SYSAID #', 'SysAid', 'Ticket#', 'Ticket', 
        'Change_Request', 'SR', 'CR', 'SR #', 'CR #'
    ],
    
    # Output column name for standardized SysAid references
    "output_column": "SYSAID #",
    
    # Field mappings for SysAid ticket data
    "field_mappings": {
        "ticket": "Ticket",
        "title": "Title",
        "description": "Description",
        "notes": "Notes",
        "request_user": "Request user",
        "process_manager": "Process manager",
        "request_time": "Request time"
    }
}

# =========================================================================
# RISK ASSESSMENT CONFIGURATION
# =========================================================================
RISK = {
    # Risk level definitions
    "levels": {
        "critical": "Critical",
        "high": "High", 
        "medium": "Medium",
        "low": "Low"
    },
    
    # SAP native risk levels
    "sap_levels": {
        "critical": "Critical",
        "important": "Important", 
        "non_critical": "Non-Critical"
    },
    
    # Column names for risk assessment
    "column_names": {
        "risk_level": "risk_level",
        "sap_risk_level": "sap_risk_level", 
        "risk_description": "risk_description", 
        "activity_type": "activity_type"
    }
}

# =========================================================================
# GENERAL SETTINGS
# =========================================================================
SETTINGS = {
    # Excluded fields (will be removed during processing)
    "exclude_fields": ['COMMENTS'],
    
    # Date/time format for output
    "datetime_format": '%Y-%m-%d %H:%M:%S',
    
    # File encoding for input/output
    "encoding": "utf-8-sig",
    
    # Debug mode for verbose logging
    "debug": False,
    
    # Record count validation thresholds
    "count_validation": {
        "error_threshold": 0.1,    # Error if more than 10% records lost
        "warning_threshold": 0.01  # Warning if more than 1% records lost
    },
    
    # Column renaming behavior
    "column_renaming": {
        "case_sensitive": False,   # Ignore case when matching columns
        "fuzzy_matching": True     # Allow partial matches for column names
    }
}

# =========================================================================
# REPORTING CONFIGURATION
# =========================================================================
REPORTING = {
    # Required columns for validation
    "required_columns": ["Session ID", "User", "Datetime", "Source"],
    
    # Column order preferences for reporting
    "column_order": [
        "Session ID", "Session ID with Date", "User", "Datetime", "Source", 
        "TCode", "TCode_Description", "Event", "Event_Description", "risk_level", "SYSAID #", 
        "Table_Maintenance", "High_Risk_TCode", "Change_Activity", "Transport_Related_Event",
        "Debugging_Related_Event", "Benign_Activity", "Observations", "Questions",
        "Response", "Conclusion", "Table", "Table_Description", "Field", "Change_Indicator", 
        "Old_Value", "New_Value", "Description", "Object", "Object_ID", 
        "risk_description", "risk_factors"
    ],
    
    # Column formatters for Excel output
    "column_formats": {
        "Datetime": "yyyy-mm-dd hh:mm:ss",
        "User": {"bold": True},
        "Session ID": {"italic": True},
        "risk_level": {
            "Critical": {"bg_color": "#7030A0", "font_color": "#FFFFFF"},
            "High": {"bg_color": "#FFC7CE", "font_color": "#000000"},
            "Medium": {"bg_color": "#FFEB9C", "font_color": "#000000"},
            "Low": {"bg_color": "#C6EFCE", "font_color": "#000000"}
        }
    },
    
    # Output template settings
    "template": {
        "title": "SAP Audit Report",
        "include_summary": True,
        "include_charts": True,
        "include_legends": True
    },
    
    # Column source mappings for color coding
    "column_source_mappings": {
        # Additional mappings beyond the defaults
        "Event": "SM20",
        "Event_Description": "Generated",
        "TCode_Description": "Generated",
        "Table_Description": "Generated",
        "Transaction": "SM20",
        "Description": "SM20",
        "Change Type": "CDHDR",
        "Change Time": "CDHDR"
    },
    
    # Header colors for new analysis columns
    "header_colors": {
        "SYSAID #": "#CCFFCC",  # Light green (Eviden)
        "Response": "#CCFFCC",  # Light green (Eviden)
        "Table_Maintenance": "#FFCC99",  # Peach
        "High_Risk_TCode": "#FFCC99",  # Peach
        "Change_Activity": "#FFCC99",  # Peach
        "Transport_Related_Event": "#FFCC99",  # Peach
        "Debugging_Related_Event": "#FFCC99",  # Peach
        "Benign_Activity": "#FFCC99",  # Peach
        "Observations": "#FFCC99",  # Peach
        "Questions": "#FFCC99",  # Peach
        "Conclusion": "#FFCC99",  # Peach
        "TCode_Description": "#D9D2E9",  # Light Purple (descriptive)
        "Event_Description": "#D9D2E9",  # Light Purple (descriptive)
        "Table_Description": "#D9D2E9"   # Light Purple (descriptive)
    }
}

# =========================================================================
# MAIN CONFIGURATION
# =========================================================================
# This combined configuration is used by the AuditController
CONFIG = {
    # Default output format (excel or csv)
    "output_format": "excel",
    
    # Default SysAid data source strategy (file or api)
    "sysaid_source": "file",
    
    # Enable/disable SysAid integration
    "enable_sysaid": False,
    
    # Default path overrides (None means use paths from PATHS)
    "output_path": None,
    
    # Performance settings
    "caching_enabled": True,
    "parallel_processing": False,
    
    # Risk assessment settings
    "risk_threshold": {
        "critical": 90,
        "high": 70,
        "medium": 40,
        "low": 10
    }
}

# =========================================================================
# HELPER FUNCTIONS
# =========================================================================
def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def get_sysaid_column(df):
    """
    Find the best column to use for SysAid ticket numbers.
    Handles different naming conventions across data sources.
    
    Args:
        df: DataFrame to search for SysAid columns
        
    Returns:
        Column name to use for SysAid tickets, or None if not found
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

def print_config_summary():
    """Print a summary of the current configuration."""
    print("\n=== SAP Audit Tool Configuration Summary ===")
    print(f"Version: {VERSION}")
    print(f"Script Directory: {SCRIPT_DIR}")
    print(f"Input Directory: {PATHS['input_dir']}")
    print(f"Output Directory: {PATHS['output_dir']}")
    print(f"Session Timeline: {PATHS['session_timeline']}")
    print(f"Audit Report: {PATHS['audit_report']}")
    print(f"Debug Mode: {SETTINGS['debug']}")
    print("===========================================\n")

# Call this function when the module is run directly
if __name__ == "__main__":
    print_config_summary()
