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
      VERSION,       # Current version of the tool
      load_config_file  # Function to load configuration from external file
  )
"""

import os
import sys
import json
from datetime import datetime

# Try to import optional dependencies
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Environment variable prefix
ENV_PREFIX = "SAP_AUDIT_"

# Try to load .env file if dotenv is installed
try:
    from dotenv import load_dotenv
    # Load from .env file if it exists
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)
        print(f"Loaded environment variables from {env_path}")
except ImportError:
    # Optional dependency, just skip if not installed
    pass

def get_env_value(env_var, default_value):
    """Get value from environment variable or use default."""
    env_name = f"{ENV_PREFIX}{env_var}"
    env_value = os.environ.get(env_name)
    return env_value if env_value else default_value

# =========================================================================
# VERSION INFORMATION
# =========================================================================
VERSION = "4.6.0"  # Updated with Environment Variable Support (May 2025)
VERSION_INFO = {
    "major": 4,
    "minor": 6,
    "patch": 0,
    "release_date": "May 2025",
    "features": [
        "Centralized configuration",
        "Environment variable support",
        "External config file loading",
        "Enhanced SysAid integration",
        "Improved error handling",
        "Better logging and reporting"
    ]
}

# =========================================================================
# DIRECTORY AND FILE PATHS
# =========================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Define path getter with environment variable support
def get_env_path(env_var, default_path):
    """Get path from environment variable or use default."""
    env_value = get_env_value(env_var, None)
    if env_value:
        # Handle relative paths (relative to script directory)
        if not os.path.isabs(env_value):
            return os.path.join(SCRIPT_DIR, env_value)
        return env_value
    return default_path

# Path configuration with environment variable support
PATHS = {
    "script_dir": SCRIPT_DIR,
    "input_dir": get_env_path("INPUT_DIR", os.path.join(SCRIPT_DIR, "input")),
    "output_dir": get_env_path("OUTPUT_DIR", os.path.join(SCRIPT_DIR, "output")),
    "cache_dir": get_env_path("CACHE_DIR", os.path.join(SCRIPT_DIR, "cache")),
    
    # Input files (processed by data prep)
    "sm20_input": get_env_path("SM20_INPUT", os.path.join(SCRIPT_DIR, "input", "SM20.csv")),
    "cdhdr_input": get_env_path("CDHDR_INPUT", os.path.join(SCRIPT_DIR, "input", "CDHDR.csv")),
    "cdpos_input": get_env_path("CDPOS_INPUT", os.path.join(SCRIPT_DIR, "input", "CDPOS.csv")),
    "sysaid_input": get_env_path("SYSAID_INPUT", os.path.join(SCRIPT_DIR, "input", "SysAid.xlsx")),
    
    # Reference data files for analysis enhancement
    "tcodes_reference": get_env_path("TCODES_REF", os.path.join(SCRIPT_DIR, "input", "TCodes.csv")),
    "tables_reference": get_env_path("TABLES_REF", os.path.join(SCRIPT_DIR, "input", "Tables.csv")),
    "events_reference": get_env_path("EVENTS_REF", os.path.join(SCRIPT_DIR, "input", "Events.csv")),
    "high_risk_tcodes": get_env_path("HIGH_RISK_TCODES", os.path.join(SCRIPT_DIR, "input", "HighRiskTCodes.csv")),
    "high_risk_tables": get_env_path("HIGH_RISK_TABLES", os.path.join(SCRIPT_DIR, "input", "HighRiskTables.csv")),
    
    # Output files
    "session_timeline": get_env_path("SESSION_TIMELINE", os.path.join(SCRIPT_DIR, "SAP_Session_Timeline.xlsx")),
    "audit_report": get_env_path("AUDIT_REPORT", os.path.join(SCRIPT_DIR, "output", "SAP_Audit_Report.xlsx")),
    
    # Cache files
    "sysaid_session_cache": get_env_path("SYSAID_CACHE", os.path.join(SCRIPT_DIR, "cache", "sysaid_session_map.json")),
    "record_counts_file": get_env_path("RECORD_COUNTS", os.path.join(SCRIPT_DIR, "cache", "record_counts.json"))
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
    "datetime_format": get_env_value("DATETIME_FORMAT", '%Y-%m-%d %H:%M:%S'),
    
    # File encoding for input/output
    "encoding": get_env_value("ENCODING", "utf-8-sig"),
    
    # Debug mode for verbose logging
    "debug": get_env_value("DEBUG", "false").lower() in ["true", "1", "yes", "y"],
    
    # Record count validation thresholds
    "count_validation": {
        "error_threshold": float(get_env_value("ERROR_THRESHOLD", "0.1")),    # Error if more than 10% records lost
        "warning_threshold": float(get_env_value("WARNING_THRESHOLD", "0.01"))  # Warning if more than 1% records lost
    },
    
    # Column renaming behavior
    "column_renaming": {
        "case_sensitive": get_env_value("CASE_SENSITIVE", "false").lower() in ["true", "1", "yes", "y"],
        "fuzzy_matching": get_env_value("FUZZY_MATCHING", "true").lower() in ["true", "1", "yes", "y"]
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
    "output_format": get_env_value("OUTPUT_FORMAT", "excel"),
    
    # Default SysAid data source strategy (file or api)
    "sysaid_source": get_env_value("SYSAID_SOURCE", "file"),
    
    # Enable/disable SysAid integration
    "enable_sysaid": get_env_value("ENABLE_SYSAID", "false").lower() in ["true", "1", "yes", "y"],
    
    # Default path overrides (None means use paths from PATHS)
    "output_path": get_env_value("OUTPUT_PATH", None),
    
    # Performance settings
    "caching_enabled": get_env_value("CACHING_ENABLED", "true").lower() in ["true", "1", "yes", "y"],
    "parallel_processing": get_env_value("PARALLEL_PROCESSING", "false").lower() in ["true", "1", "yes", "y"],
    
    # Risk assessment settings
    "risk_threshold": {
        "critical": int(get_env_value("RISK_THRESHOLD_CRITICAL", "90")),
        "high": int(get_env_value("RISK_THRESHOLD_HIGH", "70")),
        "medium": int(get_env_value("RISK_THRESHOLD_MEDIUM", "40")),
        "low": int(get_env_value("RISK_THRESHOLD_LOW", "10"))
    }
}

# =========================================================================
# CONFIGURATION FILE LOADING
# =========================================================================
def load_config_file(config_file_path):
    """
    Load configuration from an external file (YAML or JSON).
    Overrides default settings with values from the file.
    
    Args:
        config_file_path: Path to configuration file (YAML or JSON)
        
    Returns:
        True if config was loaded successfully, False otherwise
    """
    if not os.path.exists(config_file_path):
        log_message(f"Config file not found: {config_file_path}", "ERROR")
        return False
    
    try:
        # Determine file type by extension
        if config_file_path.lower().endswith('.yaml') or config_file_path.lower().endswith('.yml'):
            try:
                import yaml
                with open(config_file_path, 'r', encoding=SETTINGS['encoding']) as f:
                    config_data = yaml.safe_load(f)
            except ImportError:
                log_message("YAML module not found. Install with: pip install pyyaml", "ERROR")
                return False
        elif config_file_path.lower().endswith('.json'):
            with open(config_file_path, 'r', encoding=SETTINGS['encoding']) as f:
                config_data = json.load(f)
        else:
            log_message(f"Unsupported config file format: {config_file_path}", "ERROR")
            return False
        
        # Update configuration sections
        for section in config_data:
            section_upper = section.upper()
            if section_upper == "PATHS":
                for key, value in config_data[section].items():
                    PATHS[key] = value
            elif section_upper == "SETTINGS":
                for key, value in config_data[section].items():
                    if isinstance(value, dict) and key in SETTINGS and isinstance(SETTINGS[key], dict):
                        # Merge nested dictionaries
                        SETTINGS[key].update(value)
                    else:
                        SETTINGS[key] = value
            elif section_upper == "CONFIG":
                for key, value in config_data[section].items():
                    if isinstance(value, dict) and key in CONFIG and isinstance(CONFIG[key], dict):
                        # Merge nested dictionaries
                        CONFIG[key].update(value)
                    else:
                        CONFIG[key] = value
        
        log_message(f"Loaded configuration from {config_file_path}", "INFO")
        return True
    
    except Exception as e:
        log_message(f"Error loading config file: {str(e)}", "ERROR")
        return False

# Check for config file specified by environment variable
config_file_env = get_env_value("CONFIG_FILE", None)
if config_file_env:
    load_config_file(config_file_env)

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
    
    # If --export-env flag is provided, generate a sample .env file
    if len(sys.argv) > 1 and sys.argv[1] == "--export-env":
        env_file_path = os.path.join(SCRIPT_DIR, '.env.sample')
        with open(env_file_path, 'w', encoding='utf-8') as f:
            f.write("# SAP Audit Tool Environment Variables\n")
            f.write("# Copy this file to .env and modify as needed\n\n")
            
            # Paths
            f.write("# Path Configuration\n")
            for key in PATHS:
                f.write(f"SAP_AUDIT_{key.upper()}={PATHS[key]}\n")
            
            # Settings
            f.write("\n# General Settings\n")
            f.write(f"SAP_AUDIT_DEBUG={str(SETTINGS['debug']).lower()}\n")
            f.write(f"SAP_AUDIT_ENCODING={SETTINGS['encoding']}\n")
            
            # Config
            f.write("\n# Application Configuration\n")
            f.write(f"SAP_AUDIT_OUTPUT_FORMAT={CONFIG['output_format']}\n")
            f.write(f"SAP_AUDIT_ENABLE_SYSAID={str(CONFIG['enable_sysaid']).lower()}\n")
            f.write(f"SAP_AUDIT_CACHING_ENABLED={str(CONFIG['caching_enabled']).lower()}\n")
            f.write(f"SAP_AUDIT_PARALLEL_PROCESSING={str(CONFIG['parallel_processing']).lower()}\n")
            
        print(f"Sample environment variables exported to {env_file_path}")
        
    # If --export-config flag is provided, generate a sample config file
    if len(sys.argv) > 1 and sys.argv[1] == "--export-config":
        try:
            import yaml
            have_yaml = True
        except ImportError:
            have_yaml = False
            
        sample_config = {
            "paths": {
                "input_dir": PATHS["input_dir"],
                "output_dir": PATHS["output_dir"],
                "cache_dir": PATHS["cache_dir"]
            },
            "settings": {
                "debug": SETTINGS["debug"],
                "encoding": SETTINGS["encoding"],
                "count_validation": SETTINGS["count_validation"]
            },
            "config": {
                "output_format": CONFIG["output_format"],
                "enable_sysaid": CONFIG["enable_sysaid"],
                "caching_enabled": CONFIG["caching_enabled"],
                "parallel_processing": CONFIG["parallel_processing"],
                "risk_threshold": CONFIG["risk_threshold"]
            }
        }
        
        # Save as JSON
        json_path = os.path.join(SCRIPT_DIR, 'config.sample.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(sample_config, f, indent=2)
        print(f"Sample JSON configuration exported to {json_path}")
        
        # Save as YAML if available
        if have_yaml:
            yaml_path = os.path.join(SCRIPT_DIR, 'config.sample.yaml')
            with open(yaml_path, 'w', encoding='utf-8') as f:
                yaml.dump(sample_config, f, default_flow_style=False)
            print(f"Sample YAML configuration exported to {yaml_path}")
