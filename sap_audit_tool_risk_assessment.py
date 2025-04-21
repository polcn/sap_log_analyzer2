#!/usr/bin/env python3
"""
SAP Audit Tool - Risk Assessment Functions

This module contains improved risk assessment functions with detailed descriptions
for the SAP Audit Tool, with fixes for pattern matching issues and exclusions
for commonly false-positive field names.

Note: This is now a thin wrapper around the modular risk assessment architecture.
"""

import os
import re
from datetime import datetime
import pandas as pd

# Import from modular architecture
from sap_audit_utils import log_message
from sap_audit_risk_core import assess_risk_session as core_assess_risk
from sap_audit_reference_data import (
    get_sensitive_tables, get_sensitive_table_descriptions,
    get_common_table_descriptions, get_sensitive_tcodes,
    get_sensitive_tcode_descriptions, get_common_tcode_descriptions,
    get_common_field_descriptions, get_critical_field_patterns,
    get_critical_field_pattern_descriptions
)
from sap_audit_detectors import (
    custom_field_risk_assessment, detect_debug_patterns,
    detect_debug_with_changes, classify_activity_type
)

# Session Timeline columns (from SAP Log Session Merger)
SESSION_TABLE_COL = 'Table'
SESSION_TCODE_COL = 'TCode'
SESSION_FIELD_COL = 'Field'
SESSION_CHANGE_IND_COL = 'Change_Indicator'

# For backward compatibility
def get_field_info(field_value, field_descriptions):
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

# For backward compatibility
def get_tcode_info(tcode, common_tcode_descriptions, sensitive_tcode_descriptions):
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

# For backward compatibility
def get_table_info(table, common_table_descriptions, sensitive_table_descriptions):
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

# Main risk assessment function - delegate to core function
def assess_risk_session(session_data):
    """
    Assess risk for a session timeline.
    Returns a DataFrame with risk assessments.
    
    Note: This function now delegates to the modular core function
    """
    log_message("Starting risk assessment...")
    
    try:
        # Delegate to the core modular implementation
        return core_assess_risk(session_data)
    
    except Exception as e:
        log_message(f"Error during risk assessment: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return session_data
