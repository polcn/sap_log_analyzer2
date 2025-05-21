#!/usr/bin/env python3
"""
SAP Audit Tool - Risk Assessment Functions (Fixed)

This module contains improved risk assessment functions with detailed descriptions
for the SAP Audit Tool, with fixes for pattern matching issues.
"""

import os
import re
from datetime import datetime
import pandas as pd

# Import all functions from the original module except the ones we're fixing
from sap_audit_tool_risk_assessment_enhanced import (
    log_message, get_sensitive_tables, get_sensitive_table_descriptions,
    get_sensitive_tcodes, get_sensitive_tcode_descriptions,
    classify_activity_type,
    # We'll redefine these:
    # get_critical_field_patterns, get_critical_field_pattern_descriptions
)

# Session Timeline columns (from SAP Log Session Merger)
SESSION_TABLE_COL = 'Table'
SESSION_TCODE_COL = 'TCode'
SESSION_FIELD_COL = 'Field'
SESSION_CHANGE_IND_COL = 'Change_Indicator'

def get_critical_field_patterns():
    """Return patterns for critical fields that should be monitored closely.
    
    FIXED: Added word boundaries to patterns to avoid false matches.
    """
    return {
        # Authentication and authorization fields
        r"(?i)\bPASS(WORD)?\b": "Password field",
        r"(?i)\bAUTH(ORIZATION)?\b": "Authorization field",
        r"(?i)\bROLE\b": "Role assignment field",
        r"(?i)\bPERM(ISSION)?\b": "Permission field",
        r"(?i)\bACCESS\b": "Access control field",
        r"(?i)\bKEY\b": "Security key field",
        r"(?i)\bCRED(ENTIAL)?\b": "Credential field",
        
        # Financial fields
        r"(?i)\bAMOUNT\b": "Financial amount field",
        r"(?i)\bCURR(ENCY)?\b": "Currency field",
        r"(?i)\bBANK\b": "Banking information field",
        r"(?i)\bACCOUNT\b": "Account field",
        r"(?i)\bPAYMENT\b": "Payment field",
        
        # Master data fields
        r"(?i)\bVENDOR\b": "Vendor master data field",
        r"(?i)\bCUSTOMER\b": "Customer master data field",
        r"(?i)\bEMPLOYEE\b": "Employee data field",
        
        # System configuration
        r"(?i)\bCONFIG\b": "Configuration field",
        r"(?i)\bSETTING\b": "System setting field",
        r"(?i)\bPARAM(ETER)?\b": "Parameter field"
    }

def get_critical_field_pattern_descriptions():
    """Return detailed descriptions for critical field patterns.
    
    FIXED: Added word boundaries to patterns to avoid false matches.
    """
    return {
        # Authentication and authorization fields
        r"(?i)\bPASS(WORD)?\b": "Password/credential modification - Security sensitive change affecting user authentication",
        r"(?i)\bAUTH(ORIZATION)?\b": "Authorization configuration - Security permission change affecting system access control",
        r"(?i)\bROLE\b": "Role configuration - Security access control change affecting user permissions scope",
        r"(?i)\bPERM(ISSION)?\b": "Permission settings - Access control modification affecting security boundaries",
        r"(?i)\bACCESS\b": "Access control field - Field controlling system or resource availability",
        r"(?i)\bKEY\b": "Security key/token - Infrastructure change affecting encryption or authentication",
        r"(?i)\bCRED(ENTIAL)?\b": "Credential field - Authentication data that may grant system access",
        
        # Financial fields
        r"(?i)\bAMOUNT\b": "Financial amount field - Monetary value change affecting financial transactions",
        r"(?i)\bCURR(ENCY)?\b": "Currency field - Financial data type affecting monetary calculations",
        r"(?i)\bBANK\b": "Banking details - Payment routing information change affecting transactions",
        r"(?i)\bACCOUNT\b": "Account field - Financial or user account record modification",
        r"(?i)\bPAYMENT\b": "Payment field - Financial transaction data affecting money movement",
        
        # Master data fields
        r"(?i)\bVENDOR\b": "Vendor master data field - Supplier information affecting procurement processes",
        r"(?i)\bCUSTOMER\b": "Customer master data field - Client information affecting sales processes",
        r"(?i)\bEMPLOYEE\b": "Employee data field - Personnel information affecting HR processes",
        
        # System configuration
        r"(?i)\bCONFIG\b": "Configuration field - System setting affecting overall system behavior",
        r"(?i)\bSETTING\b": "System setting field - Parameter controlling system functionality",
        r"(?i)\bPARAM(ETER)?\b": "Parameter field - System configuration option affecting behavior"
    }

def assess_risk_session_enhanced(session_data):
    """
    Enhanced risk assessment function with more detailed descriptions.
    FIXED: Improved pattern matching to avoid false positives.
    Returns a DataFrame with comprehensive risk assessments.
    """
    log_message("Assessing risk with fixed pattern matching...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = session_data.copy()
        
        # Get reference data for risk assessment
        sensitive_tables = get_sensitive_tables()
        sensitive_tcodes = get_sensitive_tcodes()
        
        # Get enhanced descriptions
        table_descriptions = get_sensitive_table_descriptions()
        tcode_descriptions = get_sensitive_tcode_descriptions()
        field_descriptions = get_critical_field_pattern_descriptions()
        field_patterns = get_critical_field_patterns()
        
        # Initialize risk columns
        risk_df['risk_level'] = 'Low'
        risk_df['risk_factors'] = ''
        
        # Add activity type classification
        risk_df['activity_type'] = risk_df.apply(classify_activity_type, axis=1)
        
        # Assess risk based on sensitive tables
        if SESSION_TABLE_COL in risk_df.columns:
            for table in sensitive_tables:
                table_mask = risk_df[SESSION_TABLE_COL] == table
                if any(table_mask):
                    risk_df.loc[table_mask, 'risk_level'] = 'High'
                    description = table_descriptions.get(table, f"Sensitive table '{table}' - Contains critical system data")
                    risk_df.loc[table_mask, 'risk_factors'] = description
        
        # Assess risk based on sensitive transaction codes
        if SESSION_TCODE_COL in risk_df.columns:
            for tcode in sensitive_tcodes:
                tcode_mask = risk_df[SESSION_TCODE_COL] == tcode
                if any(tcode_mask):
                    risk_df.loc[tcode_mask, 'risk_level'] = 'High'
                    description = tcode_descriptions.get(tcode, f"Sensitive transaction '{tcode}' - Privileged system function")
                    empty_factors_mask = tcode_mask & (risk_df['risk_factors'] == '')
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = description
        
        # Assess risk based on critical field patterns with enhanced descriptions and FIXED patterns
        if SESSION_FIELD_COL in risk_df.columns:
            # Handle null values properly
            adjusted_fields = risk_df[SESSION_FIELD_COL].fillna('')
            
            for pattern, basic_desc in field_patterns.items():
                # Use word-bounded patterns to avoid false matches
                mask = adjusted_fields.str.contains(pattern, regex=True, na=False)
                if any(mask):
                    risk_df.loc[mask, 'risk_level'] = 'High'
                    description = field_descriptions.get(pattern, f"Critical field ({basic_desc}) - Contains sensitive data")
                    empty_factors_mask = mask & (risk_df['risk_factors'] == '')
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = description
        
        # Assess risk based on display_but_changed flag
        if 'display_but_changed' in risk_df.columns:
            mask = risk_df['display_but_changed']
            if any(mask):
                risk_df.loc[mask, 'risk_level'] = 'High'
                empty_factors_mask = mask & (risk_df['risk_factors'] == '')
                risk_df.loc[empty_factors_mask, 'risk_factors'] = "Display transaction with changes - Activity logged as view-only but includes data modifications"
        
        # Assess risk based on change indicator
        if SESSION_CHANGE_IND_COL in risk_df.columns:
            # Insert (I) operations
            insert_mask = risk_df[SESSION_CHANGE_IND_COL] == 'I'
            if any(insert_mask):
                risk_df.loc[insert_mask, 'risk_level'] = 'High'
                empty_factors_mask = insert_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Insert operation - New record created in {x[SESSION_TABLE_COL] if pd.notna(x[SESSION_TABLE_COL]) else 'unknown'} table", axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = "Insert operation - New record created"
            
            # Delete (D) operations
            delete_mask = risk_df[SESSION_CHANGE_IND_COL] == 'D'
            if any(delete_mask):
                risk_df.loc[delete_mask, 'risk_level'] = 'High'
                empty_factors_mask = delete_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Delete operation - Record removed from {x[SESSION_TABLE_COL] if pd.notna(x[SESSION_TABLE_COL]) else 'unknown'} table", axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = "Delete operation - Record removed"
            
            # Updates (U) are medium risk by default
            update_mask = (risk_df['risk_level'] == 'Low') & (risk_df[SESSION_CHANGE_IND_COL] == 'U')
            if any(update_mask):
                risk_df.loc[update_mask, 'risk_level'] = 'Medium'
                empty_factors_mask = update_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Update operation - Existing record modified in {x[SESSION_TABLE_COL] if pd.notna(x[SESSION_TABLE_COL]) else 'unknown'} table", axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = "Update operation - Existing record modified"
        
        # Count risk levels
        high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
        medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
        low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
        
        log_message(f"Fixed risk assessment complete. High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
        
        return risk_df
    
    except Exception as e:
        log_message(f"Error during risk assessment: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return session_data
