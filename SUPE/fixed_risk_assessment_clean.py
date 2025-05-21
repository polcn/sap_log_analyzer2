#!/usr/bin/env python3
"""
SAP Audit Tool - Risk Assessment Functions (Fixed Version)

This is a completely clean and fixed version of the risk assessment module.
"""

import os
import re
from datetime import datetime
import pandas as pd

# Session Timeline columns (from SAP Log Session Merger)
SESSION_TABLE_COL = 'Table'
SESSION_TCODE_COL = 'TCode'
SESSION_FIELD_COL = 'Field'
SESSION_CHANGE_IND_COL = 'Change_Indicator'

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

# Risk assessment dictionaries are imported from this module
from sap_audit_tool_risk_assessment import (
    get_sensitive_tables,
    get_sensitive_table_descriptions,
    get_common_table_descriptions,
    get_sensitive_tcodes,
    get_sensitive_tcode_descriptions,
    get_common_tcode_descriptions,
    get_common_field_descriptions
)

def get_critical_field_patterns():
    """Return patterns for critical fields that should be monitored closely."""
    patterns = {}
    
    # Authentication and authorization fields
    patterns[r"(?i)\bPASS(WORD)?\b"] = "Password field"
    patterns[r"(?i)\bAUTH(ORIZATION)?\b"] = "Authorization field"
    patterns[r"(?i)(?<![A-Za-z0-9_])ROLE(?![A-Za-z0-9_])"] = "Role assignment field"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    patterns[r"(?i)\bPERM(ISSION)?\b(?<!SPERM)"] = "Permission field"
    patterns[r"(?i)(?<![A-Za-z0-9_])ACCESS(?![A-Za-z0-9_])"] = "Access control field"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    patterns[r"(?i)\b(?!KEY$).*KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC).*\b"] = "Security key field"
    patterns[r"(?i)\bCRED(ENTIAL)?\b"] = "Credential field"
    
    # Financial fields
    patterns[r"(?i)(?<![A-Za-z0-9_])AMOUNT(?![A-Za-z0-9_])"] = "Financial amount field"
    patterns[r"(?i)\bCURR(ENCY)?\b"] = "Currency field" 
    patterns[r"(?i)(?<![A-Za-z0-9_])BANK(?![A-Za-z0-9_])"] = "Banking information field"
    patterns[r"(?i)(?<![A-Za-z0-9_])ACCOUNT(?![A-Za-z0-9_])"] = "Account field"
    patterns[r"(?i)(?<![A-Za-z0-9_])PAYMENT(?![A-Za-z0-9_])"] = "Payment field"
    
    # Master data fields
    patterns[r"(?i)(?<![A-Za-z0-9_])VENDOR(?![A-Za-z0-9_])"] = "Vendor master data field"
    patterns[r"(?i)(?<![A-Za-z0-9_])CUSTOMER(?![A-Za-z0-9_])"] = "Customer master data field"
    patterns[r"(?i)(?<![A-Za-z0-9_])EMPLOYEE(?![A-Za-z0-9_])"] = "Employee data field"
    
    # System configuration
    patterns[r"(?i)(?<![A-Za-z0-9_])CONFIG(?![A-Za-z0-9_])"] = "Configuration field"
    patterns[r"(?i)(?<![A-Za-z0-9_])SETTING(?![A-Za-z0-9_])"] = "System setting field"
    patterns[r"(?i)\bPARAM(ETER)?\b"] = "Parameter field"
    
    return patterns

def get_critical_field_pattern_descriptions():
    """Return detailed descriptions for critical field patterns."""
    descriptions = {}
    
    # Authentication and authorization fields
    descriptions[r"(?i)\bPASS(WORD)?\b"] = "Password/credential modification - Security sensitive change affecting user authentication"
    descriptions[r"(?i)\bAUTH(ORIZATION)?\b"] = "Authorization configuration - Security permission change affecting system access control"
    descriptions[r"(?i)(?<![A-Za-z0-9_])ROLE(?![A-Za-z0-9_])"] = "Role configuration - Security access control change affecting user permissions scope"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    descriptions[r"(?i)\bPERM(ISSION)?\b(?<!SPERM)"] = "Permission settings - Access control modification affecting security boundaries"
    descriptions[r"(?i)(?<![A-Za-z0-9_])ACCESS(?![A-Za-z0-9_])"] = "Access control field - Field controlling system or resource availability"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    descriptions[r"(?i)\b(?!KEY$).*KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC).*\b"] = "Security key/token - Infrastructure change affecting encryption or authentication"
    descriptions[r"(?i)\bCRED(ENTIAL)?\b"] = "Credential field - Authentication data that may grant system access"
    
    # Financial fields
    descriptions[r"(?i)(?<![A-Za-z0-9_])AMOUNT(?![A-Za-z0-9_])"] = "Financial amount field - Monetary value change affecting financial transactions"
    descriptions[r"(?i)\bCURR(ENCY)?\b"] = "Currency field - Financial data type affecting monetary calculations"
    descriptions[r"(?i)(?<![A-Za-z0-9_])BANK(?![A-Za-z0-9_])"] = "Banking details - Payment routing information change affecting transactions"
    descriptions[r"(?i)(?<![A-Za-z0-9_])ACCOUNT(?![A-Za-z0-9_])"] = "Account field - Financial or user account record modification"
    descriptions[r"(?i)(?<![A-Za-z0-9_])PAYMENT(?![A-Za-z0-9_])"] = "Payment field - Financial transaction data affecting money movement"
    
    # Master data fields
    descriptions[r"(?i)(?<![A-Za-z0-9_])VENDOR(?![A-Za-z0-9_])"] = "Vendor master data field - Supplier information affecting procurement processes"
    descriptions[r"(?i)(?<![A-Za-z0-9_])CUSTOMER(?![A-Za-z0-9_])"] = "Customer master data field - Client information affecting sales processes"
    descriptions[r"(?i)(?<![A-Za-z0-9_])EMPLOYEE(?![A-Za-z0-9_])"] = "Employee data field - Personnel information affecting HR processes"
    
    # System configuration
    descriptions[r"(?i)(?<![A-Za-z0-9_])CONFIG(?![A-Za-z0-9_])"] = "Configuration field - System setting affecting overall system behavior"
    descriptions[r"(?i)(?<![A-Za-z0-9_])SETTING(?![A-Za-z0-9_])"] = "System setting field - Parameter controlling system functionality"
    descriptions[r"(?i)\bPARAM(ETER)?\b"] = "Parameter field - System configuration option affecting behavior"
    
    return descriptions

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

def custom_field_risk_assessment(field_name):
    """
    Perform custom risk assessment for fields that need special handling.
    
    Args:
        field_name: The field name to assess
        
    Returns:
        Tuple of (is_high_risk, risk_description) or (False, None) if not high risk
    """
    # Strip whitespace and convert to uppercase for consistent comparison
    field = field_name.strip().upper() if isinstance(field_name, str) else ""
    
    # List of exact fields to exclude from any risk assessment
    exclude_fields = {"KEY", "SPERM", "SPERQ", "QUAN"}
    if field in exclude_fields:
        return False, None
    
    # Custom rules for specific field patterns
    if field.startswith("KEY_") or field.endswith("_KEY") or "SECUR" in field:
        return True, "Security key/token - Infrastructure change affecting encryption or authentication"
    if "PERM" in field and field != "SPERM" and field != "SPERQ":
        return True, "Permission settings - Access control modification affecting security boundaries"
        
    return False, None

def detect_debug_patterns(row):
    """
    Detect debugging and RFC patterns in SM20 logs.
    
    Args:
        row: DataFrame row containing potential debug data
        
    Returns:
        Tuple of (risk_level, risk_factors_list)
        Where risk_level can be 'Critical', 'High', 'Medium', 'Low', or None
        And risk_factors_list is a list of risk factor descriptions
    """
    risk_factors = []
    
    # Get values with fallbacks for missing fields
    var_2 = str(row.get('Variable_2', '')) if pd.notna(row.get('Variable_2', '')) else ''
    var_first = str(row.get('Variable_First', '')) if pd.notna(row.get('Variable_First', '')) else ''
    var_data = str(row.get('Variable_Data', '')) if pd.notna(row.get('Variable_Data', '')) else ''
    username = str(row.get('User', '')) if pd.notna(row.get('User', '')) else ''
    
    # Debug event detection (I!, D! flags)
    if 'I!' in var_2:
        risk_factors.append("Dynamic ABAP code execution detected (I!) - Internal/Insert operation that may bypass normal controls")
        return 'High', risk_factors
        
    if 'D!' in var_2:
        risk_factors.append("Debug session detected (D!) - User debugging program logic and potentially manipulating runtime variables")
        return 'High', risk_factors
    
    # RFC/Gateway detection (G! flag)
    if 'G!' in var_2:
        risk_factors.append("Gateway/RFC call detected (G!) - Remote function call or service interface access")
        return 'High', risk_factors
    
    # FireFighter detection combined with any suspicious activity
    if username.startswith('FF_') and (var_2 in ['I!', 'D!', 'G!'] or 'R3TR' in var_first):
        risk_factors.append(f"FireFighter account performing privileged action ({var_2}) - Elevated risk due to privileged access")
        return 'Critical', risk_factors
    
    # Service interface detection
    if 'R3TR IWSV' in var_first or 'R3TR IWSG' in var_first:
        risk_factors.append("Service interface access detected - OData or API gateway activity")
        return 'Medium', risk_factors
    
    # OData endpoint patterns
    if '/sap/opu/odata/' in var_data:
        risk_factors.append("OData endpoint access - API-based data access")
        return 'Medium', risk_factors
    
    return None, risk_factors

def detect_debug_with_changes(session_df):
    """
    Detect debugging activities correlated with data changes in the same session.
    
    Args:
        session_df: DataFrame containing session data
        
    Returns:
        Modified DataFrame with updated risk assessments
    """
    # Create a copy to avoid warning
    df = session_df.copy()
    
    # Group by session ID
    for session_id, session_group in df.groupby('Session ID with Date'):
        # Check for debug flags in Variable_2
        debug_events = session_group[session_group['Variable_2'].isin(['I!', 'D!', 'G!'])]
        
        # Check for change indicators
        change_events = session_group[session_group['Change_Indicator'].isin(['I', 'U', 'D'])]
        
        # If both debug events and changes exist in same session
        if not debug_events.empty and not change_events.empty:
            # Flag all debug events as Critical
            for idx in debug_events.index:
                df.loc[idx, 'risk_level'] = 'Critical'
                current_factors = df.loc[idx, 'risk_factors']
                new_factor = "Debugging activity with data changes in same session - High risk pattern indicating potential data manipulation"
                df.loc[idx, 'risk_factors'] = current_factors + "; " + new_factor if current_factors else new_factor
            
            # Flag all change events as High
            for idx in change_events.index:
                if df.loc[idx, 'risk_level'] != 'Critical':  # Don't downgrade Critical events
                    df.loc[idx, 'risk_level'] = 'High'
                current_factors = df.loc[idx, 'risk_factors']
                new_factor = "Data change during debug session - Suspicious pattern indicating potential targeted data manipulation"
                df.loc[idx, 'risk_factors'] = current_factors + "; " + new_factor if current_factors else new_factor
    
    return df

def classify_activity_type(row):
    """Classify the activity type based on the row data."""
    if pd.isna(row.get('TCode')) and pd.isna(row.get('Table')):
        return 'Unknown'
    
    # Check for display transactions
    description = str(row.get('Description', '')).upper()
    if 'DISPLAY' in description or 'VIEW' in description or 'SHOW' in description or 'LIST' in description:
        return 'View'
    
    # Check for change indicator
    change_ind = str(row.get('Change_Indicator', '')).strip().upper()
    if change_ind == 'I':
        return 'Create'
    elif change_ind == 'U':
        return 'Update'
    elif change_ind == 'D':
        return 'Delete'
    
    # Check for transaction code categories
    tcode = str(row.get('TCode', '')).strip().upper()
    if tcode.startswith('F') or tcode in ['FB50', 'FB01', 'FB02']:
        return 'Financial'
    elif tcode.startswith('S'):
        return 'System'
    elif tcode.startswith('MM'):
        return 'Material Management'
    elif tcode.startswith('VA'):
        return 'Sales'
    
    return 'Other'

def assess_risk_session(session_data):
    """
    Assess risk for a session timeline.
    Returns a DataFrame with risk assessments.
    
    Note: Data is assumed to be pre-cleaned by the data prep module,
    but minimal cleaning is still done for defensive programming.
    """
    log_message("Assessing risk with improved pattern matching...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = session_data.copy()
        
        # Minimal cleaning for defensive programming only
        # (in case data wasn't properly cleaned in the data prep step)
        for col in [SESSION_TABLE_COL, SESSION_TCODE_COL, SESSION_FIELD_COL, SESSION_CHANGE_IND_COL]:
            if col in risk_df.columns and risk_df[col].dtype == 'object':
                # Only clean if we see excessive whitespace
                if (risk_df[col].astype(str).str.strip() != risk_df[col]).any():
                    log_message(f"Note: Found whitespace in {col} column. Performing defensive cleaning.", "WARNING")
                    risk_df[col] = risk_df[col].astype(str).str.strip()
        
        # Get reference data for risk assessment
        sensitive_tables = get_sensitive_tables()
        sensitive_tcodes = get_sensitive_tcodes()
        
        # Get enhanced descriptions
        table_descriptions = get_sensitive_table_descriptions()
        tcode_descriptions = get_sensitive_tcode_descriptions()
        common_field_descriptions = get_common_field_descriptions()
        field_patterns = get_critical_field_patterns()
        field_descriptions = get_critical_field_pattern_descriptions()
        
        # Initialize risk columns
        risk_df['risk_level'] = 'Low'
        risk_df['risk_factors'] = ''
        
        # Add activity type classification
        risk_df['activity_type'] = risk_df.apply(classify_activity_type, axis=1)
        
        # Load the common table descriptions dictionary
        common_table_descriptions = get_common_table_descriptions()
        
        # Assess risk based on sensitive tables
        if SESSION_TABLE_COL in risk_df.columns:
            for table in sensitive_tables:
                table_mask = risk_df[SESSION_TABLE_COL].str.upper() == table.upper()
                if any(table_mask):
                    risk_df.loc[table_mask, 'risk_level'] = 'High'
                    description = table_descriptions.get(table, f"Sensitive table '{table}' - Contains critical system data")
                    risk_df.loc[table_mask, 'risk_factors'] = f"{description} (Table: {table})"
        
        # Load the common transaction code descriptions dictionary
        common_tcode_descriptions = get_common_tcode_descriptions()
        
        # Assess risk based on sensitive transaction codes
        if SESSION_TCODE_COL in risk_df.columns:
            for tcode in sensitive_tcodes:
                tcode_mask = risk_df[SESSION_TCODE_COL].str.upper() == tcode.upper()
                if any(tcode_mask):
                    risk_df.loc[tcode_mask, 'risk_level'] = 'High'
                    description = tcode_descriptions.get(tcode, f"Sensitive transaction '{tcode}' - Privileged system function")
                    # Only update risk factors if not already set by table assessment
                    empty_factors_mask = tcode_mask & (risk_df['risk_factors'] == '')
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = f"{description} (TCode: {tcode})"
        
        # Assess risk based on critical field patterns with enhanced descriptions
        if SESSION_FIELD_COL in risk_df.columns:
            # Handle null values properly
            adjusted_fields = risk_df[SESSION_FIELD_COL].fillna('')
            
            # First apply custom field assessment to handle special cases
            for idx, row in risk_df.iterrows():
                field_value = row[SESSION_FIELD_COL] if pd.notna(row[SESSION_FIELD_COL]) else ""
                is_high_risk, risk_desc = custom_field_risk_assessment(field_value)
                
                if is_high_risk and risk_desc:
                    risk_df.loc[idx, 'risk_level'] = 'High'
                    # Only update if risk factors not already set
                    if risk_df.loc[idx, 'risk_factors'] == '':
                        # Add field description if available
                        field_desc = common_field_descriptions.get(field_value.upper(), "")
                        field_info = f"{field_value}"
                        if field_desc:
                            field_info = f"{field_value} ({field_desc.split(' - ')[0]})"
                        
                        risk_df.loc[idx, 'risk_factors'] = f"{risk_desc} (Field: {field_info})"
            
            # Skip specific fields like "KEY" that should be excluded
            exclude_fields = ["KEY", "SPERM", "SPERQ", "QUAN"]
            exclude_mask = ~adjusted_fields.str.upper().isin([f.upper() for f in exclude_fields])
            
            # Then apply pattern matching for remaining fields
            for pattern, basic_desc in field_patterns.items():
                # Use word-bounded patterns to avoid false matches, and skip excluded fields
                pattern_mask = adjusted_fields.str.contains(pattern, regex=True, na=False) & exclude_mask
                if any(pattern_mask):
                    risk_df.loc[pattern_mask, 'risk_level'] = 'High'
                    description = field_descriptions.get(pattern, f"Critical field ({basic_desc}) - Contains sensitive data")
                    # Only update risk factors if not already set by table/tcode assessment
                    empty_factors_mask = pattern_mask & (risk_df['risk_factors'] == '')
                    # Include the actual field name that matched the pattern with description if available
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"{description} (Field: {get_field_info(x[SESSION_FIELD_COL], common_field_descriptions)})", 
                        axis=1)
        
        # Assess risk based on display_but_changed flag
        if 'display_but_changed' in risk_df.columns:
            mask = risk_df['display_but_changed']
            if any(mask):
                risk_df.loc[mask, 'risk_level'] = 'High'
                empty_factors_mask = mask & (risk_df['risk_factors'] == '')
                risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"Display transaction with changes (TCode: {get_tcode_info(x[SESSION_TCODE_COL], common_tcode_descriptions, tcode_descriptions)}) - Activity logged as view-only but includes data modifications",
                    axis=1)
        
        # Assess risk based on change indicator - using stripped values for comparison
        if SESSION_CHANGE_IND_COL in risk_df.columns:
            # Insert (I) operations
            insert_mask = risk_df[SESSION_CHANGE_IND_COL].str.upper() == 'I'
            if any(insert_mask):
                risk_df.loc[insert_mask, 'risk_level'] = 'High'
                empty_factors_mask = insert_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Insert operation - New record created in {get_table_info(x[SESSION_TABLE_COL], common_table_descriptions, table_descriptions)} table",
                        axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Insert operation (Change: {x[SESSION_CHANGE_IND_COL]}) - New record created", axis=1)
            
            # Delete (D) operations
            delete_mask = risk_df[SESSION_CHANGE_IND_COL].str.upper() == 'D'
            if any(delete_mask):
                risk_df.loc[delete_mask, 'risk_level'] = 'High'
                empty_factors_mask = delete_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Delete operation - Record removed from {get_table_info(x[SESSION_TABLE_COL], common_table_descriptions, table_descriptions)} table",
                        axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Delete operation (Change: {x[SESSION_CHANGE_IND_COL]}) - Record removed", axis=1)
            
            # Updates (U) are medium risk by default
            update_mask = (risk_df['risk_level'] == 'Low') & (risk_df[SESSION_CHANGE_IND_COL].str.upper() == 'U')
            if any(update_mask):
                risk_df.loc[update_mask, 'risk_level'] = 'Medium'
                empty_factors_mask = update_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Update operation - Existing record modified in {get_table_info(x[SESSION_TABLE_COL], common_table_descriptions, table_descriptions)} table",
                        axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Update operation (Change: {x[SESSION_CHANGE_IND_COL]}) - Existing record modified", axis=1)
        
        # Apply debugging-specific risk assessment if variable fields are present
        debug_fields_present = all(field in risk_df.columns for field in ['Variable_First', 'Variable_2', 'Variable_Data'])
        if debug_fields_present:
            log_message("Applying debugging pattern detection...")
            
            # Apply individual debug pattern detection to each row
            for idx, row in risk_df.iterrows():
                debug_risk_level, debug_risk_factors = detect_debug_patterns(row)
                
                if debug_risk_level and debug_risk_factors:
                    # Override risk level if debug risk is higher
                    current_level = risk_df.loc[idx, 'risk_level']
                    if (debug_risk_level == 'Critical' or 
                        (debug_risk_level == 'High' and current_level != 'Critical') or
                        (debug_risk_level == 'Medium' and current_level not in ['Critical', 'High'])):
                        risk_df.loc[idx, 'risk_level'] = debug_risk_level
                    
                    # Add debug risk factors to existing ones
                    current_factors = risk_df.loc[idx, 'risk_factors']
                    risk_df.loc[idx, 'risk_factors'] = current_factors + "; " + "; ".join(debug_risk_factors) if current_factors else "; ".join(debug_risk_factors)
            
            # Check for correlated debug and change events
            if 'Session ID with Date' in risk_df.columns:
                log_message("Analyzing debug activity correlation with data changes...")
                risk_df = detect_debug_with_changes(risk_df)
                
                # Count critical risk after debugging analysis
                critical_risk_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
                if critical_risk_count > 0:
                    log_message(f"Found {critical_risk_count} critical risk events from debugging pattern analysis", "WARNING")
        else:
            log_message("Skipping debugging pattern detection - variable fields not present in dataset", "INFO")
            
        # Add risk factors for Low risk items that don't have a factor yet
        low_risk_no_factor_mask = (risk_df['risk_level'] == 'Low') & (risk_df['risk_factors'] == '')
        if any(low_risk_no_factor_mask):
            log_message(f"Adding risk factors to {sum(low_risk_no_factor_mask)} low-risk items")
            
            # Use activity_type to categorize low-risk items
            for idx, row in risk_df[low_risk_no_factor_mask].iterrows():
                activity = row.get('activity_type', 'Unknown')
                tcode = row.get(SESSION_TCODE_COL, 'Unknown') if pd.notna(row.get(SESSION_TCODE_COL)) else 'Unknown'
                table = row.get(SESSION_TABLE_COL, '') if pd.notna(row.get(SESSION_TABLE_COL)) else ''
                
                # Get descriptions if available
                tcode_description = ""
                if tcode != 'Unknown' and tcode.strip() != "":
                    tcode_description = common_tcode_descriptions.get(tcode.upper(), tcode_descriptions.get(tcode.upper(), ""))
                    if tcode_description:
                        tcode_description = f" ({tcode_description.split(' - ')[0]})"
                
                table_description = ""
                if table and pd.notna(table) and table.strip() != '' and table != "nan":
                    table_description = common_table_descriptions.get(table.upper(), table_descriptions.get(table.upper(), ""))
                    if table_description:
                        table_description = f" ({table_description.split(' - ')[0]})"
                
                if activity == 'View':
                    risk_df.loc[idx, 'risk_factors'] = f"Standard view activity (TCode: {tcode}{tcode_description}) - Read-only access to system data"
                elif 'Financial' in activity:
                    risk_df.loc[idx, 'risk_factors'] = f"Standard financial transaction (TCode: {tcode}{tcode_description}) - Normal business process"
                elif 'Material Management' in activity:
                    risk_df.loc[idx, 'risk_factors'] = f"Standard material management activity (TCode: {tcode}{tcode_description}) - Normal inventory process"
                elif 'Sales' in activity:
                    risk_df.loc[idx, 'risk_factors'] = f"Standard sales activity (TCode: {tcode}{tcode_description}) - Normal business process"
                elif activity == 'Other' and table and pd.notna(table) and table.strip() != '':
                    if pd.notna(table) and table != "nan":
                        risk_df.loc[idx, 'risk_factors'] = f"Non-sensitive table access (Table: {table}{table_description}) - Contains non-sensitive data"
                    else:
                        tcode_str = "" if tcode == "Unknown" or tcode.strip() == "" else f" (TCode: {tcode}{tcode_description})"
                        risk_df.loc[idx, 'risk_factors'] = f"Standard system access{tcode_str} - No table modifications detected"
                elif tcode != 'Unknown' and tcode.strip() != "":
                    risk_df.loc[idx, 'risk_factors'] = f"Standard transaction (TCode: {t
