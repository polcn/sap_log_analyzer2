#!/usr/bin/env python3
"""
SAP Audit Tool - Risk Assessment Core Module

This module contains the core risk assessment functionality, orchestrating the
various risk detection methods and implementing the primary risk assessment logic.
It serves as the central component of the risk assessment subsystem.
"""

import pandas as pd

# Import supporting modules
from sap_audit_utils import (
    log_message, format_field_info, format_tcode_info, 
    format_table_info, format_event_code_info, clean_whitespace,
    standardize_column_values
)
from sap_audit_reference_data import (
    get_sensitive_tables, get_sensitive_table_descriptions,
    get_common_table_descriptions, get_sensitive_tcodes,
    get_sensitive_tcode_descriptions, get_common_tcode_descriptions,
    get_common_field_descriptions, get_critical_field_patterns,
    get_critical_field_pattern_descriptions, get_sap_event_code_classifications,
    get_sap_event_code_descriptions
)
from sap_audit_detectors import (
    custom_field_risk_assessment, detect_field_patterns,
    detect_debug_patterns, detect_debug_with_changes,
    classify_activity_type, detect_event_code_risk, analyze_event_details,
    detect_debug_message_codes, detect_authorization_bypass, detect_inventory_manipulation,
    INVENTORY_SENSITIVE_TABLES, INVENTORY_CRITICAL_FIELDS
)

# Column names (consistent with SAP Log Session Merger)
SESSION_TABLE_COL = 'Table'
SESSION_TCODE_COL = 'TCode'
SESSION_FIELD_COL = 'Field'
SESSION_CHANGE_IND_COL = 'Change_Indicator'
SESSION_EVENT_COL = 'Event'  # For SM20 event code

def assess_risk_session(session_data):
    """
    Core function to assess risk for a session timeline.
    Orchestrates the various risk assessment methods and combines their results.
    
    Args:
        session_data: DataFrame containing session data
        
    Returns:
        DataFrame with risk assessments applied
    """
    log_message("Starting comprehensive risk assessment...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = session_data.copy()
        
        # --- Data Preparation ---
        
        # Minimal cleaning for defensive programming
        for col in [SESSION_TABLE_COL, SESSION_TCODE_COL, SESSION_FIELD_COL, SESSION_CHANGE_IND_COL]:
            if col in risk_df.columns and risk_df[col].dtype == 'object':
                # Only clean if we see excessive whitespace
                if (risk_df[col].astype(str).str.strip() != risk_df[col]).any():
                    log_message(f"Note: Found whitespace in {col} column. Performing defensive cleaning.", "WARNING")
                    risk_df[col] = risk_df[col].astype(str).str.strip()
        
        # Initialize risk columns
        risk_df['risk_level'] = 'Low'  # Our custom risk level
        risk_df['sap_risk_level'] = 'Non-Critical'  # SAP's native risk level
        risk_df['risk_description'] = ''  # Renamed from risk_factors
        
        # Add activity type classification
        risk_df['activity_type'] = risk_df.apply(classify_activity_type, axis=1)
        
        # --- Load Reference Data ---
        
        # Table reference data
        sensitive_tables = get_sensitive_tables()
        sensitive_table_descriptions = get_sensitive_table_descriptions()
        common_table_descriptions = get_common_table_descriptions()
        
        # Transaction code reference data
        sensitive_tcodes = get_sensitive_tcodes()
        sensitive_tcode_descriptions = get_sensitive_tcode_descriptions()
        common_tcode_descriptions = get_common_tcode_descriptions()
        
        # Field reference data
        common_field_descriptions = get_common_field_descriptions()
        field_patterns = get_critical_field_patterns()
        field_descriptions = get_critical_field_pattern_descriptions()
        
        # Event code reference data
        event_classifications = get_sap_event_code_classifications()
        event_descriptions = get_sap_event_code_descriptions()
        
        # --- Risk Assessment: Table-Based Risks ---
        
        if SESSION_TABLE_COL in risk_df.columns:
            log_message("Assessing table-based risks...")
            
            for table in sensitive_tables:
                table_mask = risk_df[SESSION_TABLE_COL].str.upper() == table.upper()
                if any(table_mask):
                    risk_df.loc[table_mask, 'risk_level'] = 'High'
                    description = sensitive_table_descriptions.get(table, f"Sensitive table '{table}' - Contains critical system data")
                    
                    risk_df.loc[table_mask, 'risk_description'] = risk_df.loc[table_mask].apply(
                        lambda row: f"{description} (Table: {table}" + 
                                   (f", Field: {format_field_info(row[SESSION_FIELD_COL], common_field_descriptions)}" 
                                    if pd.notna(row[SESSION_FIELD_COL]) and row[SESSION_FIELD_COL].strip() != "" else "") + ")",
                        axis=1)
        
        # --- Risk Assessment: Transaction Code-Based Risks ---
        
        if SESSION_TCODE_COL in risk_df.columns:
            log_message("Assessing transaction code-based risks...")
            
            for tcode in sensitive_tcodes:
                tcode_mask = risk_df[SESSION_TCODE_COL].str.upper() == tcode.upper()
                if any(tcode_mask):
                    risk_df.loc[tcode_mask, 'risk_level'] = 'High'
                    description = sensitive_tcode_descriptions.get(tcode, f"Sensitive transaction '{tcode}' - Privileged system function")
                    
                    # Only update risk description if not already set by table assessment
                    empty_factors_mask = tcode_mask & (risk_df['risk_description'] == '')
                    risk_df.loc[empty_factors_mask, 'risk_description'] = f"{description} (TCode: {tcode})"
        
        # --- Risk Assessment: Field Pattern-Based Risks ---
        
        if SESSION_FIELD_COL in risk_df.columns:
            log_message("Assessing field pattern-based risks...")
            
            # Handle null values properly
            adjusted_fields = risk_df[SESSION_FIELD_COL].fillna('')
            
            # First apply custom field assessment to handle special cases
            for idx, row in risk_df.iterrows():
                field_value = row[SESSION_FIELD_COL] if pd.notna(row[SESSION_FIELD_COL]) else ""
                is_high_risk, risk_desc = custom_field_risk_assessment(field_value)
                
                if is_high_risk and risk_desc:
                    risk_df.loc[idx, 'risk_level'] = 'High'
                    # Only update if risk description not already set
                    if risk_df.loc[idx, 'risk_description'] == '':
                        # Add field description if available
                        field_desc = common_field_descriptions.get(field_value.upper(), "")
                        field_info = f"{field_value}"
                        if field_desc:
                            field_info = f"{field_value} ({field_desc.split(' - ')[0]})"
                        
                        risk_df.loc[idx, 'risk_description'] = f"{risk_desc} (Field: {field_info})"
            
            # Skip specific fields that should be excluded
            exclude_fields = ["KEY", "SPERM", "SPERQ", "QUAN"]
            exclude_mask = ~adjusted_fields.str.upper().isin([f.upper() for f in exclude_fields])
            
            # Then apply pattern matching for remaining fields
            for pattern, basic_desc in field_patterns.items():
                # Use word-bounded patterns to avoid false matches, and skip excluded fields
                pattern_mask = adjusted_fields.str.contains(pattern, regex=True, na=False) & exclude_mask
                if any(pattern_mask):
                    risk_df.loc[pattern_mask, 'risk_level'] = 'High'
                    description = field_descriptions.get(pattern, f"Critical field ({basic_desc}) - Contains sensitive data")
                    
                    # Only update risk description if not already set by previous assessments
                    empty_factors_mask = pattern_mask & (risk_df['risk_description'] == '')
                    risk_df.loc[empty_factors_mask, 'risk_description'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"{description} (Field: {format_field_info(x[SESSION_FIELD_COL], common_field_descriptions)})", 
                        axis=1)
        
        # --- Risk Assessment: Change Indicator-Based Risks ---
        
        if SESSION_CHANGE_IND_COL in risk_df.columns:
            log_message("Assessing change indicator-based risks...")
            
            # Insert (I) operations
            insert_mask = risk_df[SESSION_CHANGE_IND_COL].str.upper() == 'I'
            if any(insert_mask):
                risk_df.loc[insert_mask, 'risk_level'] = 'High'
                empty_factors_mask = insert_mask & (risk_df['risk_description'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_description'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"New data creation: User added new information to the system database. [Technical: Insert operation - New record created in {format_table_info(x[SESSION_TABLE_COL], common_table_descriptions, sensitive_table_descriptions)} table]",
                        axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_description'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"New data creation: User added new information to the system database. [Technical: Insert operation (Change: {x[SESSION_CHANGE_IND_COL]}) - New record created]", axis=1)
            
            # Delete (D) operations
            delete_mask = risk_df[SESSION_CHANGE_IND_COL].str.upper() == 'D'
            if any(delete_mask):
                risk_df.loc[delete_mask, 'risk_level'] = 'High'
                empty_factors_mask = delete_mask & (risk_df['risk_description'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_description'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Data deletion: User permanently removed information from the system - this deserves review to ensure the deletion was authorized. [Technical: Delete operation - Record removed from {format_table_info(x[SESSION_TABLE_COL], common_table_descriptions, sensitive_table_descriptions)} table]",
                        axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_description'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Data deletion: User permanently removed information from the system - this deserves review to ensure the deletion was authorized. [Technical: Delete operation (Change: {x[SESSION_CHANGE_IND_COL]}) - Record removed]", axis=1)
            
            # Updates (U) are medium risk by default
            update_mask = (risk_df['risk_level'] == 'Low') & (risk_df[SESSION_CHANGE_IND_COL].str.upper() == 'U')
            if any(update_mask):
                risk_df.loc[update_mask, 'risk_level'] = 'Medium'
                empty_factors_mask = update_mask & (risk_df['risk_description'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_description'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Data modification: User changed existing information in the system - changes to existing data should be reviewed for appropriateness. [Technical: Update operation - Existing record modified in {format_table_info(x[SESSION_TABLE_COL], common_table_descriptions, sensitive_table_descriptions)} table]",
                        axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_description'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Data modification: User changed existing information in the system - changes to existing data should be reviewed for appropriateness. [Technical: Update operation (Change: {x[SESSION_CHANGE_IND_COL]}) - Existing record modified]", axis=1)
        
        # --- Risk Assessment: Display But Changed Flag ---
        
        if 'display_but_changed' in risk_df.columns:
            log_message("Assessing display-but-changed flags...")
            
            mask = risk_df['display_but_changed']
            if any(mask):
                risk_df.loc[mask, 'risk_level'] = 'High'
                empty_factors_mask = mask & (risk_df['risk_description'] == '')
                risk_df.loc[empty_factors_mask, 'risk_description'] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"Unusual view transaction with data changes: Activity appeared as read-only but also made data modifications - this inconsistency requires investigation as it could indicate inappropriate data manipulation. [Technical: Display transaction with changes (TCode: {format_tcode_info(x[SESSION_TCODE_COL], common_tcode_descriptions, sensitive_tcode_descriptions)}) - Activity logged as view-only but includes data modifications]",
                    axis=1)
        
        # --- Risk Assessment: Detect Potential Stealth Changes ---
        # Look for SM20 entries with activity 02 (change permission) but no actual changes in CDHDR/CDPOS
        
        potential_stealth_changes = False
        
        # Check if we have SM20 source and description data
        if 'Source' in risk_df.columns and 'Description' in risk_df.columns:
            # Find SM20 entries with activity 02 indication
            sm20_activity_02_mask = (
                (risk_df['Source'] == 'SM20') & 
                (risk_df['Description'].str.contains('ACTIVITY 02', case=False, na=False)) &
                (risk_df['Description'].str.contains('AUTH. CHECK: PASSED', case=False, na=False))
            )
            
            # No Old_Value or New_Value - potential stealth changes
            no_change_values_mask = sm20_activity_02_mask & (
                (pd.isna(risk_df['Old_Value']) | (risk_df['Old_Value'] == '')) &
                (pd.isna(risk_df['New_Value']) | (risk_df['New_Value'] == ''))
            )
            
            # Apply risk assessment for these special cases
            if any(no_change_values_mask):
                log_message(f"Found {sum(no_change_values_mask)} potential stealth changes (activity 02 without recorded change values)")
                
                for idx in risk_df[no_change_values_mask].index:
                    # Don't override higher risk levels
                    if risk_df.loc[idx, 'risk_level'] not in ['Critical', 'High']:
                        risk_df.loc[idx, 'risk_level'] = 'Medium'
                    
                    current_desc = risk_df.loc[idx, 'risk_description']
                    table_name = risk_df.loc[idx, 'Table'] if 'Table' in risk_df.columns and pd.notna(risk_df.loc[idx, 'Table']) else '[unknown table]'
                    tcode = risk_df.loc[idx, 'TCode'] if 'TCode' in risk_df.columns and pd.notna(risk_df.loc[idx, 'TCode']) else '[unknown tcode]'
                    
                    new_desc = f"Potential unlogged changes: Activity with change permission (02) detected but no change records exist - changes made through debugging would not be logged. [Technical: Authorized for changes to table {table_name} using {tcode} but no CDHDR/CDPOS entries found]"
                    
                    if current_desc and current_desc.strip():
                        risk_df.loc[idx, 'risk_description'] = f"{current_desc}; {new_desc}"
                    else:
                        risk_df.loc[idx, 'risk_description'] = new_desc
                    
                potential_stealth_changes = True
        
        # --- Risk Assessment: Enhanced Debug Pattern Detection ---
        
        # Check if required fields are present for debugging detection
        debug_var_fields_present = all(field in risk_df.columns for field in ['Variable_First', 'Variable_2', 'Variable_Data'])
        message_id_present = 'Message_ID' in risk_df.columns
        
        if debug_var_fields_present or message_id_present:
            log_message("Applying enhanced debugging pattern detection...")
            
            # 1. Apply Variable-based debugging detection (legacy approach)
            if debug_var_fields_present:
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
                        current_factors = risk_df.loc[idx, 'risk_description']
                        risk_df.loc[idx, 'risk_description'] = current_factors + "; " + "; ".join(debug_risk_factors) if current_factors else "; ".join(debug_risk_factors)
            
            # 2. Apply Message Code-based debugging detection (new approach)
            if message_id_present:
                log_message("Applying message code-based debugging detection...")
                message_code_count = 0
                
                for idx, row in risk_df.iterrows():
                    detected, risk_level, risk_description = detect_debug_message_codes(row)
                    
                    if detected:
                        message_code_count += 1
                        # Override risk level if higher
                        current_level = risk_df.loc[idx, 'risk_level']
                        if (risk_level == 'Critical' or 
                            (risk_level == 'High' and current_level != 'Critical') or
                            (risk_level == 'Medium' and current_level not in ['Critical', 'High'])):
                            risk_df.loc[idx, 'risk_level'] = risk_level
                        
                        # Add message code risk description
                        current_factors = risk_df.loc[idx, 'risk_description']
                        if current_factors and current_factors.strip():
                            risk_df.loc[idx, 'risk_description'] = current_factors + "; " + risk_description
                        else:
                            risk_df.loc[idx, 'risk_description'] = risk_description
                
                if message_code_count > 0:
                    log_message(f"Found {message_code_count} debug events based on message codes", "WARNING")
            
            # 3. Session-based pattern detection (analyzes multiple events together)
            if 'Session ID with Date' in risk_df.columns:
                log_message("Analyzing session-based debugging patterns...")
                
                # Group by session ID to analyze patterns within sessions
                for session_id, session_group in risk_df.groupby('Session ID with Date'):
                    # Check for authorization bypass pattern
                    auth_bypass_detected, auth_bypass_risk, auth_bypass_factors = detect_authorization_bypass(session_group)
                    if auth_bypass_detected:
                        log_message(f"Found authorization bypass pattern in session {session_id}", "WARNING")
                        # Apply to all events in the session
                        for idx in session_group.index:
                            # Only upgrade risk level (never downgrade)
                            if auth_bypass_risk == 'Critical' or risk_df.loc[idx, 'risk_level'] != 'Critical':
                                risk_df.loc[idx, 'risk_level'] = auth_bypass_risk
                            # Add risk description
                            current_factors = risk_df.loc[idx, 'risk_description']
                            if current_factors and current_factors.strip():
                                risk_df.loc[idx, 'risk_description'] = current_factors + "; " + "; ".join(auth_bypass_factors)
                            else:
                                risk_df.loc[idx, 'risk_description'] = "; ".join(auth_bypass_factors)
                    
                    # Check for inventory manipulation with debugging
                    inv_manip_detected, inv_manip_risk, inv_manip_factors = detect_inventory_manipulation(
                        session_group, INVENTORY_SENSITIVE_TABLES)
                    if inv_manip_detected:
                        log_message(f"Found inventory manipulation pattern in session {session_id}", "WARNING")
                        # Apply to all events in the session
                        for idx in session_group.index:
                            # Only upgrade risk level (never downgrade)
                            if inv_manip_risk == 'Critical' or risk_df.loc[idx, 'risk_level'] != 'Critical':
                                risk_df.loc[idx, 'risk_level'] = inv_manip_risk
                            # Add risk description
                            current_factors = risk_df.loc[idx, 'risk_description']
                            if current_factors and current_factors.strip():
                                risk_df.loc[idx, 'risk_description'] = current_factors + "; " + "; ".join(inv_manip_factors)
                            else:
                                risk_df.loc[idx, 'risk_description'] = "; ".join(inv_manip_factors)
                
                # Legacy debug + changes detection
                log_message("Analyzing debug activity correlation with data changes...")
                risk_df = detect_debug_with_changes(risk_df)
                
                # Count critical risk after debugging analysis
                critical_risk_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
                if critical_risk_count > 0:
                    log_message(f"Found {critical_risk_count} critical risk events from debugging pattern analysis", "WARNING")
        else:
            log_message("Skipping debugging pattern detection - required fields not present in dataset", "INFO")
        
        # --- Risk Assessment: SAP Event Code Analysis ---
        
        if SESSION_EVENT_COL in risk_df.columns:
            log_message("Applying SAP event code risk analysis...")
            
            # Apply event code classification
            for idx, row in risk_df.iterrows():
                event_code = row[SESSION_EVENT_COL] if pd.notna(row[SESSION_EVENT_COL]) else ""
                event_risk_level, event_risk_desc = detect_event_code_risk(event_code, event_classifications)
                
                if event_risk_level and event_risk_desc:
                    # Map SAP criticality to our risk levels
                    if event_risk_level == 'High' and risk_df.loc[idx, 'risk_level'] != 'Critical':
                        risk_df.loc[idx, 'risk_level'] = 'High'
                    elif event_risk_level == 'Medium' and risk_df.loc[idx, 'risk_level'] not in ['Critical', 'High']:
                        risk_df.loc[idx, 'risk_level'] = 'Medium'
                    
                    # Add SAP event classification to risk factors
                    event_details = analyze_event_details(row, event_descriptions)
                    event_desc = event_descriptions.get(event_code.strip().upper(), "")
                    
                    factor = f"SAP Event: {format_event_code_info(event_code, event_descriptions)}"
                    if event_details:
                        factor += f" - {event_details}"
                    
                    # Add to existing risk description if present
                    current_factors = risk_df.loc[idx, 'risk_description']
                    if current_factors and current_factors.strip():
                        risk_df.loc[idx, 'risk_description'] = current_factors + "; " + factor
                    else:
                        risk_df.loc[idx, 'risk_description'] = factor
                        
                    # Set SAP risk level based on event classification
                    if event_risk_level == 'High':
                        risk_df.loc[idx, 'sap_risk_level'] = 'Critical'
                    elif event_risk_level == 'Medium':
                        risk_df.loc[idx, 'sap_risk_level'] = 'Important'
                    else:
                        risk_df.loc[idx, 'sap_risk_level'] = 'Non-Critical'
                        
        # --- Risk Assessment: Default Risk Factors for Low-Risk Items ---
        
        log_message("Adding default risk factors for remaining low-risk items...")
        
        low_risk_no_factor_mask = (risk_df['risk_level'] == 'Low') & (risk_df['risk_description'] == '')
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
                    tcode_description = common_tcode_descriptions.get(tcode.upper(), sensitive_tcode_descriptions.get(tcode.upper(), ""))
                    if tcode_description:
                        tcode_description = f" ({tcode_description.split(' - ')[0]})"
                
                table_description = ""
                if table and pd.notna(table) and table.strip() != '' and table != "nan":
                    table_description = common_table_descriptions.get(table.upper(), sensitive_table_descriptions.get(table.upper(), ""))
                    if table_description:
                        table_description = f" ({table_description.split(' - ')[0]})"
                
                if activity == 'View':
                    risk_df.loc[idx, 'risk_description'] = f"Information viewing activity: User only viewed data without making changes - standard access for reporting purposes. [Technical: Standard view activity (TCode: {tcode}{tcode_description}) - Read-only access to system data]"
                elif activity == 'Financial':
                    risk_df.loc[idx, 'risk_description'] = f"Regular financial transaction: Standard accounting activity that is part of normal business operations. [Technical: Standard financial transaction (TCode: {tcode}{tcode_description}) - Normal business process]"
                elif activity == 'Material Management':
                    risk_df.loc[idx, 'risk_description'] = f"Inventory management: Routine activity to manage inventory, materials, or purchasing - part of standard operations. [Technical: Standard material management activity (TCode: {tcode}{tcode_description}) - Normal inventory process]"
                elif activity == 'Sales':
                    risk_df.loc[idx, 'risk_description'] = f"Sales process: Standard sales or customer-related activity that is part of normal business operations. [Technical: Standard sales activity (TCode: {tcode}{tcode_description}) - Normal business process]"
                elif activity == 'Other' and table and pd.notna(table) and table.strip() != '':
                    if pd.notna(table) and table != "nan":
                        risk_df.loc[idx, 'risk_description'] = f"Regular data access: User accessed non-sensitive business data tables - normal system usage. [Technical: Non-sensitive table access (Table: {table}{table_description}) - Contains non-sensitive data]"
                    else:
                        tcode_str = "" if tcode == "Unknown" or tcode.strip() == "" else f" (TCode: {tcode}{tcode_description})"
                        risk_df.loc[idx, 'risk_description'] = f"Standard system usage: Routine system access without any data modifications. [Technical: Standard system access{tcode_str} - No table modifications detected]"
                elif tcode != 'Unknown' and tcode.strip() != "":
                    risk_df.loc[idx, 'risk_description'] = f"Standard business function: Regular transaction used for routine business activities. [Technical: Standard transaction (TCode: {tcode}{tcode_description}) - Routine business function]"
                else:
                    risk_df.loc[idx, 'risk_description'] = f"Low-risk system activity: Regular system usage that doesn't involve sensitive data or system changes. [Technical: Low risk activity - No sensitive data or system changes involved]"
        
        # --- Finalize Risk Assessment ---
        
        # Count risk levels
        critical_risk_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
        high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
        medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
        low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
        
        log_message(f"Risk assessment complete. Critical: {critical_risk_count}, High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
        
        return risk_df
    
    except Exception as e:
        log_message(f"Error during risk assessment: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return session_data
