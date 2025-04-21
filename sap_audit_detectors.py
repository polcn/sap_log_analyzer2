#!/usr/bin/env python3
"""
SAP Audit Tool - Specialized Detectors Module

This module contains specialized detection functions for identifying various
patterns of interest in SAP audit data, including debugging activities,
sensitive field operations, and event code classification.
"""

import re
import pandas as pd

# Import utility functions
from sap_audit_utils import log_message

# --- Constants and Configuration ---

# Dictionary of critical debugging message codes with descriptions
DEBUG_MESSAGE_CODES = {
    'CU_M': "Jump to ABAP Debugger",
    'CUL': "Field content changed in debugger",
    'BUZ': "Variable modification in debugger",
    'CUK': "C debugging activated",
    'CUN': "Process stopped from debugger",
    'CUO': "Explicit DB commit/rollback from debugger",
    'CUP': "Non-exclusive debugging session started",
    'BU4': "Dynamic ABAP coding",
    'DU9': "Generic table access (e.g., SE16)",
    'AU4': "Failed transaction start (possible authorization failure)"
}

# Dictionary of inventory-related sensitive tables
INVENTORY_SENSITIVE_TABLES = {
    # Material master data
    'MARA': "Material Master Data",
    'MARC': "Plant Data for Material",
    'MBEW': "Material Valuation",
    'EBEW': "Sales Order Stock Valuation",
    'QBEW': "Project Stock Valuation",
    
    # Batch management (potency)
    'MCH1': "Batch Master",
    'MCHA': "Batch Classification Data",
    
    # Inventory movements
    'MSEG': "Document Segment: Material",
    'MKPF': "Header: Material Document",
    
    # Valuation and pricing
    'KONP': "Conditions (pricing)",
    'KONH': "Condition Header Data"
}

# Dictionary of inventory-related critical fields
INVENTORY_CRITICAL_FIELDS = {
    # Potency-related fields
    'POTX1': "Potency value",
    'POTX2': "Potency value",
    'POTY1': "Potency value",
    'POTY2': "Potency value",
    
    # Valuation fields
    'STPRS': "Standard Price",
    'PEINH': "Price Unit",
    'VPRSV': "Price Control",
    'VERPR': "Moving Average Price",
    'BWTAR': "Valuation Type",
    'BWPRS': "Valuation Price",
    'LAEPR': "Last Price",
    
    # Quantity fields affecting valuation
    'LABST': "Unrestricted Stock",
    'INSMK': "Stock Type",
    'ERFMG': "Quantity",
    'KZBWS': "Valuation Indicator"
}

# --- Field Pattern Detection ---

def custom_field_risk_assessment(field_name):
    """
    Perform custom risk assessment for fields that need special handling.
    Returns improved dual-format risk descriptions for non-technical reviewers.

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

    # Custom rules for specific field patterns with improved descriptions
    if field.startswith("KEY_") or field.endswith("_KEY") or "SECUR" in field:
        return True, "Security credential or encryption changes: Changes to system security settings that could affect how users authenticate or data is protected. [Technical: Security key/token - Infrastructure change affecting encryption or authentication]"
    
    if "PERM" in field and field != "SPERM" and field != "SPERQ":
        return True, "Access permission changes: Modifications to who can access what in the system, potentially creating security vulnerabilities. [Technical: Permission settings - Access control modification affecting security boundaries]"

    return False, None

def detect_field_patterns(field_name, field_patterns):
    """
    Detect if a field name matches any of the specified patterns.
    
    Args:
        field_name: The field name to check
        field_patterns: Dictionary of patterns to check against
        
    Returns:
        Tuple of (matches_pattern, pattern_key, pattern_description) or (False, None, None) if no match
    """
    if not isinstance(field_name, str) or pd.isna(field_name) or field_name.strip() == "":
        return False, None, None
        
    field = field_name.strip()
    
    # Check each pattern
    for pattern, description in field_patterns.items():
        if re.search(pattern, field, re.IGNORECASE):
            return True, pattern, description
            
    return False, None, None

# --- Debug Pattern Detection ---

def detect_debug_message_codes(row):
    """
    Detect debugging activity via specific SM20 message codes.
    This is a more precise method than variable flags.
    
    Args:
        row: DataFrame row containing SM20 log data

    Returns:
        Tuple of (detected, risk_level, risk_description) or (False, None, None) if not detected
    """
    # Extract the message ID from the row
    message_id = str(row.get('Message_ID', '')) if pd.notna(row.get('Message_ID', '')) else ''
    message_id = message_id.strip().upper()
    
    # Check if message ID is one of our debugging codes
    if message_id in DEBUG_MESSAGE_CODES:
        # Get description for the code
        action_desc = DEBUG_MESSAGE_CODES[message_id]
        
        # Set risk level based on the message code
        risk_level = 'High'  # Default for most debug codes
        
        # Specific risk levels for different debug codes
        if message_id in ['CU_M', 'CUL', 'BUZ', 'CUK', 'CUO']:
            risk_level = 'High'  # Direct debugging actions
        elif message_id in ['BU4']:
            risk_level = 'Critical'  # Dynamic ABAP - highest risk
        elif message_id in ['DU9']:
            risk_level = 'Medium'  # Generic table access - medium risk
        elif message_id in ['AU4']:
            # Just detecting AU4 alone isn't a debug pattern, used for auth bypass detection
            return False, None, None
        
        # Create appropriate risk description with plain-language explanation
        risk_description = f"Advanced debugging activity detected: {action_desc} - This gives the user direct control over system behavior and data. [Technical: {message_id} message code detected - {action_desc}]"
        
        return True, risk_level, risk_description
        
    return False, None, None

def detect_authorization_bypass(session_events):
    """
    Detect potential authorization bypass pattern: 
    Failed action -> Debug activation -> Successful similar action.
    
    Args:
        session_events: DataFrame containing events for a single session

    Returns:
        Tuple of (detected, risk_level, risk_factors_list) or (False, None, []) if not detected
    """
    risk_factors = []
    
    # Need to have at least 3 events to detect this pattern
    if len(session_events) < 3:
        return False, None, risk_factors
    
    # Sort events chronologically
    events = session_events.sort_values('Datetime')
    
    # Look for the sequence: failed transaction -> debug activation -> successful transaction
    for i in range(len(events) - 2):
        # Step 1: Check for failed action/transaction
        row_i = events.iloc[i]
        message_id_i = str(row_i.get('Message_ID', '')) if pd.notna(row_i.get('Message_ID', '')) else ''
        tcode_i = str(row_i.get('TCode', '')) if pd.notna(row_i.get('TCode', '')) else ''
        desc_i = str(row_i.get('Description', '')) if pd.notna(row_i.get('Description', '')) else ''
        
        is_failed = (message_id_i == 'AU4' or 
                     'AUTHORIZATION FAILURE' in desc_i.upper() or 
                     'AUTH. CHECK: FAILED' in desc_i.upper())
        
        if not is_failed:
            continue
            
        # Step 2: Check if followed by debugging activity
        row_j = events.iloc[i+1]
        message_id_j = str(row_j.get('Message_ID', '')) if pd.notna(row_j.get('Message_ID', '')) else ''
        var_2_j = str(row_j.get('Variable_2', '')) if pd.notna(row_j.get('Variable_2', '')) else ''
        
        is_debug = (message_id_j in ['CU_M', 'CUL', 'BUZ', 'CUK', 'CUO'] or 
                   any(flag in var_2_j for flag in ['D!', 'I!']))
        
        if not is_debug:
            continue
            
        # Step 3: Check if followed by successful action (similar to the failed one)
        row_k = events.iloc[i+2]
        tcode_k = str(row_k.get('TCode', '')) if pd.notna(row_k.get('TCode', '')) else ''
        desc_k = str(row_k.get('Description', '')) if pd.notna(row_k.get('Description', '')) else ''
        
        # Check if same transaction code or similar description
        is_similar_action = (tcode_i == tcode_k or
                            (tcode_i in desc_k) or
                            ('AUTH. CHECK: PASSED' in desc_k.upper()))
        
        if is_similar_action:
            risk_description = "Authorization bypass detected: User encountered an authorization failure, used debugging, then successfully performed a similar action. This indicates possible manipulation of authorization checks. [Technical: Failed action -> Debug -> Success pattern detected - Critical security risk of authorization bypass]"
            risk_factors.append(risk_description)
            return True, 'Critical', risk_factors
    
    return False, None, risk_factors

def detect_inventory_manipulation(session_events, inventory_tables=INVENTORY_SENSITIVE_TABLES):
    """
    Detect debugging combined with inventory-related changes, especially for potency/valuation.
    
    Args:
        session_events: DataFrame containing events for a single session
        inventory_tables: Dictionary of sensitive inventory tables to check

    Returns:
        Tuple of (detected, risk_level, risk_factors_list) or (False, None, []) if not detected
    """
    risk_factors = []
    
    # Check if session contains debugging activity
    has_debug = False
    for _, row in session_events.iterrows():
        # Check for debug message codes
        message_id = str(row.get('Message_ID', '')) if pd.notna(row.get('Message_ID', '')) else ''
        message_id = message_id.strip().upper()
        
        # Check debug variable flags
        var_2 = str(row.get('Variable_2', '')) if pd.notna(row.get('Variable_2', '')) else ''
        
        if (message_id in DEBUG_MESSAGE_CODES or 
            any(flag in var_2 for flag in ['D!', 'I!', 'G!'])):
            has_debug = True
            break
    
    if not has_debug:
        return False, None, risk_factors
    
    # Check for changes to inventory tables or fields
    inventory_related_changes = False
    affected_tables = set()
    for _, row in session_events.iterrows():
        table = str(row.get('Table', '')) if pd.notna(row.get('Table', '')) else ''
        table = table.strip().upper()
        
        field = str(row.get('Field', '')) if pd.notna(row.get('Field', '')) else ''
        field = field.strip().upper()
        
        change_ind = str(row.get('Change_Indicator', '')) if pd.notna(row.get('Change_Indicator', '')) else ''
        
        # Check if this is a change to an inventory table or field
        if ((table in inventory_tables or 
             field in INVENTORY_CRITICAL_FIELDS) and 
            change_ind in ['I', 'U', 'D']):
            inventory_related_changes = True
            affected_tables.add(table)
    
    if inventory_related_changes:
        table_list = ", ".join(affected_tables)
        risk_description = f"Inventory data manipulation with debugging: User made changes to inventory data ({table_list}) while debugging tools were active. This is high-risk activity that could affect valuation or quantities. [Technical: Debug + Inventory Table Changes detected - Critical risk for potential fraud or material misstatement]"
        risk_factors.append(risk_description)
        return True, 'Critical', risk_factors
    
    return False, None, risk_factors

def detect_debug_patterns(row):
    """
    Enhanced debugging detection for SAP logs.
    Looks for debugging indicators in multiple fields with flexible column mapping.
    Provides clear explanations for non-technical reviewers.

    Args:
        row: DataFrame row containing potential debug data

    Returns:
        Tuple of (risk_level, risk_factors_list)
        Where risk_level can be 'Critical', 'High', 'Medium', 'Low', or None
        And risk_factors_list is a list of risk factor descriptions
    """
    risk_factors = []
    
    # Identify the variable fields with flexible column mapping
    # This handles different capitalization and formatting in column names
    var_fields = {}
    
    # Find Variable_2 field - try multiple possible column names
    for potential_name in ['Variable_2', 'Variable 2', 'VARIABLE 2', 'VARIABLE_2', 'VAR 2', 'VAR2']:
        if potential_name in row:
            var_fields['var_2'] = str(row.get(potential_name, '')) if pd.notna(row.get(potential_name, '')) else ''
            break
    else:
        var_fields['var_2'] = ''
    
    # Find Variable_First field - try multiple possible column names
    for potential_name in ['Variable_First', 'Variable First', 'VARIABLE_FIRST', 'FIRST VARIABLE VALUE FOR EVENT', 
                         'First Variable Value for Event', 'VAR_FIRST', 'VAR FIRST']:
        if potential_name in row:
            var_fields['var_first'] = str(row.get(potential_name, '')) if pd.notna(row.get(potential_name, '')) else ''
            break
    else:
        var_fields['var_first'] = ''
    
    # Find Variable_Data field - try multiple possible column names
    for potential_name in ['Variable_Data', 'Variable Data', 'VARIABLE_DATA', 'VARIABLE DATA FOR MESSAGE', 
                         'Variable Data for Message', 'VAR_DATA', 'VAR DATA']:
        if potential_name in row:
            var_fields['var_data'] = str(row.get(potential_name, '')) if pd.notna(row.get(potential_name, '')) else ''
            break
    else:
        var_fields['var_data'] = ''
    
    # Get other relevant fields
    event = str(row.get('Event', '')) if pd.notna(row.get('Event', '')) else ''
    description = str(row.get('Description', '')) if pd.notna(row.get('Description', '')) else ''
    username = str(row.get('User', '')) if pd.notna(row.get('User', '')) else ''
    
    # 1. DYNAMIC ABAP CODE EXECUTION (BU4 event)
    if event.upper() == 'BU4':
        # Check for specific event types in the description or variable fields
        if 'event type I!' in description or 'I!' in var_fields['var_2']:
            risk_factors.append("Dynamic ABAP code execution: User ran custom code that could bypass standard business processes and security controls. [Technical: BU4 event with I! type - Dynamic ABAP execution with internal operation]")
            return 'Critical', risk_factors
        elif 'event type G!' in description or 'G!' in var_fields['var_2']:
            risk_factors.append("Remote function call with dynamic code: User executed dynamic code that interacts with external systems. [Technical: BU4 event with G! type - Dynamic ABAP with gateway/RFC access]")
            return 'Critical', risk_factors
        elif 'event type D!' in description or 'D!' in var_fields['var_2']:
            risk_factors.append("Debugging with dynamic code execution: User combined debugging and dynamic code execution, which provides extensive system control. [Technical: BU4 event with D! type - Dynamic ABAP during debugging]")
            return 'Critical', risk_factors
        else:
            # Generic BU4 detection
            risk_factors.append("Dynamic ABAP code execution: User ran dynamic code that could bypass standard controls and security measures. [Technical: BU4 event - Dynamic ABAP code execution]")
            return 'High', risk_factors
    
    # 2. DEBUG FLAG DETECTION (more comprehensive check across multiple fields)
    # Check for I! flag in any relevant field
    if ('I!' in var_fields['var_2'] or 
        'event type I!' in description or 
        'I!' in var_fields['var_data']):
        risk_factors.append("Custom code execution: User ran custom code that could bypass standard business processes and security controls. [Technical: Dynamic ABAP code execution detected (I!) - Internal/Insert operation that may bypass normal controls]")
        return 'High', risk_factors

    # Check for D! flag in any relevant field
    if ('D!' in var_fields['var_2'] or 
        'event type D!' in description or 
        'D!' in var_fields['var_data']):
        risk_factors.append("System debugging activity: User activated debugging tools that allow viewing and potentially altering how the system processes data. [Technical: Debug session detected (D!) - User debugging program logic and potentially manipulating runtime variables]")
        return 'High', risk_factors

    # Check for G! flag in any relevant field
    if ('G!' in var_fields['var_2'] or 
        'event type G!' in description or 
        'G!' in var_fields['var_data']):
        risk_factors.append("Remote system access: User connected to another system or service which could be used to transfer data between systems. [Technical: Gateway/RFC call detected (G!) - Remote function call or service interface access]")
        return 'High', risk_factors
    
    # 3. MSG CODE DETECTION IN DESCRIPTION
    for code in ['CU_M', 'CUL', 'BUZ', 'CUK', 'CUN', 'CUO', 'CUP']:
        if code in description:
            action_desc = DEBUG_MESSAGE_CODES.get(code, "Debugging activity")
            risk_factors.append(f"Advanced debugging activity: User performed sophisticated debugging operations that allow direct system manipulation. [Technical: {code} message detected in description - {action_desc}]")
            return 'High', risk_factors
    
    # 4. OTHER PATTERNS (kept from original function)
    # Service interface access
    if 'R3TR' in var_fields['var_first']:
        risk_factors.append("Service interface access by privileged user: User accessed standard interfaces or services. [Technical: User accessing service interfaces - Standard privileged activity]")
        return 'Medium', risk_factors

    # Service interface detection - normal operations
    if 'R3TR IWSV' in var_fields['var_first'] or 'R3TR IWSG' in var_fields['var_first']:
        risk_factors.append("Standard interface access: User accessed a regular service interface for routine data exchange - normal system activity. [Technical: Service interface access - Standard OData or API gateway activity]")
        return 'Low', risk_factors

    # Gateway framework detection
    if 'R3TR G4BA' in var_fields['var_first']:
        risk_factors.append("Standard gateway access: User accessed the SAP Gateway framework for routine operations - normal system activity. [Technical: Gateway framework access - Standard SAP Gateway activity]")
        return 'Low', risk_factors

    # OData endpoint patterns
    if '/sap/opu/odata/' in var_fields['var_data']:
        risk_factors.append("API data access: User accessed data through programming interfaces rather than standard screens - may require review if unusual. [Technical: OData endpoint access - API-based data access]")
        return 'Medium', risk_factors

    return None, risk_factors

def detect_debug_with_changes(session_df):
    """
    Detect debugging activities correlated with data changes in the same session.
    Preserves Low risk level for display/view activities regardless of context.
    Provides clear explanations for non-technical reviewers.

    Args:
        session_df: DataFrame containing session data

    Returns:
        Modified DataFrame with updated risk assessments
    """
    # Create a copy to avoid warning
    df = session_df.copy()

    # Ensure activity_type is present
    if 'activity_type' not in df.columns:
        df['activity_type'] = df.apply(classify_activity_type, axis=1)

    # Group by session ID
    for session_id, session_group in df.groupby('Session ID with Date'):
        # Check for debug flags in Variable_2
        debug_events = session_group[session_group['Variable_2'].isin(['I!', 'D!', 'G!'])]

        # Check for change indicators
        change_events = session_group[session_group['Change_Indicator'].isin(['I', 'U', 'D'])]

        # If both debug events and changes exist in same session
        if not debug_events.empty and not change_events.empty:
            # Flag all debug events as Critical (except View activities)
            for idx in debug_events.index:
                # Skip view/display activities - keep them Low risk
                if df.loc[idx, 'activity_type'] == 'View':
                    continue

                df.loc[idx, 'risk_level'] = 'Critical'
                current_factors = df.loc[idx, 'risk_description'] if 'risk_description' in df.columns else df.loc[idx, 'risk_factors']
                new_factor = "System debugging followed by data changes: User used debugging tools and then made data changes in the same session - this is a red flag for potential deliberate data manipulation. [Technical: Debugging activity with data changes in same session - High risk pattern indicating potential data manipulation]"

                # Use appropriate column name (risk_description or risk_factors)
                if 'risk_description' in df.columns:
                    df.loc[idx, 'risk_description'] = current_factors + "; " + new_factor if current_factors else new_factor
                else:
                    df.loc[idx, 'risk_factors'] = current_factors + "; " + new_factor if current_factors else new_factor

            # Flag all change events as High (except View activities)
            for idx in change_events.index:
                # Skip view/display activities - keep them Low risk
                if df.loc[idx, 'activity_type'] == 'View':
                    continue

                if df.loc[idx, 'risk_level'] != 'Critical':  # Don't downgrade Critical events
                    df.loc[idx, 'risk_level'] = 'High'

                current_factors = df.loc[idx, 'risk_description'] if 'risk_description' in df.columns else df.loc[idx, 'risk_factors']
                new_factor = "Data changed during system debugging: Data was modified while debugging tools were active in the same session - this could indicate unauthorized data manipulation. [Technical: Data change during debug session - Suspicious pattern indicating potential targeted data manipulation]"

                # Use appropriate column name (risk_description or risk_factors)
                if 'risk_description' in df.columns:
                    df.loc[idx, 'risk_description'] = current_factors + "; " + new_factor if current_factors else new_factor
                else:
                    df.loc[idx, 'risk_factors'] = current_factors + "; " + new_factor if current_factors else new_factor

    return df

# --- Activity Classification ---

def classify_activity_type(row):
    """
    Classify the activity type based on the row data.
    Enhanced to better handle SE16 transactions and activity codes.
    
    Args:
        row: DataFrame row with transaction, table, and description information
        
    Returns:
        String describing the activity type
    """
    if pd.isna(row.get('TCode')) and pd.isna(row.get('Table')):
        return 'Unknown'
    
    # Extract key data with proper null handling
    tcode = str(row.get('TCode', '')).strip().upper() if pd.notna(row.get('TCode', '')) else ''
    description = str(row.get('Description', '')).upper() if pd.notna(row.get('Description', '')) else ''
    change_ind = str(row.get('Change_Indicator', '')).strip().upper() if pd.notna(row.get('Change_Indicator', '')) else ''
    var_first = str(row.get('Variable_First', '')).strip() if pd.notna(row.get('Variable_First', '')) else ''
    old_value = str(row.get('Old_Value', '')).strip() if pd.notna(row.get('Old_Value', '')) else ''
    new_value = str(row.get('New_Value', '')).strip() if pd.notna(row.get('New_Value', '')) else ''
    source = str(row.get('Source', '')).strip().upper() if pd.notna(row.get('Source', '')) else ''
    
    # Handle special case: SE16 transactions with SM20 source but no actual changes
    if tcode == 'SE16' and source == 'SM20' and old_value == '' and new_value == '':
        # This is likely just an auth check with no actual changes
        if 'ACTIVITY 02' in description and 'AUTH. CHECK: PASSED' in description:
            return 'View'  # Reclassify as View despite the 02 activity
    
    # Handle normal display keywords in description
    if 'DISPLAY' in description or 'VIEW' in description or 'SHOW' in description or 'LIST' in description:
        return 'View'
    
    # Check for actual changes via change indicators (these represent confirmed changes)
    if change_ind == 'I':
        return 'Create'
    elif change_ind == 'U':
        return 'Update'
    elif change_ind == 'D':
        return 'Delete'
    
    # Handle other known transaction types
    if tcode.startswith('F') or tcode in ['FB50', 'FB01', 'FB02']:
        return 'Financial'
    elif tcode.startswith('S'):
        return 'System'
    elif tcode.startswith('MM'):
        return 'Material Management'
    elif tcode.startswith('VA'):
        return 'Sales'
    
    # Default
    return 'Other'

# --- SAP Event Code Detection ---

def detect_event_code_risk(event_code, event_classifications):
    """
    Determine risk level based on SAP's event code classification.
    Provides clear explanations for non-technical reviewers.

    Args:
        event_code: The SAP event code
        event_classifications: Dictionary mapping event codes to criticality levels

    Returns:
        Tuple of (risk_level, risk_description) or (None, None) if not found
    """
    if not isinstance(event_code, str) or pd.isna(event_code) or event_code.strip() == "":
        return None, None

    event_code = event_code.strip().upper()

    # Get SAP's classification for this event code
    classification = event_classifications.get(event_code)

    if classification == 'Critical':
        return 'High', f"High-risk system activity: This event is classified by SAP as requiring immediate attention. [Technical: SAP Critical Event: {event_code}]"
    elif classification == 'Important':
        return 'Medium', f"Activity requiring review: This event is classified by SAP as important for security analysis. [Technical: SAP Important Event: {event_code}]"
    elif classification == 'Non-Critical':
        return 'Low', f"Routine system activity: This event is classified by SAP as normal operational activity. [Technical: SAP Non-Critical Event: {event_code}]"
    else:
        return None, None

def analyze_event_details(row, event_descriptions):
    """
    Analyze event details to extract additional context.
    Provides clear explanations for non-technical reviewers.

    Args:
        row: DataFrame row containing event data
        event_descriptions: Dictionary with event code descriptions

    Returns:
        Additional context string based on event type
    """
    event_code = row.get('Event', '')

    if not isinstance(event_code, str) or pd.isna(event_code) or event_code.strip() == "":
        return ""

    event_code = event_code.strip().upper()

    # Get variable data with proper null handling
    var_first = str(row.get('Variable_First', '')) if pd.notna(row.get('Variable_First', '')) else 'N/A'
    var_2 = str(row.get('Variable_2', '')) if pd.notna(row.get('Variable_2', '')) else 'N/A'
    var_3 = str(row.get('Variable_3', '')) if pd.notna(row.get('Variable_3', '')) else 'N/A'
    var_data = str(row.get('Variable_Data', '')) if pd.notna(row.get('Variable_Data', '')) else 'N/A'

    # Check for login events
    if event_code == 'AU1':  # Successful login
        login_type = 'N/A' if var_first == 'N/A' or var_first.strip() == '' else var_first
        login_method = 'N/A' if var_3 == 'N/A' or var_3.strip() == '' else var_3
        return f"User successfully logged into the system using {login_method if login_method != 'N/A' else 'standard'} authentication. [Technical: Login Type={login_type}, Method={login_method}]"

    # Check for RFC events
    elif event_code == 'AUK':  # Successful RFC call
        func_group = 'N/A' if var_first == 'N/A' or var_first.strip() == '' else var_first
        func_name = 'N/A' if var_data == 'N/A' or var_data.strip() == '' else var_data
        return f"User accessed a remote system function that allows interaction between different systems. [Technical: Function={func_name}, Group={func_group}]"

    # Check for failed login events
    elif event_code == 'AU2':  # Failed login
        reason = 'N/A' if var_2 == 'N/A' or var_2.strip() == '' else var_2
        return f"Failed login attempt - This could indicate a password mistake or a potential unauthorized access attempt. [Technical: Failure Reason={reason}]"

    # Application started
    elif event_code == 'CUI':
        app_name = 'N/A' if var_first == 'N/A' or var_first.strip() == '' else var_first
        return f"User started an application or program within SAP. [Technical: Application={app_name}]"

    # For other event types, provide a more generic context
    if var_first != 'N/A' and var_first.strip() != '':
        return f"Additional system activity details available. [Technical: Variable Data: {var_first}]"

    return ""
