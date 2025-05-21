#!/usr/bin/env python3
"""
Update Risk Assessment - Fix Debug Activity Classification

This script updates the risk assessment logic to correctly classify debug activities.
It separates true debugging activities from normal service interface calls.
"""

import os
import sys
import re

# Add the parent directory to sys.path to import the module
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "OneDrive", "Documents", "Python")
sys.path.append(PYTHON_DIR)

try:
    # Import the module to verify it can be loaded
    from sap_audit_tool_risk_assessment import log_message, detect_debug_patterns
    print(f"Successfully imported sap_audit_tool_risk_assessment module")
except ImportError as e:
    print(f"Error importing module: {str(e)}")
    sys.exit(1)

def update_risk_assessment_file():
    """Update the risk assessment module with improved debug pattern detection."""
    risk_assessment_file = os.path.join(PYTHON_DIR, "sap_audit_tool_risk_assessment.py")
    
    if not os.path.exists(risk_assessment_file):
        print(f"Error: Risk assessment file not found at {risk_assessment_file}")
        return False
    
    print(f"Found risk assessment file: {risk_assessment_file}")
    
    # Read the current content
    with open(risk_assessment_file, 'r') as f:
        content = f.read()
    
    # Create a backup
    backup_file = f"{risk_assessment_file}.bak"
    with open(backup_file, 'w') as f:
        f.write(content)
    print(f"Created backup at {backup_file}")
    
    # Find and replace the detect_debug_patterns function
    old_function_pattern = r'def detect_debug_patterns\(row\):.*?return None, risk_factors'
    
    # Define the updated function
    new_function = '''def detect_debug_patterns(row):
    """
    Detect debugging and RFC patterns in SM20 logs.
    Separates true debugging activities from normal service interface calls.
    
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
    
    # TRUE Debug event detection (I!, D!, G! flags)
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
        if var_2 in ['I!', 'D!', 'G!']:  # Only high risk for true debugging
            risk_factors.append(f"FireFighter account performing privileged action ({var_2}) - Elevated risk due to privileged access")
            return 'Critical', risk_factors
        else:
            risk_factors.append(f"FireFighter account accessing service interfaces - Standard but privileged activity")
            return 'Medium', risk_factors
    
    # Service interface detection - normal operations, separate from debugging
    if 'R3TR IWSV' in var_first or 'R3TR IWSG' in var_first:
        risk_factors.append("Service interface access - Standard OData or API gateway activity")
        return 'Low', risk_factors  # Lower risk level for normal operations
    
    # Gateway framework detection - normal operations, separate from debugging  
    if 'R3TR G4BA' in var_first:
        risk_factors.append("Gateway framework access - Standard SAP Gateway activity")
        return 'Low', risk_factors
    
    # OData endpoint patterns - normal operations but potentially sensitive
    if '/sap/opu/odata/' in var_data:
        risk_factors.append("OData endpoint access - API-based data access")
        return 'Medium', risk_factors
    
    return None, risk_factors'''
    
    # Replace using regex with DOTALL to match across lines
    updated_content = re.sub(old_function_pattern, new_function, content, flags=re.DOTALL)
    
    if updated_content == content:
        print("Warning: No changes were made. Function pattern may not have matched.")
        return False
    
    # Write the updated content
    with open(risk_assessment_file, 'w') as f:
        f.write(updated_content)
    
    print(f"Successfully updated {risk_assessment_file}")
    print("Added clear separation between true debugging activities and service interface calls")
    
    # Print a diff-like summary
    print("\nKey changes made:")
    print("1. TRUE Debug event detection now only matches actual debug markers (I!, D!, G!)")
    print("2. Service interface calls now categorized as 'Low' risk standard operations")
    print("3. FireFighter accounts have risk level based on actual activities")
    print("4. Gateway framework access now properly categorized separately from debugging")
    
    return True

if __name__ == "__main__":
    print("=== SAP Log Analyzer - Debug Classification Update ===")
    update_risk_assessment_file()
    print("\nUpdate complete. Please restart the SAP Audit Tool to apply changes.")
