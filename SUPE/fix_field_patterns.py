#!/usr/bin/env python3
"""
Fix script for correcting field pattern matching issues in SAP Audit Tool.
"""

import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
risk_module_path = os.path.join(SCRIPT_DIR, "sap_audit_tool_risk_assessment.py")

# Read the original file
with open(risk_module_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Define the corrected field pattern functions
corrected_patterns_function = """def get_critical_field_patterns():
    \"\"\"Return patterns for critical fields that should be monitored closely.\"\"\"
    patterns = {}
    
    # Authentication and authorization fields
    patterns[r"(?i)PASS(WORD)?"] = "Password field"
    patterns[r"(?i)AUTH(ORIZATION)?"] = "Authorization field"
    patterns[r"(?i)ROLE"] = "Role assignment field"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    patterns[r"(?i)PERM(ISSION)?(?<!SPERM)"] = "Permission field"
    patterns[r"(?i)ACCESS"] = "Access control field"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    patterns[r"(?i)KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC)"] = "Security key field"
    patterns[r"(?i)CRED(ENTIAL)?"] = "Credential field"
    
    # Financial fields
    patterns[r"(?i)AMOUNT"] = "Financial amount field"
    patterns[r"(?i)CURR(ENCY)?"] = "Currency field" 
    patterns[r"(?i)BANK"] = "Banking information field"
    patterns[r"(?i)ACCOUNT"] = "Account field"
    patterns[r"(?i)PAYMENT"] = "Payment field"
    
    # Master data fields
    patterns[r"(?i)VENDOR"] = "Vendor master data field"
    patterns[r"(?i)CUSTOMER"] = "Customer master data field"
    patterns[r"(?i)EMPLOYEE"] = "Employee data field"
    
    # System configuration
    patterns[r"(?i)CONFIG"] = "Configuration field"
    patterns[r"(?i)SETTING"] = "System setting field"
    patterns[r"(?i)PARAM(ETER)?"] = "Parameter field"
    
    return patterns"""

corrected_descriptions_function = """def get_critical_field_pattern_descriptions():
    \"\"\"Return detailed descriptions for critical field patterns.\"\"\"
    descriptions = {}
    
    # Authentication and authorization fields
    descriptions[r"(?i)PASS(WORD)?"] = "Password/credential modification - Security sensitive change affecting user authentication"
    descriptions[r"(?i)AUTH(ORIZATION)?"] = "Authorization configuration - Security permission change affecting system access control"
    descriptions[r"(?i)ROLE"] = "Role configuration - Security access control change affecting user permissions scope"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    descriptions[r"(?i)PERM(ISSION)?(?<!SPERM)"] = "Permission settings - Access control modification affecting security boundaries"
    descriptions[r"(?i)ACCESS"] = "Access control field - Field controlling system or resource availability"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    descriptions[r"(?i)KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC)"] = "Security key/token - Infrastructure change affecting encryption or authentication"
    descriptions[r"(?i)CRED(ENTIAL)?"] = "Credential field - Authentication data that may grant system access"
    
    # Financial fields
    descriptions[r"(?i)AMOUNT"] = "Financial amount field - Monetary value change affecting financial transactions"
    descriptions[r"(?i)CURR(ENCY)?"] = "Currency field - Financial data type affecting monetary calculations"
    descriptions[r"(?i)BANK"] = "Banking details - Payment routing information change affecting transactions"
    descriptions[r"(?i)ACCOUNT"] = "Account field - Financial or user account record modification"
    descriptions[r"(?i)PAYMENT"] = "Payment field - Financial transaction data affecting money movement"
    
    # Master data fields
    descriptions[r"(?i)VENDOR"] = "Vendor master data field - Supplier information affecting procurement processes"
    descriptions[r"(?i)CUSTOMER"] = "Customer master data field - Client information affecting sales processes"
    descriptions[r"(?i)EMPLOYEE"] = "Employee data field - Personnel information affecting HR processes"
    
    # System configuration
    descriptions[r"(?i)CONFIG"] = "Configuration field - System setting affecting overall system behavior"
    descriptions[r"(?i)SETTING"] = "System setting field - Parameter controlling system functionality"
    descriptions[r"(?i)PARAM(ETER)?"] = "Parameter field - System configuration option affecting behavior"
    
    return descriptions"""

# Find and replace the pattern functions
patterns_start = content.find("def get_critical_field_patterns()")
patterns_end = content.find("def get_critical_field_pattern_descriptions()")
descriptions_start = patterns_end
descriptions_end = content.find("def get_field_info(", descriptions_start)

if patterns_start == -1 or patterns_end == -1 or descriptions_start == -1 or descriptions_end == -1:
    print("Error: Could not find the pattern functions in the file.")
    exit(1)

# Replace the functions
new_content = content[:patterns_start] + corrected_patterns_function + "\n\n" + \
              corrected_descriptions_function + "\n\n" + \
              content[descriptions_end:]

# Fix the risk assessment to include field descriptions in table-based assessments
table_risk_original = "risk_df.loc[table_mask, 'risk_factors'] = f\"{description} (Table: {table})\""
table_risk_fixed = r"""risk_df.loc[table_mask, 'risk_factors'] = risk_df.loc[table_mask].apply(
                        lambda row: f"{description} (Table: {table}" + (f", Field: {get_field_info(row[SESSION_FIELD_COL], common_field_descriptions)}" if pd.notna(row[SESSION_FIELD_COL]) and row[SESSION_FIELD_COL].strip() != "" else "") + ")",
                        axis=1)"""

# Replace the risk factors assignment
new_content = new_content.replace(table_risk_original, table_risk_fixed)

# Write the updated content back to the file
with open(risk_module_path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print("Successfully fixed field pattern matching and risk assessment issues.")
