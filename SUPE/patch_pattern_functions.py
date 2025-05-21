#!/usr/bin/env python3
"""
Patch script to fix pattern functions in the risk assessment module.
This script completely replaces the problematic functions with working versions.
"""

import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
risk_module_path = os.path.join(SCRIPT_DIR, "sap_audit_tool_risk_assessment.py")

# Read the original file
with open(risk_module_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Define the new pattern functions
new_patterns_function = """def get_critical_field_patterns():
    \"\"\"Return patterns for critical fields that should be monitored closely.\"\"\"
    patterns = {}
    
    # Authentication and authorization fields
    patterns[r"(?i)\\bPASS(WORD)?\\b"] = "Password field"
    patterns[r"(?i)\\bAUTH(ORIZATION)?\\b"] = "Authorization field"
    patterns[r"(?i)(?<![A-Za-z0-9_])ROLE(?![A-Za-z0-9_])"] = "Role assignment field"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    patterns[r"(?i)\\bPERM(ISSION)?\\b(?<!SPERM)"] = "Permission field"
    patterns[r"(?i)(?<![A-Za-z0-9_])ACCESS(?![A-Za-z0-9_])"] = "Access control field"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    patterns[r"(?i)\\b(?!KEY$).*KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC).*\\b"] = "Security key field"
    patterns[r"(?i)\\bCRED(ENTIAL)?\\b"] = "Credential field"
    
    # Financial fields
    patterns[r"(?i)(?<![A-Za-z0-9_])AMOUNT(?![A-Za-z0-9_])"] = "Financial amount field"
    patterns[r"(?i)\\bCURR(ENCY)?\\b"] = "Currency field" 
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
    patterns[r"(?i)\\bPARAM(ETER)?\\b"] = "Parameter field"
    
    return patterns"""

new_descriptions_function = """def get_critical_field_pattern_descriptions():
    \"\"\"Return detailed descriptions for critical field patterns.\"\"\"
    descriptions = {}
    
    # Authentication and authorization fields
    descriptions[r"(?i)\\bPASS(WORD)?\\b"] = "Password/credential modification - Security sensitive change affecting user authentication"
    descriptions[r"(?i)\\bAUTH(ORIZATION)?\\b"] = "Authorization configuration - Security permission change affecting system access control"
    descriptions[r"(?i)(?<![A-Za-z0-9_])ROLE(?![A-Za-z0-9_])"] = "Role configuration - Security access control change affecting user permissions scope"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    descriptions[r"(?i)\\bPERM(ISSION)?\\b(?<!SPERM)"] = "Permission settings - Access control modification affecting security boundaries"
    descriptions[r"(?i)(?<![A-Za-z0-9_])ACCESS(?![A-Za-z0-9_])"] = "Access control field - Field controlling system or resource availability"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    descriptions[r"(?i)\\b(?!KEY$).*KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC).*\\b"] = "Security key/token - Infrastructure change affecting encryption or authentication"
    descriptions[r"(?i)\\bCRED(ENTIAL)?\\b"] = "Credential field - Authentication data that may grant system access"
    
    # Financial fields
    descriptions[r"(?i)(?<![A-Za-z0-9_])AMOUNT(?![A-Za-z0-9_])"] = "Financial amount field - Monetary value change affecting financial transactions"
    descriptions[r"(?i)\\bCURR(ENCY)?\\b"] = "Currency field - Financial data type affecting monetary calculations"
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
    descriptions[r"(?i)\\bPARAM(ETER)?\\b"] = "Parameter field - System configuration option affecting behavior"
    
    return descriptions"""

# Replace the pattern functions in the file
patterns_start = content.find("def get_critical_field_patterns()")
patterns_end = content.find("def get_critical_field_pattern_descriptions()")
descriptions_start = patterns_end
descriptions_end = content.find("def get_field_info(", descriptions_start)

if patterns_start == -1 or patterns_end == -1 or descriptions_start == -1 or descriptions_end == -1:
    print("Error: Could not find the pattern functions in the file.")
    exit(1)

# Replace the functions
new_content = content[:patterns_start] + new_patterns_function + "\n\n" + \
              new_descriptions_function + "\n\n" + \
              content[descriptions_end:]

# Write the updated content back to the file
with open(risk_module_path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print("Successfully patched the pattern functions in the risk assessment module.")
