#!/usr/bin/env python3
"""
Fix script for correcting remaining issues in SAP Audit Tool.
"""

import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
risk_module_path = os.path.join(SCRIPT_DIR, "sap_audit_tool_risk_assessment.py")

# Read the original file
with open(risk_module_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the security pattern to properly match PASSWORD
# Update the KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC) pattern to catch all security-related fields
key_pattern_original = r'patterns[r"(?i)KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC)"] = "Security key field"'
key_pattern_fixed = r'patterns[r"(?i)(KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC)|PASSWORD)"] = "Security key field"'

content = content.replace(key_pattern_original, key_pattern_fixed)

# Fix the description pattern to match
key_desc_original = r'descriptions[r"(?i)KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC)"] = "Security key/token'
key_desc_fixed = r'descriptions[r"(?i)(KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC)|PASSWORD)"] = "Security key/token'

content = content.replace(key_desc_original, key_desc_fixed)

# Fix the risk assessment lambda function to handle the common_field_descriptions properly
# We need to fix the scope issue by properly loading the common_field_descriptions
table_risk_original = r"""risk_df.loc[table_mask, 'risk_factors'] = risk_df.loc[table_mask].apply(
                        lambda row: f"{description} (Table: {table}" + (f", Field: {get_field_info(row[SESSION_FIELD_COL], common_field_descriptions)}" if pd.notna(row[SESSION_FIELD_COL]) and row[SESSION_FIELD_COL].strip() != "" else "") + ")",
                        axis=1)"""

table_risk_fixed = r"""# Get field descriptions for referencing in the lambda
                    common_field_desc = get_common_field_descriptions()
                    risk_df.loc[table_mask, 'risk_factors'] = risk_df.loc[table_mask].apply(
                        lambda row: f"{description} (Table: {table}" + (f", Field: {get_field_info(row[SESSION_FIELD_COL], common_field_desc)}" if pd.notna(row[SESSION_FIELD_COL]) and row[SESSION_FIELD_COL].strip() != "" else "") + ")",
                        axis=1)"""

content = content.replace(table_risk_original, table_risk_fixed)

# Fix any syntax errors in lambda function - check for missing commas
risk_df_pattern = r"risk_df.loc\[table_mask 'risk_factors'\]"
risk_df_fixed = r"risk_df.loc[table_mask, 'risk_factors']"
content = content.replace(risk_df_pattern, risk_df_fixed)

# Write the updated content back to the file
with open(risk_module_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Successfully fixed remaining pattern matching and risk assessment issues.")
