#!/usr/bin/env python3
"""
Update Output Logic - Fix Debug Activity Filtering

This script updates the output generation logic to correctly filter debug activities.
It separates true debugging activities from normal service interface calls in the output.
"""

import os
import sys
import re

# Add the parent directory to sys.path to import the module
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "OneDrive", "Documents", "Python")
sys.path.append(PYTHON_DIR)

def update_output_file():
    """Update the output module with improved debug activity filtering."""
    output_file = os.path.join(PYTHON_DIR, "sap_audit_tool_output.py")
    
    if not os.path.exists(output_file):
        print(f"Error: Output file not found at {output_file}")
        return False
    
    print(f"Found output file: {output_file}")
    
    # Read the current content
    with open(output_file, 'r') as f:
        content = f.read()
    
    # Create a backup
    backup_file = f"{output_file}.bak"
    with open(backup_file, 'w') as f:
        f.write(content)
    print(f"Created backup at {backup_file}")
    
    # Find the problem filter pattern to replace
    old_pattern = """debug_events = session_filtered[
                    (session_filtered['Variable_2'].str.contains('I!|D!|G!', na=False)) | 
                    (session_filtered['Variable_First'].str.contains('R3TR', na=False)) |
                    (session_filtered['Variable_Data'].str.contains('/sap/opu/odata/', na=False)) |
                    (session_filtered['risk_factors'].str.contains('debug|debugging|dynamic abap|gateway|rfc', case=False, na=False))
                ]"""
    
    # Define the improved filter
    new_filter = """debug_events = session_filtered[
                    # Only actual debug activities with debug markers
                    (session_filtered['Variable_2'].str.contains('I!|D!|G!', na=False)) |
                    
                    # FireFighter accounts with high risk activities
                    ((session_filtered['User'].str.startswith('FF_', na=False)) & 
                     (session_filtered['risk_level'].isin(['High', 'Critical']))) |
                    
                    # Explicit debug mentioned in risk factors (true debugging only)
                    (session_filtered['risk_factors'].str.contains('debug session detected|dynamic abap code execution', 
                                                                 case=False, na=False))
                ]"""
    
    # Replace the filter in the content
    updated_content = content.replace(old_pattern, new_filter)
    
    if updated_content == content:
        print("Warning: No changes were made. Pattern may not have matched.")
        
        # Try a more flexible pattern match
        import re
        debug_filter_pattern = r"debug_events\s+=\s+session_filtered\[\s+\(session_filtered\['Variable_2'\].str.contains.*?risk_factors.*?\)\s+\]"
        
        # Replace using regex with DOTALL to match across lines
        updated_content = re.sub(debug_filter_pattern, new_filter, content, flags=re.DOTALL)
        
        if updated_content == content:
            print("Warning: Second attempt to match pattern also failed.")
            return False
    
    # Write the updated content
    with open(output_file, 'w') as f:
        f.write(updated_content)
    
    print(f"Successfully updated {output_file}")
    print("Fixed Debug Activities filter to only include true debugging entries")
    
    # Add debug count and categorization output
    add_debug_count_output = """                    
                    # Count records by category for analysis
                    debug_count = len(debug_events)
                    true_debug_markers = len(debug_events[debug_events['Variable_2'].str.contains('I!|D!|G!', na=False)])
                    firefighter_high_risk = len(debug_events[
                        (debug_events['User'].str.startswith('FF_', na=False)) & 
                        (debug_events['risk_level'].isin(['High', 'Critical']))
                    ])
                    
                    log_message(f"Debug activity statistics:")
                    log_message(f"  - True debug markers (I!, D!, G!): {true_debug_markers}")
                    log_message(f"  - FireFighter high risk activities: {firefighter_high_risk}")
                    log_message(f"  - Total debug activities: {debug_count}")"""
    
    # Find position to insert this before debug_events_fixed = debug_events.fillna('')
    insert_point = "debug_events_fixed = debug_events.fillna('')"
    updated_content = updated_content.replace(insert_point, add_debug_count_output + "\n                    " + insert_point)
    
    # Write the updated content
    with open(output_file, 'w') as f:
        f.write(updated_content)
    
    print("Added detailed debug activity statistics output")
    
    return True

if __name__ == "__main__":
    print("=== SAP Log Analyzer - Output Logic Update ===")
    update_output_file()
    print("\nUpdate complete. Please restart the SAP Audit Tool to apply changes.")
