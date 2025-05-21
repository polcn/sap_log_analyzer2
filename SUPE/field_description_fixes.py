#!/usr/bin/env python3
"""
SAP Audit Tool - Field Description Fixes

This script fixes issues identified during the field description testing:
1. Improves pattern matching for field detection
2. Enhances risk assessment to include field descriptions in risk factors
"""

import os
import sys
import re
import inspect

# Add script directory to Python path for module imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

def fix_field_pattern_matching():
    """
    Fix field pattern matching issues.
    
    The issue is that \b word boundary in regex doesn't match when there's an underscore
    adjacent to the word. This function updates the patterns to better handle field names
    with underscores.
    """
    # Path to the risk assessment module
    risk_module_path = os.path.join(SCRIPT_DIR, "sap_audit_tool_risk_assessment.py")
    
    # Read the module content
    with open(risk_module_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Look for the get_critical_field_patterns function
    pattern_start = content.find("def get_critical_field_patterns()")
    pattern_end = content.find("def get_critical_field_pattern_descriptions()")
    
    if pattern_start == -1 or pattern_end == -1:
        print("Could not find pattern functions in the risk assessment module.")
        return False
    
    # Extract the function content
    pattern_function = content[pattern_start:pattern_end]
    
    # Find patterns using \b (word boundary) and modify them
    # For example: r"(?i)\bROLE\b" → r"(?i)(?<![A-Za-z0-9_])ROLE(?![A-Za-z0-9_])"
    # This properly handles words with adjacent underscores
    
    # Regular expression to find patterns with \b
    pattern_regex = r'r"(\(\?i\))\\b([A-Za-z0-9_]+?)(?:\\b|\\\(.+?\)\\b)'
    
    # Function to replace with more robust pattern
    def replace_pattern(match):
        case_insensitive = match.group(1)
        word = match.group(2)
        
        # Extract any trailing part after the word
        trailing_part = ""
        if "(" in match.group(0):
            trailing_part = match.group(0).split(word, 1)[1].rstrip('"')
        
        # Create a new pattern that handles underscores better
        if "(" in trailing_part:
            # More complex patterns need to be handled carefully
            return f'r"{case_insensitive}(?<![A-Za-z0-9_]){word}{trailing_part}'
        else:
            # Simple word boundary replacement
            return f'r"{case_insensitive}(?<![A-Za-z0-9_]){word}(?![A-Za-z0-9_])"'
    
    # Replace the patterns
    updated_pattern_function = re.sub(pattern_regex, replace_pattern, pattern_function)
    
    # Check if changes were made
    if updated_pattern_function == pattern_function:
        print("No pattern changes needed.")
        return False
    
    # Update the content
    updated_content = content[:pattern_start] + updated_pattern_function + content[pattern_end:]
    
    # Write back the updated content
    with open(risk_module_path, 'w', encoding='utf-8') as f:
        f.write(updated_content)
    
    print("Updated field patterns for better matching with underscores.")
    return True

def enhance_field_risk_assessment():
    """
    Enhance risk assessment to include field descriptions in risk factors.
    
    The issue is that when a field matches a pattern or is in a high-risk table,
    the specific field description isn't included in the risk factors.
    """
    # Path to the risk assessment module
    risk_module_path = os.path.join(SCRIPT_DIR, "sap_audit_tool_risk_assessment.py")
    
    # Read the module content
    with open(risk_module_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Locate the pattern where field risk assessment happens in assess_risk_session function
    # This might be a bit fragile, so we'll look for a recognizable pattern
    
    # Find the place where table risk is applied to fields
    table_risk_pattern = "description = table_descriptions.get(table, f\"Sensitive table '{table}' - Contains critical system data\")"
    table_risk_index = content.find(table_risk_pattern)
    
    if table_risk_index != -1:
        # Find the line where risk factors are assigned
        next_line = content.find("risk_df.loc[table_mask, 'risk_factors']", table_risk_index)
        
        if next_line != -1:
            # Find the line end
            line_end = content.find("\n", next_line)
            
            # Get the original line
            original_line = content[next_line:line_end]
            
            # Create the enhanced line that includes field information
            enhanced_line = original_line.replace("}", ", field=None}", 1)
            enhanced_line = enhanced_line.replace("f\"{description} (Table: {table})", 
                                                 "f\"{description} (Table: {table}{' | Field: ' + get_field_info(field, common_field_descriptions) if field else ''})")
            
            # Replace the line
            content = content[:next_line] + enhanced_line + content[line_end:]
            
            print("Enhanced table risk assessment to include field descriptions.")
        else:
            print("Could not find the risk factor assignment line.")
            return False
    else:
        print("Could not find the table risk pattern.")
        return False
    
    # Write back the updated content
    with open(risk_module_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("Enhanced risk assessment to include field descriptions.")
    return True

def main():
    """Main function to apply fixes."""
    print("=== SAP Audit Tool Field Description Fixes ===")
    
    # Fix field pattern matching
    pattern_result = fix_field_pattern_matching()
    
    # Enhance field risk assessment
    risk_result = enhance_field_risk_assessment()
    
    if pattern_result and risk_result:
        print("\nAll fixes successfully applied!")
        return 0
    else:
        print("\nSome fixes could not be applied. Check the logs for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
