#!/usr/bin/env python3
"""
Quick fix for the syntax errors in the pattern definitions.
"""

import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
risk_module_path = os.path.join(SCRIPT_DIR, "sap_audit_tool_risk_assessment.py")

print("Fixing syntax errors in field patterns...")

# Read the file
with open(risk_module_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Pattern to find the problematic definition
pattern_func_start = content.find("def get_critical_field_patterns()")
pattern_func_end = content.find("def get_critical_field_pattern_descriptions()")

if pattern_func_start == -1 or pattern_func_end == -1:
    print("Could not find the pattern functions!")
    exit(1)

# Extract the function content
patterns_content = content[pattern_func_start:pattern_func_end]

# Fix the syntax errors by replacing extra quotes
fixed_patterns = re.sub(r'r"(\(\?i\)\(\?<!\[A-Za-z0-9_\]\)[A-Za-z0-9_]+\(\?!\[A-Za-z0-9_\]\))"', r'r"\1"', patterns_content)

# Check if we need to manually fix specific patterns
if ')"":' in fixed_patterns:
    fixed_patterns = fixed_patterns.replace(')"":"', ')":', 1)
    # Apply the fix for all occurrences
    while ')"":' in fixed_patterns:
        fixed_patterns = fixed_patterns.replace(')"":"', ')":', 1)

# Update the file content
updated_content = content[:pattern_func_start] + fixed_patterns + content[pattern_func_end:]

# Write back to the file
with open(risk_module_path, 'w', encoding='utf-8') as f:
    f.write(updated_content)

print("Fixed pattern syntax errors! Let's try running the tests again.")
