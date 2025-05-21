#!/usr/bin/env python3
"""
Script to combine all parts of the SAP Audit Tool into a single file.
"""

import os

# Define the parts to combine
parts = [
    "../OneDrive/Documents/Python/sap_audit_tool_refactored_part1.py",
    "../OneDrive/Documents/Python/sap_audit_tool_refactored_part2.py",
    "../OneDrive/Documents/Python/sap_audit_tool_refactored_part3.py",
    "../OneDrive/Documents/Python/sap_audit_tool_refactored_part4.py",
    "../OneDrive/Documents/Python/sap_audit_tool_refactored_part5.py",
    "../OneDrive/Documents/Python/sap_audit_tool_refactored_part6.py"
]

# Define the output file
output_file = "../OneDrive/Documents/Python/sap_audit_tool_refactored.py"

# Combine the parts
with open(output_file, 'w', encoding='utf-8') as outfile:
    for part in parts:
        if os.path.exists(part):
            with open(part, 'r', encoding='utf-8') as infile:
                # Skip the shebang and docstring for all but the first file
                if part != parts[0]:
                    # Skip lines until we find a line that's not a comment, shebang, or empty
                    for line in infile:
                        if not (line.startswith('#') or line.startswith('"""') or line.strip() == ''):
                            outfile.write(line)
                            break
                # Write the rest of the file
                outfile.write(infile.read())
                outfile.write('\n\n')
        else:
            print(f"Warning: Part {part} not found.")

print(f"Combined file created at: {output_file}")
