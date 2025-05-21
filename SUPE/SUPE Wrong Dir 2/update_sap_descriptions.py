#!/usr/bin/env python3
"""
SAP Descriptions Updater

This script helps maintain the table, transaction code, and field descriptions
used by the SAP Audit Tool. It analyzes the session timeline file to identify 
elements without descriptions and provides an automated way to add them.

Usage:
  python update_sap_descriptions.py [--analyze|--update]

Options:
  --analyze   Analyze the session timeline to identify missing descriptions (default)
  --update    Update the risk assessment module with new descriptions
"""

import pandas as pd
import sys
import os
import re
from pathlib import Path

# Script configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "OneDrive", "Documents", "Python")
SAP_MODULE_PATH = os.path.join(PYTHON_DIR, "sap_audit_tool_risk_assessment.py")
SESSION_TIMELINE_PATH = os.path.join(PYTHON_DIR, "SAP_Session_Timeline.xlsx")

# Import the dictionaries from the risk assessment module
sys.path.append(os.path.dirname(SCRIPT_DIR))
from OneDrive.Documents.Python.sap_audit_tool_risk_assessment import (
    get_common_table_descriptions, 
    get_sensitive_table_descriptions,
    get_common_tcode_descriptions,
    get_sensitive_tcode_descriptions,
    get_common_field_descriptions
)

def analyze_session_timeline():
    """Analyze the session timeline to identify elements without descriptions."""
    print(f"Reading session timeline: {SESSION_TIMELINE_PATH}")
    try:
        df = pd.read_excel(SESSION_TIMELINE_PATH, sheet_name='Session_Timeline')
        print(f"Total rows: {len(df)}")
    except Exception as e:
        print(f"Error reading session timeline: {str(e)}")
        return

    # Load existing dictionaries
    common_tables = get_common_table_descriptions()
    sensitive_tables = get_sensitive_table_descriptions()
    common_tcodes = get_common_tcode_descriptions()
    sensitive_tcodes = get_sensitive_tcode_descriptions()
    common_fields = get_common_field_descriptions()
    
    # Combine dictionaries
    all_tables = {k.upper(): v for k, v in {**common_tables, **sensitive_tables}.items()}
    all_tcodes = {k.upper(): v for k, v in {**common_tcodes, **sensitive_tcodes}.items()}
    all_fields = {k.upper(): v for k, v in common_fields.items()}
    
    # Extract unique values
    tables = df['Table'].dropna().astype(str).str.strip().unique()
    tcodes = df['TCode'].dropna().astype(str).str.strip().unique()
    fields = df['Field'].dropna().astype(str).str.strip().unique()
    
    print(f"\nFound {len(tables)} unique tables")
    print(f"Found {len(tcodes)} unique transaction codes")
    print(f"Found {len(fields)} unique fields")
    
    # Find elements without descriptions
    missing_tables = [t for t in tables if t.upper() not in all_tables and t.strip() and t != "nan"]
    missing_tcodes = [t for t in tcodes if t.upper() not in all_tcodes and t.strip() and t != "nan"]
    missing_fields = [f for f in fields if f.upper() not in all_fields and f.strip() and f != "nan"]
    
    # Calculate frequency of missing elements
    table_counts = df['Table'].value_counts()
    tcode_counts = df['TCode'].value_counts()
    field_counts = df['Field'].value_counts()
    
    # Filter to only those without descriptions
    missing_table_counts = {t: table_counts.get(t, 0) for t in missing_tables}
    missing_tcode_counts = {t: tcode_counts.get(t, 0) for t in missing_tcodes}
    missing_field_counts = {f: field_counts.get(f, 0) for f in missing_fields}
    
    # Sort by frequency (most common first)
    sorted_tables = sorted(missing_table_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_tcodes = sorted(missing_tcode_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_fields = sorted(missing_field_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Print results
    print(f"\nTables without descriptions: {len(missing_tables)}")
    print(f"Transaction codes without descriptions: {len(missing_tcodes)}")
    print(f"Fields without descriptions: {len(missing_fields)}")
    
    if len(sorted_tables) > 0:
        print("\nTop 10 tables without descriptions:")
        for i, (table, count) in enumerate(sorted_tables[:10], 1):
            print(f"{i}. {table} ({count} occurrences)")
    
    if len(sorted_tcodes) > 0:
        print("\nTop 10 transaction codes without descriptions:")
        for i, (tcode, count) in enumerate(sorted_tcodes[:10], 1):
            print(f"{i}. {tcode} ({count} occurrences)")
    
    if len(sorted_fields) > 0:
        print("\nTop 10 fields without descriptions:")
        for i, (field, count) in enumerate(sorted_fields[:10], 1):
            print(f"{i}. {field} ({count} occurrences)")
    
    # Generate dictionary code snippets for the most common missing items
    if len(sorted_tables) > 0 or len(sorted_tcodes) > 0 or len(sorted_fields) > 0:
        print("\n--- DICTIONARY CODE SNIPPETS ---")
        
        if len(sorted_tables) > 0:
            print("\n# Table descriptions to add:")
            for table, count in sorted_tables[:20]:  # Top 20
                print(f'    "{table}": "{table} - [Add description here]",')
        
        if len(sorted_tcodes) > 0:
            print("\n# Transaction code descriptions to add:")
            for tcode, count in sorted_tcodes[:20]:  # Top 20
                print(f'    "{tcode}": "{tcode} - [Add description here]",')
        
        if len(sorted_fields) > 0:
            print("\n# Field descriptions to add:")
            for field, count in sorted_fields[:20]:  # Top 20
                print(f'    "{field}": "{field} - [Add description here]",')

def update_descriptions():
    """Update the risk assessment module with new descriptions."""
    print("To add new descriptions to the SAP Audit Tool:")
    print("1. Open sap_audit_tool_risk_assessment.py")
    print("2. Find the appropriate dictionary function:")
    print("   - get_common_table_descriptions() for tables")
    print("   - get_common_tcode_descriptions() for transaction codes")
    print("   - get_common_field_descriptions() for fields")
    print("3. Add the new descriptions in the same format:")
    print('   "TABLE_NAME": "Table Name - Description of what it contains",')
    print("4. Save the file and run the SAP Audit Tool again")
    print("\nNote: If you're adding a sensitive table/tcode, add it to the sensitive dictionaries instead.")

def main():
    """Main function to execute the script."""
    # Parse command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        update_descriptions()
    else:
        analyze_session_timeline()

if __name__ == "__main__":
    main()
