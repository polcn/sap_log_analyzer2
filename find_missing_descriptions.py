import pandas as pd
import sys
import os

# Import the dictionaries from the risk assessment module
from sap_audit_tool_risk_assessment import (
    get_common_table_descriptions,
    get_sensitive_table_descriptions,
    get_common_tcode_descriptions,
    get_sensitive_tcode_descriptions,
    get_common_field_descriptions
)

# File to analyze
file_path = r"C:\Users\craig\OneDrive\Documents\Python\SAP_Session_Timeline.xlsx"

# Load existing dictionaries
common_tables = get_common_table_descriptions()
sensitive_tables = get_sensitive_table_descriptions()
common_tcodes = get_common_tcode_descriptions()
sensitive_tcodes = get_sensitive_tcode_descriptions()
common_fields = get_common_field_descriptions()

# Combine dictionaries
all_tables = {**common_tables, **sensitive_tables}
all_tcodes = {**common_tcodes, **sensitive_tcodes}
all_fields = common_fields

def analyze_timeline():
    """Analyze the session timeline and identify all fields with their descriptions status."""
    print(f"Reading file: {file_path}")
    df = pd.read_excel(file_path, sheet_name='Session_Timeline')
    print(f"Total rows: {len(df)}")
    
    # Extract unique values
    tables = df['Table'].dropna().astype(str).str.strip().unique()
    tcodes = df['TCode'].dropna().astype(str).str.strip().unique()
    fields = df['Field'].dropna().astype(str).str.strip().unique()
    
    # Remove 'nan' values
    tables = [t for t in tables if t != "nan" and t.strip()]
    tcodes = [t for t in tcodes if t != "nan" and t.strip()]
    fields = [f for f in fields if f != "nan" and f.strip()]
    
    print(f"\nFound {len(tables)} unique tables")
    print(f"Found {len(tcodes)} unique transaction codes")
    print(f"Found {len(fields)} unique fields")
    
    # Get frequency counts
    table_counts = df['Table'].value_counts()
    tcode_counts = df['TCode'].value_counts()
    field_counts = df['Field'].value_counts()
    
    # Find tables without descriptions
    missing_tables = []
    tables_with_desc = []
    for table in tables:
        if table.upper() not in all_tables:
            missing_tables.append(table)
        else:
            tables_with_desc.append(table)
    
    # Find TCodes without descriptions
    missing_tcodes = []
    tcodes_with_desc = []
    for tcode in tcodes:
        if tcode.upper() not in all_tcodes:
            missing_tcodes.append(tcode)
        else:
            tcodes_with_desc.append(tcode)
    
    # Find fields without descriptions
    missing_fields = []
    fields_with_desc = []
    for field in fields:
        if field.upper() not in all_fields:
            missing_fields.append(field)
        else:
            fields_with_desc.append(field)
    
    # Sort all by frequency
    sorted_all_fields = sorted([(field, field_counts.get(field, 0)) for field in fields], 
                               key=lambda x: x[1], reverse=True)
    
    # Print comprehensive field analysis
    print("\n=== COMPREHENSIVE FIELD ANALYSIS ===")
    print(f"\nTotal unique fields: {len(fields)}")
    print(f"Fields with descriptions: {len(fields_with_desc)}")
    print(f"Fields without descriptions: {len(missing_fields)}")
    
    print("\n--- ALL FIELDS BY FREQUENCY ---")
    for i, (field, count) in enumerate(sorted_all_fields, 1):
        has_desc = "✓" if field.upper() in all_fields else "✗"
        desc = all_fields.get(field.upper(), "No description")
        if has_desc == "✓":
            print(f"{i}. {field} ({count} occurrences) {has_desc} - {desc.split(' - ')[0]}")
        else:
            print(f"{i}. {field} ({count} occurrences) {has_desc}")
    
    # Filter to only those without descriptions
    missing_table_counts = {t: table_counts.get(t, 0) for t in missing_tables}
    missing_tcode_counts = {t: tcode_counts.get(t, 0) for t in missing_tcodes}
    missing_field_counts = {f: field_counts.get(f, 0) for f in missing_fields}
    
    # Sort by frequency (most common first)
    sorted_tables = sorted(missing_table_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_tcodes = sorted(missing_tcode_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_fields = sorted(missing_field_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Print top 10 most frequent items without descriptions
    if missing_fields:
        print("\n--- FIELDS MISSING DESCRIPTIONS ---")
        for i, (field, count) in enumerate(sorted_fields, 1):
            print(f"{i}. {field} ({count} occurrences)")
    
    # Generate dictionary code snippets for the most common missing items
    print("\n--- DICTIONARY CODE SNIPPETS ---")
    
    if missing_fields:
        print("\n# Field descriptions to add:")
        for field, count in sorted_fields:  # All missing fields
            print(f'    "{field}": "{field} - [Add description here]",')

if __name__ == "__main__":
    analyze_timeline()
