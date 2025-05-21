import pandas as pd
import sys
import os

# Import the dictionaries from the risk assessment module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from OneDrive.Documents.Python.sap_audit_tool_risk_assessment import (
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
    """Analyze the session timeline and identify missing descriptions."""
    print(f"Reading file: {file_path}")
    df = pd.read_excel(file_path, sheet_name='Session_Timeline')
    print(f"Total rows: {len(df)}")
    
    # Extract unique values
    tables = df['Table'].dropna().astype(str).str.strip().unique()
    tcodes = df['TCode'].dropna().astype(str).str.strip().unique()
    fields = df['Field'].dropna().astype(str).str.strip().unique()
    
    print(f"\nFound {len(tables)} unique tables")
    print(f"Found {len(tcodes)} unique transaction codes")
    print(f"Found {len(fields)} unique fields")
    
    # Find tables without descriptions
    missing_tables = []
    for table in tables:
        if table.upper() not in all_tables and table.strip() and table != "nan":
            missing_tables.append(table)
    
    # Find TCodes without descriptions
    missing_tcodes = []
    for tcode in tcodes:
        if tcode.upper() not in all_tcodes and tcode.strip() and tcode != "nan":
            missing_tcodes.append(tcode)
    
    # Find fields without descriptions
    missing_fields = []
    for field in fields:
        if field.upper() not in all_fields and field.strip() and field != "nan":
            missing_fields.append(field)
    
    # Print results
    print(f"\nTables without descriptions ({len(missing_tables)}):")
    for i, table in enumerate(sorted(missing_tables), 1):
        print(f"{i}. {table}")
    
    print(f"\nTransaction codes without descriptions ({len(missing_tcodes)}):")
    for i, tcode in enumerate(sorted(missing_tcodes), 1):
        print(f"{i}. {tcode}")
    
    print(f"\nFields without descriptions ({len(missing_fields)}):")
    for i, field in enumerate(sorted(missing_fields), 1):
        print(f"{i}. {field}")
    
    # Also find the most frequent tables, TCodes, and fields that don't have descriptions
    # to prioritize which ones to add first
    
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
    
    # Print top 10 most frequent items without descriptions
    print("\n--- TOP 10 MOST FREQUENT MISSING DESCRIPTIONS ---")
    
    print("\nTop tables without descriptions:")
    for i, (table, count) in enumerate(sorted_tables[:10], 1):
        print(f"{i}. {table} ({count} occurrences)")
    
    print("\nTop transaction codes without descriptions:")
    for i, (tcode, count) in enumerate(sorted_tcodes[:10], 1):
        print(f"{i}. {tcode} ({count} occurrences)")
    
    print("\nTop fields without descriptions:")
    for i, (field, count) in enumerate(sorted_fields[:10], 1):
        print(f"{i}. {field} ({count} occurrences)")
    
    # Generate dictionary code snippets for the most common missing items
    print("\n--- DICTIONARY CODE SNIPPETS ---")
    
    print("\n# Table descriptions to add:")
    for table, count in sorted_tables[:20]:  # Top 20
        print(f'    "{table}": "{table} - [Add description here]",')
    
    print("\n# Transaction code descriptions to add:")
    for tcode, count in sorted_tcodes[:20]:  # Top 20
        print(f'    "{tcode}": "{tcode} - [Add description here]",')
    
    print("\n# Field descriptions to add:")
    for field, count in sorted_fields[:20]:  # Top 20
        print(f'    "{field}": "{field} - [Add description here]",')

if __name__ == "__main__":
    analyze_timeline()
