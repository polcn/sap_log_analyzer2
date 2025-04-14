#!/usr/bin/env python3
"""
SAP Field Monitor

This script monitors SAP session timeline data for new fields that might need descriptions.
Run it periodically after processing new SAP log files to ensure all fields have descriptions.
"""

import pandas as pd
import os
import sys
from datetime import datetime

# Import the field descriptions
from sap_audit_tool_risk_assessment import get_common_field_descriptions

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def monitor_fields(file_path):
    """
    Monitor for new fields in the session timeline.
    
    Args:
        file_path: Path to the session timeline Excel file
    """
    log_message(f"Analyzing file: {file_path}")
    
    try:
        # Read the session timeline
        df = pd.read_excel(file_path, sheet_name='Session_Timeline')
        log_message(f"Loaded {len(df)} rows of data")
        
        # Get current field descriptions
        field_descriptions = get_common_field_descriptions()
        known_fields = set(field_descriptions.keys())
        
        # Extract all fields from the data
        found_fields = set()
        for field in df['Field'].dropna().unique():
            if isinstance(field, str) and field.strip() and field.strip().upper() != 'NAN':
                found_fields.add(field.strip().upper())
        
        log_message(f"Found {len(found_fields)} unique fields in the data")
        
        # Check for new fields
        new_fields = found_fields - known_fields
        if new_fields:
            log_message(f"Detected {len(new_fields)} new fields without descriptions", "WARNING")
            print("\nNew fields detected:")
            for i, field in enumerate(sorted(new_fields), 1):
                count = df[df['Field'].str.upper() == field].shape[0]
                print(f"{i}. {field} ({count} occurrences)")
            
            print("\nField description templates:")
            for field in sorted(new_fields):
                print(f'    "{field}": "{field} - [Add description here]",')
        else:
            log_message("All fields have descriptions. No action needed.")
            
        # Field coverage statistics
        covered_percentage = 100 if not found_fields else (len(found_fields - new_fields) / len(found_fields) * 100)
        log_message(f"Field description coverage: {covered_percentage:.1f}%")
        
        return len(new_fields) == 0
    
    except Exception as e:
        log_message(f"Error analyzing fields: {str(e)}", "ERROR")
        return False

if __name__ == "__main__":
    # Use command line argument for file path or default to standard location
    file_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 
        "SAP_Session_Timeline.xlsx"
    )
    
    success = monitor_fields(file_path)
    sys.exit(0 if success else 1)
