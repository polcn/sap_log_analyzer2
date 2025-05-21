#!/usr/bin/env python3
"""
Simple test script to verify the execution of the refactored data preparation module.
This simulates a real execution without requiring actual input files.
"""

import os
import sys
import pandas as pd
from pathlib import Path

# Ensure we can import the modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Mock the file finding and processing functions for testing
import sap_audit_data_prep
from sap_audit_config import PATHS, COLUMNS

def create_test_data():
    """Create test data files for each source."""
    print("Creating test data files...")
    
    # Create test directories if they don't exist
    os.makedirs(PATHS["input_dir"], exist_ok=True)
    
    # Create SM20 test data
    sm20_data = pd.DataFrame({
        'USER': ['USER1', 'USER2', 'USER3'],
        'DATE': ['2025-05-01', '2025-05-01', '2025-05-02'],
        'TIME': ['10:00:00', '11:00:00', '14:30:00'],
        'EVENT': ['AU1', 'AU3', 'AU1'],
        'SOURCE TA': ['SE16', 'SM59', 'SU01'],
        'ABAP SOURCE': ['PROGRAM1', 'PROGRAM2', 'PROGRAM3'],
        'AUDIT LOG MSG. TEXT': ['Message 1', 'Message 2', 'Message 3']
    })
    sm20_file = os.path.join(PATHS["input_dir"], "test_sm20_export.xlsx")
    sm20_data.to_excel(sm20_file, index=False)
    print(f"Created SM20 test file: {sm20_file}")
    
    # Create CDHDR test data
    cdhdr_data = pd.DataFrame({
        'USER': ['USER1', 'USER2', 'USER3'],
        'DATE': ['2025-05-01', '2025-05-01', '2025-05-02'],
        'TIME': ['10:05:00', '11:15:00', '14:35:00'],
        'TCODE': ['SE16', 'SM59', 'SU01'],
        'DOC.NUMBER': ['0000000001', '0000000002', '0000000003'],
        'OBJECT': ['OBJECT1', 'OBJECT2', 'OBJECT3'],
        'OBJECT VALUE': ['ID1', 'ID2', 'ID3']
    })
    cdhdr_file = os.path.join(PATHS["input_dir"], "test_cdhdr_export.xlsx")
    cdhdr_data.to_excel(cdhdr_file, index=False)
    print(f"Created CDHDR test file: {cdhdr_file}")
    
    # Create CDPOS test data
    cdpos_data = pd.DataFrame({
        'DOC.NUMBER': ['0000000001', '0000000002', '0000000003'],
        'TABLE NAME': ['USER_T', 'ROLE_T', 'AUTH_T'],
        'TABLE KEY': ['KEY1', 'KEY2', 'KEY3'],
        'FIELD NAME': ['FIELD1', 'FIELD2', 'FIELD3'],
        'CHANGE INDICATOR': ['U', 'I', 'D'],
        'NEW VALUE': ['NewVal1', 'NewVal2', 'NewVal3'],
        'OLD VALUE': ['OldVal1', 'OldVal2', 'OldVal3']
    })
    cdpos_file = os.path.join(PATHS["input_dir"], "test_cdpos_export.xlsx")
    cdpos_data.to_excel(cdpos_file, index=False)
    print(f"Created CDPOS test file: {cdpos_file}")
    
    return sm20_file, cdhdr_file, cdpos_file

def patch_file_finding():
    """
    Patch the find_latest_file function to return our test files.
    This avoids having to modify the module code for testing.
    """
    # Store the original function
    original_find_latest_file = sap_audit_data_prep.find_latest_file
    
    # Create test files
    sm20_file, cdhdr_file, cdpos_file = create_test_data()
    
    # Define a patched function
    def patched_find_latest_file(pattern):
        if "sm20" in pattern.lower():
            return sm20_file
        elif "cdhdr" in pattern.lower():
            return cdhdr_file
        elif "cdpos" in pattern.lower():
            return cdpos_file
        return original_find_latest_file(pattern)
    
    # Replace the function
    sap_audit_data_prep.find_latest_file = patched_find_latest_file

def test_data_prep_execution():
    """Test the execution of the data preparation module."""
    print("\nTesting SAP Audit Data Preparation module execution...")
    
    # Patch the file finding function
    patch_file_finding()
    
    # Execute the main function from the module
    success = sap_audit_data_prep.main()
    
    # Check output files
    print("\nChecking output files:")
    for source_type in ["SM20", "CDHDR", "CDPOS"]:
        output_file = os.path.join(PATHS["input_dir"], f"{source_type}.csv")
        if os.path.exists(output_file):
            df = pd.read_csv(output_file)
            print(f"- {source_type}: {len(df)} records processed successfully")
        else:
            print(f"- {source_type}: Output file not found")
    
    return success

if __name__ == "__main__":
    success = test_data_prep_execution()
    if success:
        print("\nTest completed successfully.")
    else:
        print("\nTest completed with errors.")
