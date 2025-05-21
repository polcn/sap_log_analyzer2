#!/usr/bin/env python3
"""
Test script for SysAid-based session identification.
This script tests the updated SAP Log Session Merger with various SysAid ticket scenarios.
"""

import os
import sys
import pandas as pd
from datetime import datetime, timedelta
import importlib.util

# Import the SAP Log Session Merger module
merger_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SAP Log Session Merger.py")
spec = importlib.util.spec_from_file_location("sap_log_merger", merger_path)
merger = importlib.util.module_from_spec(spec)
sys.modules["sap_log_merger"] = merger
spec.loader.exec_module(merger)

# --- Test Functions ---
def create_test_data():
    """Create test data with different SysAid ticket scenarios."""
    print("Creating test data...")
    
    # Test Case 1: All rows with valid SysAid tickets
    data1 = pd.DataFrame({
        'USER': ['USER1', 'USER1', 'USER1', 'USER2', 'USER2'],
        'DATE': ['2023-05-01', '2023-05-01', '2023-05-02', '2023-05-01', '2023-05-02'],
        'TIME': ['08:00:00', '09:00:00', '10:00:00', '11:00:00', '12:00:00'],
        'EVENT': ['LOGON', 'TX', 'TX', 'LOGON', 'TX'],
        'SOURCE TA': ['', 'MM01', 'MM02', '', 'FI01'],
        'SYSAID#': ['SR-12345', 'SR-12345', 'SR-12345', 'CR-67890', 'CR-67890']
    })
    
    # Test Case 2: Some rows with missing SysAid tickets
    data2 = pd.DataFrame({
        'USER': ['USER3', 'USER3', 'USER3', 'USER4', 'USER4'],
        'DATE': ['2023-05-03', '2023-05-03', '2023-05-04', '2023-05-03', '2023-05-04'],
        'TIME': ['08:00:00', '09:00:00', '10:00:00', '11:00:00', '12:00:00'],
        'EVENT': ['LOGON', 'TX', 'TX', 'LOGON', 'TX'],
        'SOURCE TA': ['', 'MM03', 'MM04', '', 'FI02'],
        'SYSAID#': ['SR-45678', 'SR-45678', '', 'CR-98765', '']
    })
    
    # Test Case 3: Different column name for SysAid tickets
    data3 = pd.DataFrame({
        'USER': ['USER5', 'USER5', 'USER5', 'USER6', 'USER6'],
        'DATE': ['2023-05-05', '2023-05-05', '2023-05-06', '2023-05-05', '2023-05-06'],
        'TIME': ['08:00:00', '09:00:00', '10:00:00', '11:00:00', '12:00:00'],
        'EVENT': ['LOGON', 'TX', 'TX', 'LOGON', 'TX'],
        'SOURCE TA': ['', 'MM05', 'MM06', '', 'FI03'],
        'Ticket#': ['T-12345', 'T-12345', 'T-12345', 'T-67890', 'T-67890']
    })
    
    # Test Case 4: No SysAid ticket column
    data4 = pd.DataFrame({
        'USER': ['USER7', 'USER7', 'USER7', 'USER8', 'USER8'],
        'DATE': ['2023-05-07', '2023-05-07', '2023-05-08', '2023-05-07', '2023-05-08'],
        'TIME': ['08:00:00', '09:00:00', '10:00:00', '11:00:00', '12:00:00'],
        'EVENT': ['LOGON', 'TX', 'TX', 'LOGON', 'TX'],
        'SOURCE TA': ['', 'MM07', 'MM08', '', 'FI04']
    })
    
    # Convert to datetime format for each test case
    for df in [data1, data2, data3, data4]:
        df['Datetime'] = pd.to_datetime(df['DATE'] + ' ' + df['TIME'])
        df['Source'] = 'SM20'
    
    return {
        'Case 1: All valid SysAid tickets': data1,
        'Case 2: Some missing SysAid tickets': data2,
        'Case 3: Different SysAid column name': data3,
        'Case 4: No SysAid column': data4
    }

def test_sysaid_session_assignment():
    """Test SysAid-based session assignment with various scenarios."""
    test_data = create_test_data()
    
    for case_name, data in test_data.items():
        print(f"\n=== Testing {case_name} ===")
        
        # Find SysAid column if present
        sysaid_col = merger.find_sysaid_column(data)
        if sysaid_col:
            print(f"Found SysAid column: {sysaid_col}")
            # Standardize SysAid references
            data = merger.standardize_sysaid_references(data, sysaid_col)
            print(f"Standardized SysAid values: {data[sysaid_col].unique().tolist()}")
        else:
            print("No SysAid column found - will use user+date based sessions")
        
        # Assign session IDs
        result = merger.assign_session_ids(data, 'USER', 'Datetime')
        
        # Print session results
        print("\nSession Assignment Results:")
        for i, row in result.iterrows():
            user = row['USER']
            date = row['Datetime'].strftime('%Y-%m-%d')
            time = row['Datetime'].strftime('%H:%M:%S')
            session_id = row['Session ID']
            session_with_date = row['Session ID with Date']
            sysaid = row[sysaid_col] if sysaid_col and sysaid_col in row else 'N/A'
            
            print(f"Row {i}: User={user}, Date={date}, Time={time}, SysAid={sysaid}, " +
                  f"Session={session_id}, Session with Date={session_with_date}")
        
        # Print session summary
        sessions = result.groupby('Session ID')['USER'].count().reset_index()
        print("\nSession Summary:")
        for i, row in sessions.iterrows():
            session_id = row['Session ID']
            count = row['USER']
            session_rows = result[result['Session ID'] == session_id]
            users = session_rows['USER'].unique()
            dates = session_rows['Datetime'].dt.date.unique()
            
            if sysaid_col and sysaid_col in result.columns:
                sysaids = session_rows[sysaid_col].unique()
                print(f"Session {session_id}: {count} rows, Users={users}, Dates={dates}, SysAid={sysaids}")
            else:
                print(f"Session {session_id}: {count} rows, Users={users}, Dates={dates}")
        
        print("\n" + "="*50)

def main():
    """Main function to run the tests."""
    print("\n" + "="*80)
    print(" SYSAID SESSION IDENTIFICATION TEST ".center(80, "*"))
    print("="*80 + "\n")
    
    test_sysaid_session_assignment()
    
    print("\nTest completed!")

if __name__ == "__main__":
    main()
