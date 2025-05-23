#!/usr/bin/env python3
"""
Test script for the unified output format in the SAP Audit Tool.

This script tests the new unified output format by:
1. Loading sample data
2. Running it through the pipeline
3. Verifying all analysis columns are correctly populated
4. Generating an Excel output in the new format
"""

import os
import sys
import pandas as pd
from datetime import datetime, timedelta
import random

# Import the SAP Audit modules
from sap_audit_analyzer import SAPAuditAnalyzer
from sap_audit_output import ExcelOutputGenerator
from sap_audit_config import PATHS, REPORTING

# Constants for test data generation
TEST_USERS = ['ADMIN', 'USER1', 'USER2', 'MAINT_USER', 'DEV_USER']
TEST_TCODES = {
    'display': ['VA03', 'MM03', 'ME23', 'FK03'],  # Display transactions
    'change': ['VA01', 'MM01', 'ME21', 'FK01'],   # Create transactions
    'high_risk': ['SE38', 'SE37', 'SM30', 'SE16', 'SU01', 'PFCG', 'STMS'],  # High-risk transactions
    'debugging': ['/H', 'SE24', 'SE80']  # Debugging transactions
}
TEST_EVENTS = {
    'logon': ['AU1'],
    'logoff': ['AUC'],
    'session': ['AU6'],
    'change': ['BU', 'BC', 'BD']
}
TEST_TABLES = ['MARA', 'MARC', 'KNA1', 'LFA1', 'VBAK', 'LIKP', 'USR02']

def create_test_sm20_data(num_records=50):
    """Create test SM20 data."""
    print(f"Creating {num_records} sample SM20 records")
    
    records = []
    base_date = datetime.now().replace(hour=8, minute=0, second=0, microsecond=0)
    
    for i in range(num_records):
        record_time = base_date + timedelta(minutes=i*15)
        date_str = record_time.strftime('%Y-%m-%d')
        time_str = record_time.strftime('%H:%M:%S')
        
        # Determine record type and properties
        if i % 10 == 0:  # Every 10th record is a logon
            event = random.choice(TEST_EVENTS['logon'])
            tcode = ''
            msg = 'User logged on'
        elif i % 10 == 9:  # Every 10th record (offset by 9) is a logoff
            event = random.choice(TEST_EVENTS['logoff'])
            tcode = ''
            msg = 'User logged off'
        elif i % 5 == 0:  # Some session manager events
            event = random.choice(TEST_EVENTS['session'])
            tcode = ''
            msg = 'Session manager started'
        else:  # Regular transaction activity
            # Mix of display, change, and high-risk transactions
            if i % 7 == 0:
                event = random.choice(TEST_EVENTS['change'])
                tcode = random.choice(TEST_TCODES['high_risk'])
                msg = f'Executed high-risk transaction {tcode}'
            elif i % 3 == 0:
                event = 'TX'
                tcode = random.choice(TEST_TCODES['change'])
                msg = f'Executed change transaction {tcode}'
            else:
                event = 'TX'
                tcode = random.choice(TEST_TCODES['display']) 
                msg = f'Executed display transaction {tcode}'
        
        # Add debugging markers to some records
        debug_var = ''
        if i % 15 == 0 and tcode:  # Some debugging activity
            debug_var = 'D!DEBUGACTIVE'
        
        # Create the record
        record = {
            'USER': random.choice(TEST_USERS),
            'DATE': date_str,
            'TIME': time_str,
            'EVENT': event,
            'SOURCE TA': tcode,
            'AUDIT LOG MSG. TEXT': msg,
            'NOTE': '',
            'VARIABLE 2': debug_var,
            'SYSAID#': f'SR-{10000 + i//3}' if i % 3 == 0 else '',  # Add SysAid ticket to every 3rd record
            'Datetime': record_time,
            'Source': 'SM20'
        }
        records.append(record)
    
    return pd.DataFrame(records)

def create_test_cdhdr_data(sm20_df, ratio=0.4):
    """Create test CDHDR data that corresponds to some SM20 records."""
    print(f"Creating CDHDR records for approximately {ratio*100:.0f}% of SM20 records")
    
    records = []
    # Select a subset of SM20 records that used change transactions
    change_records = sm20_df[sm20_df['SOURCE TA'].isin(
        TEST_TCODES['change'] + TEST_TCODES['high_risk']
    )].sample(frac=ratio)
    
    for _, sm20_row in change_records.iterrows():
        record_time = sm20_row['Datetime'] + timedelta(seconds=random.randint(10, 120))
        date_str = record_time.strftime('%Y-%m-%d')
        time_str = record_time.strftime('%H:%M:%S')
        
        # Determine object class and ID
        if 'VA' in sm20_row['SOURCE TA']:
            obj_class = 'VERKBELEG'  # Sales document
            obj_id = f'10{random.randint(1000, 9999)}'
        elif 'MM' in sm20_row['SOURCE TA']:
            obj_class = 'MATERIAL'  # Material 
            obj_id = f'10{random.randint(1000, 9999)}'
        elif 'ME' in sm20_row['SOURCE TA']:
            obj_class = 'EINKBELEG'  # Purchasing document
            obj_id = f'45{random.randint(1000, 9999)}'
        else:
            obj_class = 'UNKNOWN'
            obj_id = f'{random.randint(10000, 99999)}'
        
        # Create the record
        change_number = random.randint(1000000, 9999999)
        record = {
            'USER': sm20_row['USER'],
            'DATE': date_str,
            'TIME': time_str,
            'TCODE': sm20_row['SOURCE TA'],
            'DOC.NUMBER': change_number,
            'OBJECT': obj_class,
            'OBJECT VALUE': obj_id,
            'CHANGE FLAG FOR APPLICATION OBJECT': '',
            'SYSAID#': sm20_row['SYSAID#'],
            'Datetime': record_time,
            'Source': 'CDHDR'
        }
        records.append(record)
    
    return pd.DataFrame(records)

def create_test_cdpos_data(cdhdr_df, ratio=0.8):
    """Create test CDPOS data that corresponds to CDHDR records."""
    print(f"Creating CDPOS records for approximately {ratio*100:.0f}% of CDHDR records")
    
    records = []
    # Select a subset of CDHDR records
    selected_cdhdr = cdhdr_df.sample(frac=ratio)
    
    for _, cdhdr_row in selected_cdhdr.iterrows():
        # Each CDHDR can have multiple CDPOS records (1-3 for simplicity)
        num_pos_records = random.randint(1, 3)
        
        for j in range(num_pos_records):
            # Determine table based on object class
            if cdhdr_row['OBJECT'] == 'VERKBELEG':
                table = 'VBAK' if j == 0 else 'VBAP'
            elif cdhdr_row['OBJECT'] == 'MATERIAL':
                table = 'MARA' if j == 0 else 'MARC'
            elif cdhdr_row['OBJECT'] == 'EINKBELEG':
                table = 'EKKO' if j == 0 else 'EKPO'
            else:
                table = random.choice(TEST_TABLES)
            
            # Determine field name based on table
            if table == 'VBAK':
                field = random.choice(['VKORG', 'VTWEG', 'SPART', 'AUART'])
            elif table == 'MARA':
                field = random.choice(['MATNR', 'MATKL', 'MEINS', 'MSTAE'])
            else:
                field = f'FIELD_{random.randint(1, 20)}'
            
            # Determine change indicator
            change_indicators = ['U', 'I', 'D', 'C']
            change_indicator = random.choice(change_indicators)
            
            # Determine old and new values
            if change_indicator == 'I':  # Insert
                old_value = ''
                new_value = f'NEW_{random.randint(1000, 9999)}'
            elif change_indicator == 'U':  # Update
                old_value = f'OLD_{random.randint(1000, 9999)}'
                new_value = f'NEW_{random.randint(1000, 9999)}'
            elif change_indicator == 'D':  # Delete
                old_value = f'OLD_{random.randint(1000, 9999)}'
                new_value = ''
            else:  # Create
                old_value = ''
                new_value = f'NEW_{random.randint(1000, 9999)}'
            
            # Create CDPOS record
            record = {
                'DOC.NUMBER': cdhdr_row['DOC.NUMBER'],
                'TABLE NAME': table,
                'TABLE KEY': f'KEY_{cdhdr_row["OBJECT VALUE"]}',
                'FIELD NAME': field,
                'CHANGE INDICATOR': change_indicator,
                'TEXT FLAG': '',
                'OLD VALUE': old_value,
                'NEW VALUE': new_value,
                'Source': 'CDPOS'
            }
            records.append(record)
    
    return pd.DataFrame(records)

def create_combined_dataset():
    """Create a combined dataset with SM20, CDHDR, and CDPOS data."""
    # Create SM20 data
    sm20_df = create_test_sm20_data(num_records=100)
    
    # Create CDHDR data
    cdhdr_df = create_test_cdhdr_data(sm20_df, ratio=0.4)
    
    # Create CDPOS data
    cdpos_df = create_test_cdpos_data(cdhdr_df, ratio=0.8)
    
    # Combine datasets
    # First, get all unique columns
    all_columns = list(set(sm20_df.columns) | set(cdhdr_df.columns) | set(cdpos_df.columns))
    
    # Create a unified DataFrame with all columns
    combined_data = []
    
    # Add SM20 data
    for _, row in sm20_df.iterrows():
        row_dict = {}
        for col in all_columns:
            row_dict[col] = row[col] if col in row else None
        combined_data.append(row_dict)
    
    # Add CDHDR data
    for _, row in cdhdr_df.iterrows():
        row_dict = {}
        for col in all_columns:
            row_dict[col] = row[col] if col in row else None
        combined_data.append(row_dict)
    
    # Add CDPOS data
    for _, row in cdpos_df.iterrows():
        row_dict = {}
        for col in all_columns:
            row_dict[col] = row[col] if col in row else None
        combined_data.append(row_dict)
    
    # Create DataFrame from combined data
    df = pd.DataFrame(combined_data)
    
    print(f"Created combined dataset with {len(df)} total records:")
    print(f"- SM20: {len(sm20_df)} records")
    print(f"- CDHDR: {len(cdhdr_df)} records")
    print(f"- CDPOS: {len(cdpos_df)} records")
    
    # Add a session ID column
    df['Session ID'] = 'S0001'  # Simplified for testing
    df['Session ID with Date'] = 'S0001 (2025-05-22)'
    
    # Add a risk_level column for testing
    risk_levels = ['Critical', 'High', 'Medium', 'Low']
    df['risk_level'] = pd.Series([random.choice(risk_levels) for _ in range(len(df))])
    
    # Fill NaN values with empty strings
    df = df.fillna('')
    
    return df

def run_analysis_and_output_test():
    """Run the test to verify analyzer and output modules work together."""
    print("\n=== Testing SAP Audit Unified Output Format ===\n")
    
    # Create test dataset
    combined_df = create_combined_dataset()
    
    # Initialize the analyzer
    print("\nInitializing SAPAuditAnalyzer...")
    analyzer = SAPAuditAnalyzer()
    
    # Run analysis
    print("\nRunning enhanced analysis...")
    enhanced_df = analyzer.analyze(combined_df)
    
    # Verify analysis columns were added
    required_columns = [
        'TCode_Description', 'Event_Description', 'Table_Description',
        'Table_Maintenance', 'High_Risk_TCode', 'Change_Activity',
        'Transport_Related_Event', 'Debugging_Related_Event', 'Benign_Activity',
        'Observations', 'Questions', 'Response', 'Conclusion'
    ]
    
    print("\nVerifying analysis columns:")
    for column in required_columns:
        if column in enhanced_df.columns:
            print(f"  ✓ {column} added successfully")
        else:
            print(f"  ✗ {column} missing!")
    
    # Check for populated flags
    print("\nVerifying flag populations:")
    for flag in ['Table_Maintenance', 'High_Risk_TCode', 'Change_Activity', 
                 'Debugging_Related_Event', 'Benign_Activity']:
        populated = (enhanced_df[flag] != '').sum()
        print(f"  - {flag}: {populated} records populated")
    
    # Initialize the output generator
    print("\nInitializing ExcelOutputGenerator...")
    output_generator = ExcelOutputGenerator()
    
    # Generate Excel output
    output_path = os.path.join(PATHS.get("output_dir", "."), "Test_Unified_Output.xlsx")
    print(f"\nGenerating Excel output to: {output_path}")
    success = output_generator.generate_report(enhanced_df, output_path)
    
    if success:
        print(f"\n✓ Test completed successfully! Output saved to {output_path}")
    else:
        print("\n✗ Test failed - could not generate output!")

if __name__ == "__main__":
    run_analysis_and_output_test()
