#!/usr/bin/env python3
"""
SAP Audit Tool - Risk Assessment Test Script

This script demonstrates the functionality of the refactored Risk Assessment module
by loading sample data and performing risk assessment on it.
"""

import os
import sys
import pandas as pd
from datetime import datetime

# Import the risk assessment module
from sap_audit_risk import RiskAssessor
from sap_audit_utils import log_section, log_message
from sap_audit_config import PATHS

def load_sample_data():
    """
    Load sample data for testing the risk assessment.
    
    In a real scenario, this would be data from the session merger,
    but for testing we'll create a simplified dataset.
    
    Returns:
        DataFrame with sample data
    """
    log_section("Loading Sample Data")
    
    # Check if we have a real session timeline file to use
    session_file = PATHS.get("session_timeline")
    if os.path.exists(session_file):
        log_message(f"Using existing session timeline file: {session_file}")
        try:
            df = pd.read_excel(session_file)
            log_message(f"Loaded {len(df)} records from session timeline")
            return df
        except Exception as e:
            log_message(f"Error loading {session_file}: {str(e)}", "ERROR")
            # Fall back to sample data
    
    # Create a sample dataset for testing
    log_message("Creating sample dataset for testing")
    
    data = {
        'Session ID': ['S001']*5 + ['S002']*3 + ['S003']*4,
        'Session ID with Date': ['S001-20250510']*5 + ['S002-20250510']*3 + ['S003-20250510']*4,
        'User': ['ADMIN', 'ADMIN', 'ADMIN', 'ADMIN', 'ADMIN', 
                'USER1', 'USER1', 'USER1',
                'SYSTEM', 'SYSTEM', 'SYSTEM', 'SYSTEM'],
        'Datetime': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")]*12,
        'Source': ['SM20', 'SM20', 'CDHDR', 'CDPOS', 'CDPOS',
                  'SM20', 'CDHDR', 'CDPOS',
                  'SM20', 'SM20', 'CDHDR', 'CDPOS'],
        'TCode': ['SU01', 'SU01', 'SU01', 'SU01', 'SU01',
                 'FB01', 'FB01', 'FB01',
                 'SE16N', 'SE16N', 'SE16N', 'SE16N'],
        'Table': ['USR02', 'USR02', 'USR02', 'USR02', 'USR02',
                 'BSEG', 'BSEG', 'BSEG',
                 'MARA', 'MARA', 'MARA', 'MARA'],
        'Field': ['PASSWORD', '', '', 'PASSWORD', '',
                'AMOUNT', 'AMOUNT', '',
                '', '', 'QUAN', ''],
        'Change_Indicator': ['', '', '', 'U', '',
                           '', '', 'I',
                           '', '', '', 'D'],
        'Event': ['AUB', '', '', '', '',
                '', '', '',
                'CUI', 'BU4', '', ''],
        'Variable_2': ['', 'D!', '', '', '',
                     '', '', '',
                     '', 'I!', '', ''],
        'Message_ID': ['', '', '', '', '',
                     '', '', '',
                     '', 'BU4', '', ''],
    }
    
    df = pd.DataFrame(data)
    log_message(f"Created sample dataset with {len(df)} records")
    return df

def run_risk_assessment_test():
    """Run a test of the risk assessment functionality."""
    log_section("Risk Assessment Test")
    
    # Load sample data
    sample_data = load_sample_data()
    
    # Create a risk assessor instance
    risk_assessor = RiskAssessor()
    log_message("Created RiskAssessor instance")
    
    # Run the risk assessment
    log_message("Running risk assessment...")
    enhanced_df = risk_assessor.assess_risk(sample_data)
    
    # Display results
    log_section("Risk Assessment Results")
    
    if enhanced_df is not None and not enhanced_df.empty:
        # Get distribution of risk levels
        risk_level_col = risk_assessor.col_names["risk_level"]
        risk_counts = enhanced_df[risk_level_col].value_counts()
        
        log_message("Risk Level Distribution:")
        for level, count in risk_counts.items():
            log_message(f"  - {level}: {count} records")
        
        # Show a few examples of high risk items
        if risk_assessor.risk_levels["high"] in risk_counts:
            log_message("\nSample High Risk Items:")
            high_risk = enhanced_df[enhanced_df[risk_level_col] == risk_assessor.risk_levels["high"]].head(3)
            
            for idx, row in high_risk.iterrows():
                tcode = row.get('TCode', 'N/A')
                table = row.get('Table', 'N/A')
                risk_desc = row.get(risk_assessor.col_names["risk_description"], 'No description available')
                log_message(f"  - TCode: {tcode}, Table: {table}")
                log_message(f"    Description: {risk_desc}")
                log_message("")
        
        # Optionally save to Excel for review
        output_file = os.path.join(PATHS.get("output_dir", ""), "risk_assessment_test_results.xlsx")
        enhanced_df.to_excel(output_file, index=False)
        log_message(f"Full results saved to: {output_file}")
    else:
        log_message("No results to display. Risk assessment may have failed.", "ERROR")
    
    log_message("Test completed.")
    return enhanced_df

if __name__ == "__main__":
    log_section("SAP Audit Risk Assessment Test")
    log_message("Starting test of the refactored Risk Assessment module")
    
    result_df = run_risk_assessment_test()
    
    log_message("Test script completed")
    print(f"\nTest completed with {len(result_df)} assessed records.")
