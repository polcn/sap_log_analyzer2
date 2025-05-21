#!/usr/bin/env python3
"""
Integration test for the SAP Audit Tool pipeline with the enhanced analyzer.

This script runs the full SAP audit pipeline including the new SAPAuditAnalyzer
to verify that the enhanced analysis features work correctly in the context
of the complete workflow.
"""

import os
import sys
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Add script directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

# Import required modules
from sap_audit_controller import AuditController
from sap_audit_config import PATHS, CONFIG
from sap_audit_utils import log_message, log_section, log_error


def create_test_data():
    """
    Create test data for the integration test.
    
    This function creates sample data files for SM20, CDHDR, and CDPOS
    to simulate the input for a full audit run.
    
    Returns:
        dict: Paths to the created test files
    """
    log_section("Creating Test Data")
    
    # Create test directory
    test_dir = os.path.join(script_dir, "test_data")
    os.makedirs(test_dir, exist_ok=True)
    
    # Generate current date for filenames
    current_date = datetime.now().strftime("%Y%m%d")
    
    # Create sample SM20 data
    sm20_data = {
        "USER": ["ADMIN", "USER1", "USER2", "ADMIN", "USER1", "FIREFIGHTER"],
        "DATE": ["2025-05-01", "2025-05-01", "2025-05-01", "2025-05-01", "2025-05-01", "2025-05-01"],
        "TIME": ["10:00:00", "11:00:00", "12:00:00", "13:00:00", "14:00:00", "15:00:00"],
        "EVENT": ["AU1", "AU3", "AUE", "DB", "AU1", "AU1"],
        "SOURCE TA": ["SM30", "FB03", "", "/H", "SU01", "SE38"],
        "AUDIT LOG MSG. TEXT": [
            "User logged on", 
            "Transaction start", 
            "User logged off", 
            "Debugger started", 
            "User logged on", 
            "User logged on"
        ],
        "VARIABLE_DATA": ["", "", "", "", "", ""],
        "VARIABLE 2": ["", "", "", "D!", "", ""],
        "SYSAID#": ["12345", "", "", "67890", "", "54321"]
    }
    sm20_df = pd.DataFrame(sm20_data)
    sm20_path = os.path.join(test_dir, f"test_sm20_{current_date}.csv")
    sm20_df.to_csv(sm20_path, index=False)
    log_message(f"Created SM20 test data with {len(sm20_df)} records")
    
    # Create sample CDHDR data
    cdhdr_data = {
        "USER": ["ADMIN", "USER1", "ADMIN", "FIREFIGHTER"],
        "DATE": ["2025-05-01", "2025-05-01", "2025-05-01", "2025-05-01"],
        "TIME": ["10:15:00", "11:15:00", "13:15:00", "15:15:00"],
        "TCODE": ["SM30", "MM03", "SM30", "SE38"],
        "DOC.NUMBER": ["0000000001", "0000000002", "0000000003", "0000000004"],
        "OBJECT": ["MARA", "EKKO", "USR02", "TADIR"],
        "OBJECT VALUE": ["MATERIAL123", "PO10001", "USER1", "PROGRAM1"],
        "SYSAID#": ["12345", "", "67890", "54321"]
    }
    cdhdr_df = pd.DataFrame(cdhdr_data)
    cdhdr_path = os.path.join(test_dir, f"test_cdhdr_{current_date}.csv")
    cdhdr_df.to_csv(cdhdr_path, index=False)
    log_message(f"Created CDHDR test data with {len(cdhdr_df)} records")
    
    # Create sample CDPOS data
    cdpos_data = {
        "DOC.NUMBER": ["0000000001", "0000000001", "0000000002", "0000000003", "0000000004"],
        "TABLE NAME": ["MARA", "MARA", "EKKO", "USR02", "TADIR"],
        "FIELD NAME": ["MATNR", "MAKTX", "EBELN", "BNAME", "PROGNAME"],
        "CHANGE INDICATOR": ["I", "I", "U", "U", "I"],
        "NEW VALUE": ["MATERIAL123", "Material Description", "PO10001-Updated", "USER1-NEW", "PROGRAM1"],
        "OLD VALUE": ["", "", "PO10001", "USER1", ""]
    }
    cdpos_df = pd.DataFrame(cdpos_data)
    cdpos_path = os.path.join(test_dir, f"test_cdpos_{current_date}.csv")
    cdpos_df.to_csv(cdpos_path, index=False)
    log_message(f"Created CDPOS test data with {len(cdpos_df)} records")
    
    # Create sample SysAid data
    sysaid_data = {
        "Ticket": ["12345", "67890", "54321"],
        "Title": ["System Access Request", "Password Reset", "Development Access"],
        "Description": [
            "Request for table maintenance", 
            "Debug access for issue resolution", 
            "Development environment access"
        ],
        "Notes": [
            "Approved for SM30 access", 
            "Temporary debugging access granted", 
            "SE38 access for development work"
        ],
        "Request user": ["ADMIN", "ADMIN", "FIREFIGHTER"],
        "Process manager": ["MANAGER1", "MANAGER2", "MANAGER1"],
        "Request time": ["2025-04-30 15:00:00", "2025-04-30 16:00:00", "2025-04-30 14:00:00"]
    }
    sysaid_df = pd.DataFrame(sysaid_data)
    sysaid_path = os.path.join(test_dir, f"test_sysaid_{current_date}.xlsx")
    sysaid_df.to_excel(sysaid_path, index=False)
    log_message(f"Created SysAid test data with {len(sysaid_df)} records")
    
    # Return paths to test files
    test_files = {
        "sm20": sm20_path,
        "cdhdr": cdhdr_path,
        "cdpos": cdpos_path,
        "sysaid": sysaid_path
    }
    
    return test_files, test_dir


def setup_test_environment(test_files):
    """
    Set up the test environment by updating config paths.
    
    Args:
        test_files: Dictionary of test file paths
        
    Returns:
        dict: Modified configuration for test run
    """
    log_section("Setting Up Test Environment")
    
    # Create a test configuration based on the default config
    test_config = CONFIG.copy()
    test_paths = PATHS.copy()
    
    # Update paths to use test files
    test_paths["sm20_input"] = test_files["sm20"]
    test_paths["cdhdr_input"] = test_files["cdhdr"]
    test_paths["cdpos_input"] = test_files["cdpos"]
    test_paths["sysaid_input"] = test_files["sysaid"]
    
    # Create a test output directory
    test_output_dir = os.path.join(script_dir, "test_output")
    os.makedirs(test_output_dir, exist_ok=True)
    test_paths["output_dir"] = test_output_dir
    
    # Set test output file
    current_date = datetime.now().strftime("%Y%m%d_%H%M%S")
    test_output_file = os.path.join(test_output_dir, f"Test_Audit_Report_{current_date}.xlsx")
    test_paths["audit_report"] = test_output_file
    
    # Enable SysAid integration for testing
    test_config["enable_sysaid"] = True
    test_config["output_path"] = test_output_file
    
    # Update PATHS in the modified configuration
    test_config["_paths"] = test_paths
    
    log_message(f"Test environment configured with output to: {test_output_file}")
    
    return test_config, test_paths


def run_integration_test():
    """
    Run the integration test for the full audit pipeline.
    
    This function:
    1. Creates test data
    2. Sets up a test environment
    3. Runs the full audit pipeline
    4. Validates the output
    
    Returns:
        bool: Success status of the test
    """
    log_section("Starting SAP Audit Integration Test")
    
    try:
        # Step 1: Create test data
        test_files, test_dir = create_test_data()
        
        # Step 2: Set up test environment
        test_config, test_paths = setup_test_environment(test_files)
        
        # Step 3: Initialize audit controller with test configuration
        controller = AuditController(config=test_config)
        
        # Step 4: Run the full audit pipeline
        log_section("Running Full Audit Pipeline")
        success = controller.run_full_audit()
        
        if not success:
            log_message("Audit pipeline failed", "ERROR")
            return False
        
        # Step 5: Validate the output
        log_section("Validating Output")
        output_file = test_paths["audit_report"]
        
        if not os.path.exists(output_file):
            log_message(f"Output file not found: {output_file}", "ERROR")
            return False
            
        # Load the output file to verify contents
        try:
            output_df = pd.read_excel(output_file)
            
            # Verify output contains expected columns
            expected_columns = [
                "TCode_Description", "Event_Description", "Table_Description",
                "Table_Maintenance", "High_Risk_TCode", "Change_Activity",
                "Transport_Related_Event", "Debugging_Related_Event", "Benign_Activity",
                "Observations", "Questions", "Response", "Conclusion"
            ]
            
            missing_columns = [col for col in expected_columns if col not in output_df.columns]
            
            if missing_columns:
                log_message(f"Missing expected columns in output: {', '.join(missing_columns)}", "ERROR")
                return False
                
            # Verify output contains expected records
            if len(output_df) == 0:
                log_message("Output file contains no records", "ERROR")
                return False
                
            log_message(f"Output file contains {len(output_df)} records")
            log_message(f"Output file has {len(output_df.columns)} columns")
            
            # Verify some key content
            # Check for a debugging event
            debug_rows = output_df[output_df["Debugging_Related_Event"] == "Yes"]
            if len(debug_rows) == 0:
                log_message("No debugging events found in output", "WARNING")
            else:
                log_message(f"Found {len(debug_rows)} debugging events")
                
            # Check for table maintenance activity
            table_maint_rows = output_df[output_df["Table_Maintenance"] == "Yes"]
            if len(table_maint_rows) == 0:
                log_message("No table maintenance activities found in output", "WARNING")
            else:
                log_message(f"Found {len(table_maint_rows)} table maintenance activities")
            
            # Check for SysAid integration
            sysaid_rows = output_df[output_df["SYSAID #"] != ""]
            if len(sysaid_rows) == 0:
                log_message("No SysAid tickets found in output", "WARNING")
            else:
                log_message(f"Found {len(sysaid_rows)} rows with SysAid tickets")
                
            # Verify conclusions auto-populated
            conclusion_rows = output_df[output_df["Conclusion"] != ""]
            log_message(f"Found {len(conclusion_rows)} rows with auto-populated conclusions")
            
            log_message("Output validation completed successfully")
            return True
            
        except Exception as e:
            log_error(e, "Error validating output file")
            return False
            
    except Exception as e:
        log_error(e, "Error in integration test")
        return False
    finally:
        # Clean up test files (optional - keep commented for debugging)
        # if 'test_dir' in locals() and os.path.exists(test_dir):
        #     import shutil
        #     shutil.rmtree(test_dir)
        #     log_message(f"Cleaned up test directory: {test_dir}")
        pass


if __name__ == "__main__":
    success = run_integration_test()
    
    if success:
        log_message("Integration test completed successfully", "SUCCESS")
        sys.exit(0)
    else:
        log_message("Integration test failed", "ERROR")
        sys.exit(1)
