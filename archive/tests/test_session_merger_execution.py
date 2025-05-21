#!/usr/bin/env python3
"""
Test script for the SAP Audit Session Merger module.

This script demonstrates the basic execution of the refactored session merger
to verify its functionality. It imports the module and runs a test session
merging process.
"""

import os
import sys
import pandas as pd
from datetime import datetime

# Import the refactored modules
from sap_audit_config import PATHS, COLUMNS, SETTINGS, VERSION
from sap_audit_utils import log_message, log_section, log_error
from sap_audit_session_merger import SessionMerger

def main():
    """Main function to test the session merger functionality."""
    log_section("STARTING SESSION MERGER TEST")
    
    log_message(f"SAP Audit Tool version: {VERSION}")
    log_message(f"Using configuration from: {os.path.abspath('sap_audit_config.py')}")
    log_message(f"Input directories: {PATHS['input_dir']}")
    log_message(f"Output file: {PATHS['session_timeline']}")
    
    try:
        # Create and initialize the session merger
        log_message("Creating SessionMerger instance...")
        merger = SessionMerger()
        
        # Process the data sources
        log_message("Starting merger processing...")
        start_time = datetime.now()
        
        result = merger.process()
        
        elapsed_time = (datetime.now() - start_time).total_seconds()
        
        # Check the result
        if result:
            log_message(f"Session merger completed successfully in {elapsed_time:.2f} seconds")
            log_message(f"Output file created: {os.path.abspath(PATHS['session_timeline'])}")
            
            # Attempt to read the output file for verification
            try:
                timeline_df = pd.read_excel(PATHS['session_timeline'])
                row_count = len(timeline_df)
                source_counts = timeline_df['Source'].value_counts().to_dict() if 'Source' in timeline_df.columns else {}
                
                log_message(f"Generated timeline contains {row_count} records")
                log_message(f"Records by source: {source_counts}")
                
                return True
            except Exception as e:
                log_error(e, "Error reading output file for verification")
                return False
        else:
            log_message("Session merger failed", "ERROR")
            return False
        
    except Exception as e:
        log_error(e, "Error in test execution")
        return False

if __name__ == "__main__":
    # Add a banner
    banner = "\n" + "="*80 + "\n"
    banner += " SAP AUDIT SESSION MERGER TEST ".center(80, "*") + "\n"
    banner += " Verifies the functionality of the refactored session merger ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)
    
    success = main()
    
    if success:
        print("\nTest completed successfully!")
        sys.exit(0)
    else:
        print("\nTest failed. Check the logs for details.")
        sys.exit(1)
