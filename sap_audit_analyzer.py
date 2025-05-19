#!/usr/bin/env python3
"""
SAP Audit Analyzer Adapter

This module serves as an adapter between the main SAP Audit Tool and the new modular
SAP Analyzer package. It provides backward compatibility for existing code.
"""

import os
import sys
from datetime import datetime

# Add script directory to path to ensure imports work correctly
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Import the new analyzer package
try:
    from sap_analyzer.run import run_analysis_from_audit_tool as run_analysis_internal
    from sap_analyzer.utils import log_message
    ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: SAP Analyzer package import failed: {str(e)}")
    ANALYZER_AVAILABLE = False
    
    # Define a placeholder log_message function if the real one isn't available
    def log_message(message, level="INFO"):
        """Log a message with timestamp and level."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")

def run_analysis_from_audit_tool(excel_path=None, output_dir=None, sysaid_path=None):
    """
    Bridge to the new analyzer package's run_analysis_from_audit_tool function.
    This maintains backward compatibility with the main sap_audit_tool.py.
    
    Args:
        excel_path: Path to the generated Excel report (if not default)
        output_dir: Output directory for analysis files
        sysaid_path: Path to SysAid ticket information
    
    Returns:
        Boolean indicating success or failure
    """
    if not ANALYZER_AVAILABLE:
        log_message("SAP Analyzer package is not available. Analysis cannot be performed.", "ERROR")
        return False
    
    try:
        # Set default output directory if not provided
        if output_dir is None:
            output_dir = os.path.join(SCRIPT_DIR, "output")
        
        # Ensure the output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Set default excel path if not provided
        if excel_path is None:
            excel_path = os.path.join(output_dir, "SAP_Audit_Report.xlsx")
        
        # Check if SysAid data is available
        if sysaid_path is None:
            sysaid_path = os.path.join(SCRIPT_DIR, "input", "SysAid.xlsx")
            if not os.path.exists(sysaid_path):
                log_message(f"SysAid data file not found at {sysaid_path}. Proceeding without ticket data.", "WARNING")
                sysaid_path = None
        
        # Run the analysis using the new module
        log_message("Running analysis with SAP Analyzer package...")
        
        # Pass the report path directly rather than the excel_path parameter
        report_path = excel_path
        
        result = run_analysis_internal(
            excel_path, 
            output_dir, 
            sysaid_path
        )
        
        # Return success if no error occurred
        if result and "error" not in result:
            log_message("Analysis completed successfully with SAP Analyzer package")
            return True
        else:
            error_msg = result.get("error", "Unknown error") if result else "No result returned"
            log_message(f"Analysis failed: {error_msg}", "ERROR")
            return False
        
    except Exception as e:
        log_message(f"Error running analysis: {str(e)}", "ERROR")
        import traceback
        log_message(traceback.format_exc(), "ERROR")
        return False

# For testing the adapter directly
if __name__ == "__main__":
    print("SAP Audit Analyzer Adapter")
    print(f"Analyzer package available: {ANALYZER_AVAILABLE}")
    
    if len(sys.argv) > 1:
        excel_path = sys.argv[1]
        print(f"Running analysis on: {excel_path}")
        success = run_analysis_from_audit_tool(excel_path)
        print(f"Analysis {'succeeded' if success else 'failed'}")
    else:
        print("Usage: python sap_audit_analyzer.py <excel_path>")
        print("Using default path...")
        
        # Check if default report exists
        default_path = os.path.join(SCRIPT_DIR, "output", "SAP_Audit_Report.xlsx")
        if os.path.exists(default_path):
            print(f"Found report at: {default_path}")
            success = run_analysis_from_audit_tool(default_path)
            print(f"Analysis {'succeeded' if success else 'failed'}")
        else:
            print(f"No report found at: {default_path}")
            print("Please provide a path to an existing report file")
