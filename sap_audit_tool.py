#!/usr/bin/env python3
"""
SAP Audit Tool - Main Script

This script provides the main entry point for the SAP Audit Tool.
It uses the AuditController to orchestrate all processing steps
of the SAP Audit workflow.

Usage:
  python sap_audit_tool.py [options]

Options:
  --mode MODE          Processing mode: full, prep, merge, existing
  --timeline FILE      Timeline file for 'existing' mode
  --output FILE        Override output file path
  --format FORMAT      Output format: excel, csv
  --sysaid STRATEGY    SysAid strategy: file, api

Examples:
  python sap_audit_tool.py                    # Run full audit process
  python sap_audit_tool.py --mode prep        # Run only data preparation
  python sap_audit_tool.py --mode merge       # Run data preparation and session merging
  python sap_audit_tool.py --mode existing    # Process from existing timeline file
                      --timeline FILE.xlsx
  python sap_audit_tool.py --format csv       # Generate CSV output
"""

import sys
import os
import time
import argparse
from datetime import datetime

# Import configurations
try:
    from sap_audit_config import PATHS, SETTINGS
    from sap_audit_utils import log_message, log_section, log_error, handle_exception
except ImportError as e:
    print(f"ERROR: Required modules not found: {e}")
    print("Please ensure all core configuration modules are available.")
    sys.exit(1)

# Import controller (which will import all required components)
try:
    from sap_audit_controller import AuditController
except ImportError as e:
    print(f"ERROR: Cannot import AuditController: {e}")
    print("The SAP Audit Controller module is required to run this tool.")
    sys.exit(1)

# Constants
MODES = {
    "full": "Run full audit process",
    "prep": "Data preparation only",
    "merge": "Data preparation and session merging only",
    "existing": "Process from existing timeline file",
}

OUTPUT_FORMATS = ["excel", "csv"]
SYSAID_STRATEGIES = ["file", "api"]


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="SAP Audit Tool")
    
    parser.add_argument("--mode", choices=list(MODES.keys()), default="full",
                        help=f"Processing mode: {', '.join(MODES.keys())}")
    parser.add_argument("--timeline", 
                        help="Timeline file for 'existing' mode")
    parser.add_argument("--output", 
                        help="Override output file path")
    parser.add_argument("--format", choices=OUTPUT_FORMATS, default="excel",
                        help=f"Output format: {', '.join(OUTPUT_FORMATS)}")
    parser.add_argument("--sysaid", choices=SYSAID_STRATEGIES, default="file",
                        help=f"SysAid data strategy: {', '.join(SYSAID_STRATEGIES)}")
    
    return parser.parse_args()


def create_config_from_args(args):
    """Create configuration dictionary from command line arguments."""
    config = {}
    
    # Set output format
    config["output_format"] = args.format
    
    # Set SysAid strategy
    config["sysaid_source"] = args.sysaid
    
    # Set output path if specified
    if args.output:
        config["output_path"] = args.output
    
    # Set timeline file for existing mode
    if args.timeline:
        config["timeline_file"] = args.timeline
    
    return config


def display_banner():
    """Display a banner with tool information."""
    version = SETTINGS.get("version", "1.0.0")
    banner = "\n" + "="*80 + "\n"
    banner += f" SAP AUDIT TOOL v{version} ".center(80, "*") + "\n"
    banner += " Enhanced Security Analysis for SAP Logs ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)


def display_mode_info(mode):
    """Display information about the selected processing mode."""
    mode_description = MODES.get(mode, "Unknown mode")
    print(f"\nProcessing Mode: {mode} - {mode_description}\n")


@handle_exception
def main():
    """Main function to execute the SAP audit process."""
    # Display banner
    display_banner()
    
    # Parse command line arguments
    args = parse_args()
    
    # Display mode information
    display_mode_info(args.mode)
    
    # Log start of process
    version = SETTINGS.get("version", "1.0.0")
    log_section(f"SAP Audit Tool v{version}")
    log_message(f"Starting in {args.mode} mode")
    
    # Create configuration from arguments
    config = create_config_from_args(args)
    
    try:
        # Create audit controller
        controller = AuditController(config)
        
        # Process based on selected mode
        if args.mode == "full":
            # Run full audit
            success = controller.run_full_audit()
        elif args.mode == "prep":
            # Run data preparation only
            success = controller.run_data_preparation()
        elif args.mode == "merge":
            # Run data preparation and session merging
            success = controller.run_data_preparation() and controller.run_session_merging()
        elif args.mode == "existing":
            # Process from existing timeline file
            if not args.timeline:
                log_message("Timeline file path is required for 'existing' mode", "ERROR")
                return False
                
            try:
                # Load the existing timeline
                import pandas as pd
                existing_timeline = pd.read_excel(args.timeline)
                log_message(f"Loaded existing timeline with {len(existing_timeline)} records")
                
                # Set the session data and continue with risk assessment
                controller.session_data = existing_timeline
                
                # Run remaining steps
                risk_success = controller.run_risk_assessment()
                sysaid_success = controller.run_sysaid_integration() if risk_success else False
                output_success = controller.generate_output() if risk_success else False
                
                success = risk_success and output_success
                
            except Exception as e:
                log_error(e, f"Failed to process existing timeline: {args.timeline}")
                return False
        else:
            log_message(f"Unknown mode: {args.mode}", "ERROR")
            return False
        
        return success
        
    except Exception as e:
        log_error(e, "Unhandled exception in main process")
        return False


# Main execution
if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
