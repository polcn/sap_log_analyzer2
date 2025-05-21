#!/usr/bin/env python3
"""
SAP Audit Tool - Main Runner

This script serves as the main entry point for running the SAP Audit Tool.
It provides command-line arguments for configuring the execution and uses
the centralized configuration system.

Usage:
    python run_sap_audit.py [options]

Options:
    --input-dir DIR     Directory containing input files
    --output-dir DIR    Directory for output files
    --config-file FILE  Path to configuration file (JSON or YAML)
    --sysaid            Enable SysAid integration
    --debug             Enable debug mode
    --env-file FILE     Path to .env file to load
    --help              Show this help message
"""

import argparse
import os
import sys
from datetime import datetime

# Import the configuration module
from sap_audit_config import PATHS, SETTINGS, CONFIG, VERSION, load_config_file, log_message

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description=f"SAP Audit Tool v{VERSION}")
    
    parser.add_argument("--input-dir", help="Directory containing input files")
    parser.add_argument("--output-dir", help="Directory for output files")
    parser.add_argument("--config-file", help="Path to configuration file (JSON or YAML)")
    parser.add_argument("--env-file", help="Path to .env file to load")
    parser.add_argument("--sysaid", action="store_true", help="Enable SysAid integration")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--export-env", action="store_true", help="Export sample .env file")
    parser.add_argument("--export-config", action="store_true", help="Export sample config files")
    
    return parser.parse_args()

def main():
    """Main entry point for the SAP Audit Tool."""
    start_time = datetime.now()
    args = parse_args()
    
    # Load .env file if specified
    if args.env_file:
        try:
            from dotenv import load_dotenv
            if load_dotenv(args.env_file):
                log_message(f"Loaded environment variables from {args.env_file}")
            else:
                log_message(f"Could not load .env file: {args.env_file}", "WARNING")
        except ImportError:
            log_message("python-dotenv package not installed. Cannot load .env file.", "ERROR")
    
    # Export sample configuration if requested
    if args.export_env:
        os.system(f"python {os.path.join(PATHS['script_dir'], 'sap_audit_config.py')} --export-env")
        return
    
    if args.export_config:
        os.system(f"python {os.path.join(PATHS['script_dir'], 'sap_audit_config.py')} --export-config")
        return
    
    # Override config with command line arguments
    if args.input_dir:
        os.environ["SAP_AUDIT_INPUT_DIR"] = args.input_dir
    if args.output_dir:
        os.environ["SAP_AUDIT_OUTPUT_DIR"] = args.output_dir
    if args.config_file:
        load_config_file(args.config_file)
    if args.debug:
        os.environ["SAP_AUDIT_DEBUG"] = "true"
        SETTINGS["debug"] = True
    if args.sysaid:
        CONFIG["enable_sysaid"] = True
    
    # Import the controller after all configuration is set
    try:
        from sap_audit_controller import AuditController
        
        log_message(f"Starting SAP Audit Tool v{VERSION}")
        log_message(f"Input directory: {PATHS['input_dir']}")
        log_message(f"Output directory: {PATHS['output_dir']}")
        
        # Run the audit controller
        controller = AuditController()
        controller.run()
        
        elapsed_time = datetime.now() - start_time
        log_message(f"Audit completed successfully in {elapsed_time}")
    
    except ImportError as e:
        log_message(f"Failed to import AuditController: {str(e)}", "ERROR")
        log_message("Make sure all dependencies are installed. Run: pip install -r requirements.txt", "ERROR")
        return 1
    except Exception as e:
        log_message(f"An error occurred: {str(e)}", "ERROR")
        if SETTINGS["debug"]:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
