#!/usr/bin/env python3
"""
SAP Audit Tool - Main Controller Module

This module provides the AuditController class that orchestrates the entire SAP audit workflow,
connecting all refactored modules into a cohesive pipeline.

Key features:
- Central AuditController class to orchestrate workflow
- Pipeline architecture connecting all refactored modules
- Validation between processing steps
- Progress tracking and reporting
- Unified error handling system
- Configuration validation at startup
"""

import os
import pandas as pd
from datetime import datetime
import time
from typing import Dict, List, Optional, Union, Any, Tuple

# Import configuration and utilities
from sap_audit_config import CONFIG, PATHS, SETTINGS
from sap_audit_utils import (
    log_message, log_section, log_error, handle_exception,
    clean_whitespace, validate_required_columns
)

# Import refactored modules
from sap_audit_data_prep import DataPrepManager
from sap_audit_session_merger import SessionMerger
from sap_audit_risk import RiskAssessor
from sap_audit_analyzer import SAPAuditAnalyzer
from sap_audit_sysaid_integrator import SysAidIntegrator
from sap_audit_output import ExcelOutputGenerator, CsvOutputGenerator

# Import record counter if available
try:
    from sap_audit_record_counts import record_counter
except ImportError:
    # Placeholder if record counter is not available
    class RecordCounter:
        def update_source_counts(self, source_type, file_name, original_count, final_count):
            pass
        
        def update_timeline_count(self, total_records, source_counts=None):
            pass
        
        def get_counts_for_report(self):
            return {"completeness_score": 0, "source_files": []}
    
    record_counter = RecordCounter()


class AuditController:
    """
    Main controller class that orchestrates the entire audit workflow.
    
    This class connects all the refactored modules into a cohesive pipeline
    and provides methods for running the full audit or individual steps.
    """
    
    def __init__(self, config=None):
        """
        Initialize controller with optional config override.
        
        Args:
            config: Dictionary with configuration overrides
        """
        self.config = config or CONFIG
        self.paths = PATHS
        self.settings = SETTINGS
        
        # Initialize session state
        self.session_data = None
        
        # Initialize components
        self.data_prep = DataPrepManager()
        self.session_merger = SessionMerger()
        self.risk_assessor = RiskAssessor()
        self.analyzer = SAPAuditAnalyzer()
        self.sysaid_integrator = SysAidIntegrator(
            data_source_strategy=self.config.get("sysaid_source", "file")
        )
        
        # Initialize output generator based on configured format
        output_format = self.config.get("output_format", "excel")
        if output_format.lower() == "csv":
            self.output_generator = CsvOutputGenerator()
        else:
            self.output_generator = ExcelOutputGenerator()
        
        # Initialize timing metrics
        self.start_time = None
        self.end_time = None
        self.elapsed_time = None
    
    @handle_exception
    def run_full_audit(self):
        """
        Run the complete audit process from data prep to output.
        
        Returns:
            bool: Success status
        """
        # Start timing
        self.start_time = time.time()
        
        log_section("Starting Full SAP Audit")
        log_message(f"Using configuration: {self.config}")
        
        # Step 1: Validate configuration
        if not self._validate_configuration():
            log_message("Configuration validation failed, cannot continue", "ERROR")
            return False
        
        # Step 2: Data preparation
        if not self.run_data_preparation():
            log_message("Data preparation failed, cannot continue", "ERROR")
            return False
            
        # Step 3: Session merging
        if not self.run_session_merging():
            log_message("Session merging failed, cannot continue", "ERROR")
            return False
            
        # Step 4: Risk assessment
        if not self.run_risk_assessment():
            log_message("Risk assessment failed", "ERROR")
            return False
            
        # Step 5: SysAid integration
        if not self.run_sysaid_integration():
            log_message("SysAid integration failed or skipped", "WARNING")
            # Continue anyway, as SysAid is optional
            
        # Step 6: Enhanced analysis
        if not self.run_enhanced_analysis():
            log_message("Enhanced analysis failed", "WARNING")
            # Continue anyway, as this is an enhancement
            
        # Step 7: Output generation
        if not self.generate_output():
            log_message("Output generation failed", "ERROR")
            return False
        
        # End timing
        self.end_time = time.time()
        self.elapsed_time = self.end_time - self.start_time
        
        # Log completion
        hours, remainder = divmod(self.elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        log_message(f"Full audit completed in {int(hours)}h {int(minutes)}m {int(seconds)}s")
        
        return True
    
    @handle_exception
    def run_data_preparation(self):
        """
        Run data preparation step.
        
        Returns:
            bool: Success status
        """
        log_section("Running Data Preparation")
        
        # Data preparation is done independently, no need to return data
        success = self.data_prep.process_input_files()
        
        if not success:
            log_message("Data preparation failed", "ERROR")
            return False
        
        log_message("Data preparation completed successfully")
        return True
    
    @handle_exception
    def run_session_merging(self):
        """
        Run session merger step.
        
        Returns:
            bool: Success status
        """
        log_section("Running Session Merger")
        
        # Run the session merger
        self.session_data = self.session_merger.merge_sessions()
        
        if self.session_data is None or len(self.session_data) == 0:
            log_message("Session merger produced no results", "ERROR")
            return False
        
        # Validate the result
        required_cols = ["Session ID", "User", "Datetime", "Source"]
        is_valid, missing_cols = validate_required_columns(self.session_data, required_cols, "Session Timeline")
        if not is_valid:
            log_message(f"Session data missing required columns: {', '.join(missing_cols)}", "ERROR")
            return False
        
        log_message(f"Session merger completed with {len(self.session_data)} records")
        return True
    
    @handle_exception
    def run_risk_assessment(self):
        """
        Run risk assessment step.
        
        Returns:
            bool: Success status
        """
        log_section("Running Risk Assessment")
        
        if self.session_data is None:
            log_message("No session data available for risk assessment", "ERROR")
            return False
        
        # Run risk assessment
        self.session_data = self.risk_assessor.assess_risk(self.session_data)
        
        if "risk_level" not in self.session_data.columns:
            log_message("Risk assessment did not produce risk levels", "ERROR")
            return False
        
        # Log risk statistics
        risk_counts = self.session_data["risk_level"].value_counts().to_dict()
        log_message("Risk assessment results:")
        log_message(f"  Critical: {risk_counts.get('Critical', 0)}")
        log_message(f"  High: {risk_counts.get('High', 0)}")
        log_message(f"  Medium: {risk_counts.get('Medium', 0)}")
        log_message(f"  Low: {risk_counts.get('Low', 0)}")
        
        return True
    
    @handle_exception
    def run_sysaid_integration(self):
        """
        Run SysAid integration step.
        
        Returns:
            bool: Success status
        """
        log_section("Running SysAid Integration")
        
        if self.session_data is None:
            log_message("No session data available for SysAid integration", "ERROR")
            return False
        
        # Check if SysAid integration is enabled
        if not self.config.get("enable_sysaid", True):
            log_message("SysAid integration is disabled in config, skipping", "INFO")
            return True
        
        # Run SysAid integration
        self.session_data = self.sysaid_integrator.enhance_session_timeline(self.session_data)
        
        # We don't fail if SysAid integration didn't add ticket info, as it's optional
        return True
    
    @handle_exception
    def run_enhanced_analysis(self):
        """
        Run enhanced analysis to add descriptive columns and analysis flags.
        
        Returns:
            bool: Success status
        """
        log_section("Running Enhanced Analysis")
        
        if self.session_data is None:
            log_message("No session data available for enhanced analysis", "ERROR")
            return False
        
        # Run enhanced analysis
        try:
            self.session_data = self.analyzer.analyze(self.session_data)
            
            # Check if key columns were added
            if "TCode_Description" not in self.session_data.columns:
                log_message("Enhanced analysis did not produce expected columns", "WARNING")
                # Don't fail, just warn
                
            log_message(f"Enhanced analysis completed successfully with {len(self.session_data.columns)} columns")
            return True
        except Exception as e:
            log_error(e, "Error during enhanced analysis")
            # Continue with original data if analysis fails
            return False
    
    @handle_exception
    def generate_output(self):
        """
        Generate output reports.
        
        Returns:
            bool: Success status
        """
        log_section("Generating Output")
        
        if self.session_data is None:
            log_message("No session data available for output generation", "ERROR")
            return False
        
        # Get the output path from config or use default
        output_path = self.config.get("output_path") or self.paths.get("audit_report")
        
        # Generate the output
        success = self.output_generator.generate_report(self.session_data, output_path)
        
        if not success:
            log_message("Output generation failed", "ERROR")
            return False
        
        log_message(f"Output generated successfully: {output_path}")
        return True
    
    def _validate_configuration(self):
        """
        Validate the configuration at startup.
        
        Returns:
            bool: Validation status
        """
        # Check for required paths
        required_paths = ["input_dir", "output_dir", "audit_report"]
        for path_name in required_paths:
            if path_name not in self.paths:
                log_message(f"Missing required path: {path_name}", "ERROR")
                return False
            
            path_value = self.paths[path_name]
            
            # For directories, verify they exist or can be created
            if path_name.endswith("_dir"):
                try:
                    os.makedirs(path_value, exist_ok=True)
                except Exception as e:
                    log_message(f"Cannot create directory {path_value}: {str(e)}", "ERROR")
                    return False
        
        # Validate SysAid configuration if enabled
        if self.config.get("enable_sysaid", True):
            sysaid_source = self.config.get("sysaid_source", "file")
            
            if sysaid_source == "file":
                sysaid_file = self.paths.get("sysaid_input")
                if not sysaid_file or not os.path.exists(sysaid_file):
                    log_message(f"SysAid file not found: {sysaid_file}", "WARNING")
                    # Don't fail, just warn - SysAid is optional
            elif sysaid_source == "api":
                if not self.config.get("sysaid_api_url"):
                    log_message("SysAid API URL not configured", "WARNING")
                    # Don't fail, just warn - will use cache if available
        
        log_message("Configuration validation completed")
        return True


# Example usage
if __name__ == "__main__":
    controller = AuditController()
    success = controller.run_full_audit()
    
    if success:
        log_message("Audit completed successfully")
    else:
        log_message("Audit completed with errors", "ERROR")
