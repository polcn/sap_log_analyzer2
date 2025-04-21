#!/usr/bin/env python3
"""
SAP Audit Tool - Record Count Tracking Module

This module handles record count tracking and reconciliation for the SAP Log Analyzer.
It provides functions to track record counts from various data sources and calculate
completeness metrics for the final output.
"""

import os
import pandas as pd
from datetime import datetime
import json

# Define the path for the record counts metadata file
RECORD_COUNTS_FILE = "record_counts.json"

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

class RecordCounter:
    """
    Class to track record counts and calculate completeness metrics.
    """
    def __init__(self):
        """Initialize the record counter."""
        self.counts = {
            "sm20": {
                "file_name": "",
                "original_count": 0,
                "after_cleaning": 0,
                "final_count": 0
            },
            "cdhdr": {
                "file_name": "",
                "original_count": 0,
                "after_cleaning": 0,
                "final_count": 0
            },
            "cdpos": {
                "file_name": "",
                "original_count": 0,
                "after_cleaning": 0,
                "final_count": 0
            },
            "sysaid": {
                "file_name": "",
                "original_count": 0,
                "final_count": 0
            },
            "timeline": {
                "total_records": 0,
                "completeness_score": 0
            }
        }
    
    def update_source_counts(self, source_type, file_name, original_count, after_cleaning=None, final_count=None):
        """
        Update the record counts for a specific source.
        
        Args:
            source_type (str): Type of source (sm20, cdhdr, cdpos, sysaid)
            file_name (str): Name of the source file
            original_count (int): Original record count from the file
            after_cleaning (int, optional): Record count after cleaning. Defaults to None.
            final_count (int, optional): Final record count in the output. Defaults to None.
        """
        if source_type not in self.counts:
            log_message(f"Invalid source type: {source_type}", "WARNING")
            return
        
        self.counts[source_type]["file_name"] = os.path.basename(file_name)
        self.counts[source_type]["original_count"] = original_count
        
        if after_cleaning is not None:
            self.counts[source_type]["after_cleaning"] = after_cleaning
        
        if final_count is not None:
            self.counts[source_type]["final_count"] = final_count
    
    def update_timeline_count(self, total_records):
        """
        Update the total record count in the final timeline.
        
        Args:
            total_records (int): Total number of records in the final timeline
        """
        self.counts["timeline"]["total_records"] = total_records
        
        # Calculate completeness score based on total records compared to original counts
        source_total = (
            self.counts["sm20"]["original_count"] + 
            self.counts["cdhdr"]["original_count"] + 
            self.counts["cdpos"]["original_count"]
        )
        
        if source_total > 0:
            # Completeness is defined as the percentage of source records represented in the timeline
            # Note: This can exceed 100% if there's duplication in the timeline
            completeness = (total_records / source_total) * 100
            
            # Cap at 100% for reporting purposes
            self.counts["timeline"]["completeness_score"] = min(completeness, 100.0)
        else:
            self.counts["timeline"]["completeness_score"] = 0
    
    def calculate_percentage(self, source_type):
        """
        Calculate the percentage of records included in the final output.
        
        Args:
            source_type (str): Type of source (sm20, cdhdr, cdpos, sysaid)
            
        Returns:
            float: Percentage of records included
        """
        if source_type not in self.counts:
            return 0
        
        original = self.counts[source_type]["original_count"]
        final = self.counts[source_type]["final_count"]
        
        if original > 0:
            return (final / original) * 100
        return 0
    
    def save_to_file(self, file_path=RECORD_COUNTS_FILE):
        """
        Save record counts to a JSON file.
        
        Args:
            file_path (str, optional): Path to save the file. Defaults to RECORD_COUNTS_FILE.
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(self.counts, f, indent=4)
            log_message(f"Record counts saved to {file_path}")
            return True
        except Exception as e:
            log_message(f"Error saving record counts: {str(e)}", "ERROR")
            return False
    
    def load_from_file(self, file_path=RECORD_COUNTS_FILE):
        """
        Load record counts from a JSON file.
        
        Args:
            file_path (str, optional): Path to load the file from. Defaults to RECORD_COUNTS_FILE.
            
        Returns:
            bool: True if successfully loaded, False otherwise
        """
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    self.counts = json.load(f)
                log_message(f"Record counts loaded from {file_path}")
                return True
            return False
        except Exception as e:
            log_message(f"Error loading record counts: {str(e)}", "ERROR")
            return False
    
    def get_counts_for_report(self):
        """
        Get a formatted dictionary of record counts for reporting.
        
        Returns:
            dict: Formatted record counts for report display
        """
        report_data = {
            "source_files": [],
            "completeness_score": self.counts["timeline"]["completeness_score"]
        }
        
        for source_type in ["sm20", "cdhdr", "cdpos", "sysaid"]:
            if self.counts[source_type]["original_count"] > 0:
                report_data["source_files"].append({
                    "source_type": source_type.upper(),
                    "file_name": self.counts[source_type]["file_name"],
                    "original_count": self.counts[source_type]["original_count"],
                    "final_count": self.counts[source_type]["final_count"],
                    "percentage": self.calculate_percentage(source_type)
                })
        
        return report_data

# Global instance for use across modules
record_counter = RecordCounter()
