#!/usr/bin/env python3
"""
Test script for SAP Audit SysAid Integration module.

This script performs comprehensive testing of the SysAid ticket integration:
1. Tests loading of SysAid ticket data
2. Tests merging of SysAid ticket data with session timeline
3. Tests various ticket matching scenarios
4. Tests Excel formatting of SysAid fields

Usage:
    python test_sap_audit_sysaid.py
"""

import os
import sys
import pandas as pd
import numpy as np
import shutil
from datetime import datetime
import unittest
from io import StringIO
import tempfile

# Import the module to test
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import sap_audit_sysaid
import sap_audit_tool_output  # For testing Excel formatting

# Redirect stdout to capture log messages
original_stdout = sys.stdout

class TestSysAidIntegration(unittest.TestCase):
    """Test cases for SysAid ticket integration."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.input_dir = os.path.join(self.test_dir, "input")
        os.makedirs(self.input_dir, exist_ok=True)
        
        # Store original constants
        self.original_input_dir = sap_audit_sysaid.INPUT_DIR
        self.original_sysaid_file = sap_audit_sysaid.SYSAID_FILE
        
        # Modify constants for testing
        sap_audit_sysaid.INPUT_DIR = self.input_dir
        sap_audit_sysaid.SYSAID_FILE = os.path.join(self.input_dir, "SysAid.xlsx")
        
        # Create output capture
        self.output = StringIO()
        sys.stdout = self.output
    
    def tearDown(self):
        """Clean up after test."""
        # Restore original constants
        sap_audit_sysaid.INPUT_DIR = self.original_input_dir
        sap_audit_sysaid.SYSAID_FILE = self.original_sysaid_file
        
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
        
        # Restore stdout
        sys.stdout = original_stdout
    
    def create_test_sysaid_file(self, column_format="standard"):
        """Create a test SysAid ticket file."""
        # Define column headers based on variation
        if column_format == "standard":
            columns = {
                "Service Record Type": ["Incident", "Incident", "Service Request"],
                "Status": ["Verified closed", "Open", "In progress"],
                "Ticket": [114484, 114488, 114489],
                "Category": ["IS Systems Software", "IS Network", "SAP"],
                "Sub-Category": ["SAP Canada", "LAN", "SAP Security"],
                "Title": [
                    "SAP - Orders going on hold", 
                    "Network connectivity issues", 
                    "SAP role access update"
                ],
                "Description": [
                    "SAP - Orders going on hold when the customer has the credit for the order. Need to see what the reason is for this.",
                    "Network connectivity issues between locations",
                    "Need to update role access for department"
                ],
                "Notes": [
                    "Investigated with user.", 
                    np.nan,
                    "Role update completed"
                ],
                "Request user": ["Lisa Kaminski", "John Smith", "Maria Garcia"],
                "Process manager": ["Nikhil Agarwal", "Ahmad Khan", "Sarah Johnson"],
                "Priority": ["Medium", "High", "Low"],
                "Request time": ["10/01/2024 02:55 PM", "10/01/2024 06:04 PM", "10/01/2024 06:11 PM"]
            }
        elif column_format == "alternative":
            # Test with alternative column names for ticket field
            columns = {
                "Service Record Type": ["Incident", "Incident", "Service Request"],
                "Status": ["Verified closed", "Open", "In progress"],
                "Ticket #": [114484, 114488, 114489],  # Different column name for ticket
                "Category": ["IS Systems Software", "IS Network", "SAP"],
                "Sub-Category": ["SAP Canada", "LAN", "SAP Security"],
                "Title": [
                    "SAP - Orders going on hold", 
                    "Network connectivity issues", 
                    "SAP role access update"
                ],
                "Description": [
                    "SAP - Orders going on hold when the customer has the credit for the order. Need to see what the reason is for this.",
                    "Network connectivity issues between locations",
                    "Need to update role access for department"
                ],
                "Notes": [
                    "Investigated with user.", 
                    np.nan,
                    "Role update completed"
                ],
                "Request user": ["Lisa Kaminski", "John Smith", "Maria Garcia"],
                "Process manager": ["Nikhil Agarwal", "Ahmad Khan", "Sarah Johnson"],
                "Priority": ["Medium", "High", "Low"],
                "Request time": ["10/01/2024 02:55 PM", "10/01/2024 06:04 PM", "10/01/2024 06:11 PM"]
            }
        
        # Create DataFrame
        df = pd.DataFrame(columns)
        
        # Add a few more tickets
        for i in range(3, 10):
            new_row = {
                "Service Record Type": "Incident",
                "Status": "Closed",
                "Title": f"Test Ticket {i}",
                "Description": f"Description for test ticket {i}",
                "Request user": "Test User",
                "Process manager": "Test Manager",
                "Priority": "Medium",
                "Request time": "10/02/2024 09:00 AM"
            }
            
            # Add ticket ID based on format
            if column_format == "standard":
                new_row["Ticket"] = 114500 + i
            else:
                new_row["Ticket #"] = 114500 + i
                
            df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
        
        # Save to Excel - create a 'Report' sheet to match SysAid export format
        output_path = sap_audit_sysaid.SYSAID_FILE
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name="Report", index=False)
        
        return output_path
    
    def create_test_session_data(self, include_ticket_field=True):
        """Create test session timeline data."""
        # Create base session data
        session_data = {
            "Session ID with Date": ["2025-04-01_USER1", "2025-04-01_USER1", "2025-04-01_USER2"],
            "Source": ["SM20", "SM20", "CDHDR"],
            "User": ["USER1", "USER1", "USER2"],
            "Datetime": [
                pd.Timestamp("2025-04-01 09:30:00"),
                pd.Timestamp("2025-04-01 09:45:00"),
                pd.Timestamp("2025-04-01 10:30:00")
            ],
            "Event": ["AU1", "AU3", ""],
            "TCode": ["SE16", "SE01", "SE38"],
            "Description": [
                "User accessed table MARA",
                "Table display",
                "System function accessed"
            ],
            "Note": ["", "With debug", ""],
            "Table": ["MARA", "", "MARC"],
            "Field": ["MATNR", "", "WERKS"],
            "risk_level": ["Medium", "High", "Low"]
        }
        
        # Add SysAid ticket field if requested
        if include_ticket_field:
            session_data["SYSAID #"] = ["114484", "", "114488"]
        
        # Create DataFrame
        df = pd.DataFrame(session_data)
        return df
    
    def test_load_sysaid_data_standard(self):
        """Test loading of SysAid data with standard column names."""
        # Create test SysAid file
        self.create_test_sysaid_file(column_format="standard")
        
        # Load the data
        sysaid_df = sap_audit_sysaid.load_sysaid_data()
        
        # Verify successful loading
        self.assertIsNotNone(sysaid_df)
        self.assertGreater(len(sysaid_df), 0)
        
        # Verify correct ticket column was found
        self.assertEqual(sap_audit_sysaid.SYSAID_TICKET_COL, "Ticket")
        
        # Verify critical columns exist
        essential_cols = [
            sap_audit_sysaid.SYSAID_TICKET_COL,
            sap_audit_sysaid.SYSAID_TITLE_COL,
            sap_audit_sysaid.SYSAID_DESCRIPTION_COL
        ]
        for col in essential_cols:
            self.assertIn(col, sysaid_df.columns)
    
    def test_load_sysaid_data_alternative(self):
        """Test loading of SysAid data with alternative column names."""
        # Create test SysAid file with alternative column names
        self.create_test_sysaid_file(column_format="alternative")
        
        # Load the data
        sysaid_df = sap_audit_sysaid.load_sysaid_data()
        
        # Verify successful loading
        self.assertIsNotNone(sysaid_df)
        self.assertGreater(len(sysaid_df), 0)
        
        # Verify correct ticket column was found using case-insensitive matching
        self.assertEqual(sap_audit_sysaid.SYSAID_TICKET_COL, "Ticket #")
    
    def test_merge_sysaid_data(self):
        """Test merging of SysAid data with session timeline."""
        # Create test files
        self.create_test_sysaid_file()
        session_df = self.create_test_session_data()
        
        # Load SysAid data
        sysaid_df = sap_audit_sysaid.load_sysaid_data()
        
        # Merge the data
        result_df = sap_audit_sysaid.merge_sysaid_data(session_df, sysaid_df)
        
        # Verify successful merging
        self.assertIsNotNone(result_df)
        self.assertEqual(len(result_df), len(session_df))
        
        # Verify SysAid fields were added
        sysaid_fields = [
            sap_audit_sysaid.SYSAID_TITLE_COL,
            "SysAid Description",  # New renamed field
            sap_audit_sysaid.SYSAID_NOTES_COL,
            sap_audit_sysaid.SYSAID_REQUEST_USER_COL,
            sap_audit_sysaid.SYSAID_PROCESS_MANAGER_COL,
            sap_audit_sysaid.SYSAID_REQUEST_TIME_COL
        ]
        for field in sysaid_fields:
            self.assertIn(field, result_df.columns)
        
        # Verify ticket data was merged correctly
        matched_row = result_df[result_df[sap_audit_sysaid.SAP_SYSAID_COL_ADDED] == "114484"]
        self.assertEqual(len(matched_row), 1)
        # Check that some SysAid data is present
        self.assertIn("Orders going on hold", matched_row['Title'].iloc[0])
    
    def test_merge_without_sysaid_field(self):
        """Test merging when session data doesn't have SysAid field."""
        # Create test files
        self.create_test_sysaid_file()
        session_df = self.create_test_session_data(include_ticket_field=False)
        
        # Load SysAid data
        sysaid_df = sap_audit_sysaid.load_sysaid_data()
        
        # Merge the data
        result_df = sap_audit_sysaid.merge_sysaid_data(session_df, sysaid_df)
        
        # Verify SysAid field was added
        self.assertIn(sap_audit_sysaid.SAP_SYSAID_COL_ADDED, result_df.columns)
    
    def test_nan_handling_in_sysaid(self):
        """Test handling of NaN values in SysAid data."""
        # Create test files
        self.create_test_sysaid_file()
        session_df = self.create_test_session_data()
        
        # Load SysAid data
        sysaid_df = sap_audit_sysaid.load_sysaid_data()
        
        # Merge the data
        result_df = sap_audit_sysaid.merge_sysaid_data(session_df, sysaid_df)
        
        # Verify NaN values are handled as empty strings
        for col in result_df.columns:
            col_values = result_df[col].astype(str)
            self.assertTrue(not any(val.lower() == 'nan' for val in col_values))
    
    def test_excel_formatting(self):
        """Test Excel formatting of SysAid fields."""
        # Instead of directly accessing column_sources (which is function-scoped),
        # we'll verify that the SysAid color constant is defined
        
        # Create a temporary Excel writer
        with tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False) as temp_file:
            excel_path = temp_file.name
        
        try:
            # Verify SysAid color constant is defined (used for formatting SysAid columns)
            self.assertTrue(hasattr(sap_audit_tool_output, 'SYSAID_COLOR'))
            self.assertTrue(sap_audit_tool_output.SYSAID_COLOR.startswith('#'))
            
            # Verify SysAid color is correctly set
            self.assertEqual(sap_audit_tool_output.SYSAID_COLOR, '#D9D2E9', 
                           "SysAid color should be light purple (#D9D2E9)")
            
            # Check for required columns in SESSION_ESSENTIAL_COLUMNS
            if hasattr(sap_audit_tool_output, 'SESSION_ESSENTIAL_COLUMNS'):
                sysaid_essential_cols = ['SYSAID #', 'Title', 'SysAid Description', 
                                        'Notes', 'Request user', 'Process manager', 'Request time']
                for col in sysaid_essential_cols:
                    self.assertIn(col, sap_audit_tool_output.SESSION_ESSENTIAL_COLUMNS,
                                f"Column '{col}' should be in SESSION_ESSENTIAL_COLUMNS")
        finally:
            # Clean up
            if os.path.exists(excel_path):
                os.unlink(excel_path)

def run_tests():
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

if __name__ == "__main__":
    print("\n" + "="*80)
    print(" SAP AUDIT SYSAID INTEGRATION - TEST SUITE ".center(80, "*"))
    print("="*80 + "\n")
    run_tests()
