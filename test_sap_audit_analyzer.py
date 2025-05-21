#!/usr/bin/env python3
"""
Test suite for the SAP Audit Analyzer module.

This module contains unit tests for the SAPAuditAnalyzer class and its methods,
ensuring that the enhanced analysis features work as expected with various inputs.
"""

import os
import sys
import unittest
import pandas as pd
import numpy as np
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the module to test
from sap_audit_analyzer import SAPAuditAnalyzer
from sap_audit_config import PATHS


class TestSAPAuditAnalyzer(unittest.TestCase):
    """Test cases for the SAPAuditAnalyzer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create sample data for testing
        self.sample_data = self._create_sample_data()
        
        # Create a mock analyzer with test reference data
        self.analyzer = SAPAuditAnalyzer()
        
        # Override reference data with test data
        self.analyzer.tcode_descriptions = {
            "SM30": "Table Maintenance",
            "SE38": "ABAP Editor",
            "SU01": "User Maintenance",
            "FB03": "Display Document",
            "/H": "Debug Mode"
        }
        
        self.analyzer.event_descriptions = {
            "AU1": "Logon successful",
            "AUE": "Logoff",
            "BU": "Record creation",
            "BC": "Field modification",
            "BD": "Record deletion",
            "DB": "Debugger: Program stopped"
        }
        
        self.analyzer.table_descriptions = {
            "USR02": "User Password Data",
            "MARA": "Material Master",
            "BKPF": "Accounting Document Headers"
        }
        
        self.analyzer.high_risk_tcodes = {"SM30", "SE38", "SU01", "/H"}
        self.analyzer.high_risk_tcode_categories = {
            "SM30": "Table Maintenance",
            "SE38": "Development",
            "SU01": "Security Management",
            "/H": "Debugging"
        }
        
        self.analyzer.high_risk_tables = {"USR02"}
        self.analyzer.high_risk_table_categories = {
            "USR02": "Security"
        }
    
    def _create_sample_data(self):
        """Create sample data for testing."""
        data = {
            "Session ID": ["123", "123", "123", "456", "456", "789"],
            "User": ["ADMIN", "ADMIN", "ADMIN", "USER1", "USER1", "USER2"],
            "Datetime": ["2025-05-01 10:00:00", "2025-05-01 10:05:00", "2025-05-01 10:10:00",
                        "2025-05-01 11:00:00", "2025-05-01 11:05:00", "2025-05-01 12:00:00"],
            "Source": ["SM20", "SM20", "CDHDR", "SM20", "CDPOS", "SM20"],
            "TCode": ["SM30", "SE38", "FB03", "SU01", "", "/H"],
            "Event": ["", "", "", "AU1", "BC", "DB"],
            "Table": ["", "", "", "", "USR02", ""],
            "Description": ["Table maintenance", "Program development", "Display document", 
                            "User login", "Changed user password", "Debugger started"],
            "risk_level": ["High", "Critical", "Low", "Medium", "Critical", "High"],
            "risk_description": ["Table maintenance activity", "Development activity", "Display only activity",
                                "Security administration", "User password change", "Debugging activity"],
            "Change_Indicator": ["", "", "", "", "U", ""],
            "SYSAID #": ["12345", "12345", "12345", "", "", "67890"]
        }
        return pd.DataFrame(data)
    
    def test_load_reference_data(self):
        """Test loading reference data from files."""
        # Create a new analyzer with default paths
        analyzer = SAPAuditAnalyzer()
        
        # Verify that reference data is loaded
        self.assertGreater(len(analyzer.tcode_descriptions), 0, "TCode descriptions should be loaded")
        self.assertGreater(len(analyzer.event_descriptions), 0, "Event descriptions should be loaded")
        self.assertGreater(len(analyzer.high_risk_tcodes), 0, "High-risk TCodes should be loaded")
    
    def test_add_descriptive_columns(self):
        """Test adding descriptive columns to the data."""
        # Run the method
        df_enhanced = self.analyzer._add_descriptive_columns(self.sample_data.copy())
        
        # Verify TCode descriptions
        self.assertIn("TCode_Description", df_enhanced.columns)
        self.assertEqual(df_enhanced.loc[0, "TCode_Description"], "Table Maintenance")
        self.assertEqual(df_enhanced.loc[2, "TCode_Description"], "Display Document")
        
        # Verify Event descriptions
        self.assertIn("Event_Description", df_enhanced.columns)
        self.assertEqual(df_enhanced.loc[3, "Event_Description"], "Logon successful")
        self.assertEqual(df_enhanced.loc[4, "Event_Description"], "Field modification")
        
        # Verify Table descriptions
        self.assertIn("Table_Description", df_enhanced.columns)
        self.assertEqual(df_enhanced.loc[4, "Table_Description"], "User Password Data")
    
    def test_identify_table_maintenance(self):
        """Test identification of table maintenance activities."""
        # Run the method
        table_maintenance = self.analyzer._identify_table_maintenance(self.sample_data)
        
        # Verify identification
        self.assertEqual(table_maintenance.iloc[0], "Yes", "SM30 should be flagged as table maintenance")
        self.assertEqual(table_maintenance.iloc[1], "", "SE38 should not be flagged as table maintenance")
    
    def test_identify_high_risk_tcodes(self):
        """Test identification of high-risk transaction codes."""
        # Run the method
        high_risk = self.analyzer._identify_high_risk_tcodes(self.sample_data)
        
        # Verify identification
        self.assertEqual(high_risk.iloc[0], "Table Maintenance", "SM30 should be identified as Table Maintenance")
        self.assertEqual(high_risk.iloc[1], "Development", "SE38 should be identified as Development")
        self.assertEqual(high_risk.iloc[3], "Security Management", "SU01 should be identified as Security Management")
        self.assertEqual(high_risk.iloc[5], "Debugging", "/H should be identified as Debugging")
        self.assertEqual(high_risk.iloc[2], "", "FB03 should not be identified as high risk")
    
    def test_identify_change_activity(self):
        """Test identification of change activities."""
        # Run the method
        change_activity = self.analyzer._identify_change_activity(self.sample_data)
        
        # Verify identification
        self.assertEqual(change_activity.iloc[4], "02 - Update", "Change indicator U should be identified as Update")
        
        # Test with event codes
        modified_data = self.sample_data.copy()
        modified_data.loc[2, "Event"] = "BU"  # Record creation
        modified_data.loc[2, "Change_Indicator"] = ""
        
        change_activity = self.analyzer._identify_change_activity(modified_data)
        self.assertEqual(change_activity.iloc[2], "01 - Insert", "Event BU should be identified as Insert")
    
    def test_identify_transport_events(self):
        """Test identification of transport-related events."""
        # Modify sample data to include transport events
        modified_data = self.sample_data.copy()
        modified_data.loc[1, "TCode"] = "STMS"
        modified_data.loc[1, "Description"] = "Transport Management"
        
        # Run the method
        transport_related = self.analyzer._identify_transport_events(modified_data)
        
        # Verify identification
        self.assertEqual(transport_related.iloc[1], "Yes", "STMS should be identified as transport-related")
    
    def test_identify_debugging_events(self):
        """Test identification of debugging-related events."""
        # Run the method
        debugging_related = self.analyzer._identify_debugging_events(self.sample_data)
        
        # Verify identification
        self.assertEqual(debugging_related.iloc[5], "Yes", "/H with DB event should be identified as debugging-related")
    
    def test_identify_benign_activities(self):
        """Test identification of benign activities."""
        # Add needed columns to test data
        test_data = self.sample_data.copy()
        test_data["Change_Activity"] = ["", "", "", "", "", ""]
        test_data["Transport_Related_Event"] = ["", "", "", "", "", ""]
        test_data["Debugging_Related_Event"] = ["", "", "", "", "", ""]
        
        # Run the method
        benign_activity = self.analyzer._identify_benign_activities(test_data)
        
        # Verify identification
        self.assertEqual(benign_activity.iloc[2], "Display", "FB03 with Low risk should be identified as Display")
        self.assertEqual(benign_activity.iloc[3], "Logon", "AU1 event should be identified as Logon")
    
    def test_populate_conclusions_for_benign_activities(self):
        """Test auto-populating conclusions for benign activities."""
        # Prepare test data
        test_data = self.sample_data.copy()
        test_data["Benign_Activity"] = ["", "", "Display", "Logon", "", ""]
        test_data["Conclusion"] = ["", "", "", "", "", ""]
        
        # Run the method
        result = self.analyzer._populate_conclusions_for_benign_activities(test_data)
        
        # Verify conclusions
        self.assertEqual(
            result.loc[2, "Conclusion"],
            "Activity appears to be appropriate based on SysAid ticket (Display activity)",
            "Conclusion should be auto-populated for Display with SysAid"
        )
        
        # Verify activities without SysAid aren't auto-populated
        self.assertEqual(result.loc[3, "Conclusion"], "", "Activities without SysAid should not get auto-conclusions")
    
    def test_analyze_with_full_pipeline(self):
        """Test the full analyze method pipeline."""
        # Run the analyze method
        result = self.analyzer.analyze(self.sample_data)
        
        # Verify all expected columns are present
        expected_columns = [
            "TCode_Description", "Event_Description", "Table_Description",
            "Table_Maintenance", "High_Risk_TCode", "Change_Activity",
            "Transport_Related_Event", "Debugging_Related_Event", "Benign_Activity",
            "Observations", "Questions", "Response", "Conclusion"
        ]
        
        for col in expected_columns:
            self.assertIn(col, result.columns, f"Column {col} should be present in results")
        
        # Verify some specific values
        self.assertEqual(result.loc[0, "Table_Maintenance"], "Yes")
        self.assertEqual(result.loc[1, "High_Risk_TCode"], "Development")
        self.assertEqual(result.loc[5, "Debugging_Related_Event"], "Yes")
    
    def test_analyze_with_empty_data(self):
        """Test analyze method with empty dataframe."""
        # Create empty DataFrame
        empty_df = pd.DataFrame()
        
        # Run analyze method - should return empty DataFrame, not error
        result = self.analyzer.analyze(empty_df)
        self.assertTrue(result.empty)
    
    def test_analyze_with_missing_columns(self):
        """Test analyze method with missing columns."""
        # Create DataFrame with minimal columns
        minimal_df = pd.DataFrame({
            "Session ID": ["123"],
            "User": ["ADMIN"],
            "Datetime": ["2025-05-01 10:00:00"]
        })
        
        # Run analyze method - should add columns but not error
        result = self.analyzer.analyze(minimal_df)
        
        # Verify expected columns were added
        # Note: Only check for analysis columns since descriptive columns
        # depend on source columns like TCode, Event, and Table
        for col in ["Observations", "Questions", "Response", "Conclusion"]:
            self.assertIn(col, result.columns)
    
    def test_analyze_with_none_input(self):
        """Test analyze method with None input."""
        # Run analyze method with None
        result = self.analyzer.analyze(None)
        
        # Should return empty DataFrame
        self.assertIsInstance(result, pd.DataFrame)
        self.assertTrue(result.empty)


class TestSAPAuditAnalyzerWithFiles(unittest.TestCase):
    """Test cases that interact with actual reference files."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = SAPAuditAnalyzer()
        
        # Create sample data
        self.sample_data = pd.DataFrame({
            "Session ID": ["123", "456"],
            "User": ["ADMIN", "USER1"],
            "Datetime": ["2025-05-01 10:00:00", "2025-05-01 11:00:00"],
            "Source": ["SM20", "CDHDR"],
            "TCode": ["SM30", "FB03"],
            "Event": ["AU3", ""],
            "Table": ["USR02", ""],
            "Description": ["Table maintenance", "Display document"],
            "risk_level": ["High", "Low"],
            "SYSAID #": ["12345", ""]
        })
    
    def test_loading_real_reference_files(self):
        """Test loading real reference files."""
        # Verify TCodes reference
        tcodes_ref = PATHS.get("tcodes_reference")
        self.assertIsNotNone(tcodes_ref, "TCodes reference path should be defined")
        self.assertTrue(os.path.exists(tcodes_ref), "TCodes reference file should exist")
        
        # Verify Events reference
        events_ref = PATHS.get("events_reference")
        self.assertIsNotNone(events_ref, "Events reference path should be defined")
        self.assertTrue(os.path.exists(events_ref), "Events reference file should exist")
        
        # Verify HighRiskTCodes reference
        hr_tcodes_ref = PATHS.get("high_risk_tcodes")
        self.assertIsNotNone(hr_tcodes_ref, "HighRiskTCodes reference path should be defined")
        self.assertTrue(os.path.exists(hr_tcodes_ref), "HighRiskTCodes reference file should exist")
    
    def test_analyze_with_real_reference_data(self):
        """Test analyze method with real reference data."""
        # Run analyze method using actual reference files
        result = self.analyzer.analyze(self.sample_data)
        
        # Verify TCode descriptions were loaded
        self.assertIn("TCode_Description", result.columns)
        self.assertTrue(result.loc[0, "TCode_Description"] != "", "TCode description should be populated")
        
        # Verify Event descriptions were loaded
        self.assertIn("Event_Description", result.columns)
        self.assertTrue(result.loc[0, "Event_Description"] != "", "Event description should be populated")


if __name__ == "__main__":
    unittest.main()
