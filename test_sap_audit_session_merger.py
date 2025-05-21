#!/usr/bin/env python3
"""
Unit Tests for SAP Audit Session Merger Module

This script tests the functionality of the refactored sap_audit_session_merger.py module,
verifying that the class-based implementation and modular architecture work correctly.
"""

import os
import sys
import unittest
import pandas as pd
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

# Import the module to test
import sap_audit_session_merger
from sap_audit_config import COLUMNS, PATHS
from sap_audit_utils import handle_exception

class TestDataSourceProcessor(unittest.TestCase):
    """Test cases for the base DataSourceProcessor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = sap_audit_session_merger.DataSourceProcessor("test")
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test data file
        self.test_data = pd.DataFrame({
            'USER': ['USER1', 'USER2'],
            'DATE': ['2025-05-01', '2025-05-02'],
            'TIME': ['10:00:00', '11:00:00'],
            'EVENT': ['LOGIN', 'CHANGE']
        })
        
        self.test_file = os.path.join(self.temp_dir, "test.csv")
        self.test_data.to_csv(self.test_file, index=False)
    
    def tearDown(self):
        """Clean up after tests."""
        shutil.rmtree(self.temp_dir)
    
    def test_load_data(self):
        """Test loading data from a CSV file."""
        df = self.processor.load_data(self.test_file)
        self.assertEqual(len(df), 2)
        self.assertIn('USER', df.columns)
        
    def test_standardize_column_names(self):
        """Test standardizing column names to uppercase."""
        # Create a DataFrame with mixed case columns
        df = pd.DataFrame({
            'User': ['USER1', 'USER2'],
            'Date': ['2025-05-01', '2025-05-02'],
            'time': ['10:00:00', '11:00:00'],
            'EVENT': ['LOGIN', 'CHANGE']
        })
        
        # Standardize columns
        result = self.processor.standardize_column_names(df)
        
        # Check all columns are uppercase
        for col in result.columns:
            self.assertEqual(col, col.upper())
    
    def test_add_source_identifier(self):
        """Test adding source identifier column."""
        df = pd.DataFrame({'A': [1, 2], 'B': [3, 4]})
        result = self.processor.add_source_identifier(df)
        
        # Check source column was added
        self.assertIn('Source', result.columns)
        self.assertEqual(result['Source'].iloc[0], 'TEST')


class TestSM20Processor(unittest.TestCase):
    """Test cases for the SM20Processor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = sap_audit_session_merger.SM20Processor()
        
        # Create a test DataFrame with SM20 data
        self.test_df = pd.DataFrame({
            COLUMNS["sm20"]["user"]: ['USER1', 'USER2'],
            COLUMNS["sm20"]["date"]: ['2025-05-01', '2025-05-02'],
            COLUMNS["sm20"]["time"]: ['10:00:00', '11:00:00'],
            COLUMNS["sm20"]["event"]: ['AU1', 'AU3'],
            COLUMNS["sm20"]["tcode"]: ['SE16', 'SM59'],
            COLUMNS["sm20"]["abap_source"]: ['PROGRAM1', 'PROGRAM2'],
            COLUMNS["sm20"]["message"]: ['Message 1', 'Message 2']
        })
    
    def test_validate_sm20_data(self):
        """Test validating SM20 data."""
        # Should be valid with all required columns
        is_valid, missing = self.processor.validate_sm20_data(self.test_df)
        self.assertTrue(is_valid)
        self.assertEqual(len(missing), 0)
        
        # Create a DataFrame missing a required column
        invalid_df = self.test_df.drop(columns=[COLUMNS["sm20"]["event"]])
        is_valid, missing = self.processor.validate_sm20_data(invalid_df)
        self.assertFalse(is_valid)
        self.assertGreater(len(missing), 0)
    
    def test_create_datetime_column(self):
        """Test creating datetime column."""
        result = self.processor.create_datetime_column(self.test_df)
        
        # Check datetime column was created
        self.assertIn('Datetime', result.columns)
        
        # Check values are correct
        expected_dates = pd.to_datetime([
            '2025-05-01 10:00:00', 
            '2025-05-02 11:00:00'
        ])
        
        # Convert expected_dates to Series for comparison
        expected_series = pd.Series(expected_dates)
        pd.testing.assert_series_equal(
            result['Datetime'], 
            expected_series,
            check_names=False
        )


class TestCDHDRProcessor(unittest.TestCase):
    """Test cases for the CDHDRProcessor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = sap_audit_session_merger.CDHDRProcessor()
        
        # Create a test DataFrame with CDHDR data
        self.test_df = pd.DataFrame({
            COLUMNS["cdhdr"]["user"]: ['USER1', 'USER2'],
            COLUMNS["cdhdr"]["date"]: ['2025-05-01', '2025-05-02'],
            COLUMNS["cdhdr"]["time"]: ['10:00:00', '11:00:00'],
            COLUMNS["cdhdr"]["tcode"]: ['SE16', 'SM59'],
            COLUMNS["cdhdr"]["change_number"]: ['0000000001', '0000000002'],
            COLUMNS["cdhdr"]["object"]: ['OBJECT1', 'OBJECT2'],
            COLUMNS["cdhdr"]["object_id"]: ['ID1', 'ID2']
        })
    
    def test_validate_cdhdr_data(self):
        """Test validating CDHDR data."""
        # Should be valid with all required columns
        is_valid, missing = self.processor.validate_cdhdr_data(self.test_df)
        self.assertTrue(is_valid)
        self.assertEqual(len(missing), 0)
        
        # Create a DataFrame missing a required column
        invalid_df = self.test_df.drop(columns=[COLUMNS["cdhdr"]["change_number"]])
        is_valid, missing = self.processor.validate_cdhdr_data(invalid_df)
        self.assertFalse(is_valid)
        self.assertGreater(len(missing), 0)


class TestCDPOSProcessor(unittest.TestCase):
    """Test cases for the CDPOSProcessor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = sap_audit_session_merger.CDPOSProcessor()
        
        # Create a test DataFrame with CDPOS data
        self.test_df = pd.DataFrame({
            COLUMNS["cdpos"]["change_number"]: ['0000000001', '0000000002'],
            COLUMNS["cdpos"]["table_name"]: ['USER_T', 'ROLE_T'],
            COLUMNS["cdpos"]["table_key"]: ['KEY1', 'KEY2'],
            COLUMNS["cdpos"]["field_name"]: ['FIELD1', 'FIELD2'],
            COLUMNS["cdpos"]["change_indicator"]: ['u', 'I'],
            COLUMNS["cdpos"]["value_new"]: ['NewVal1', 'NewVal2'],
            COLUMNS["cdpos"]["value_old"]: ['OldVal1', 'OldVal2']
        })
    
    def test_validate_cdpos_data(self):
        """Test validating CDPOS data."""
        # Should be valid with all required columns
        is_valid, missing = self.processor.validate_cdpos_data(self.test_df)
        self.assertTrue(is_valid)
        self.assertEqual(len(missing), 0)
        
        # Create a DataFrame missing a required column
        invalid_df = self.test_df.drop(columns=[COLUMNS["cdpos"]["change_indicator"]])
        is_valid, missing = self.processor.validate_cdpos_data(invalid_df)
        self.assertFalse(is_valid)
        self.assertGreater(len(missing), 0)
    
    def test_standardize_change_indicators(self):
        """Test standardizing change indicators."""
        # Standardize change indicators
        result = self.processor.standardize_change_indicators(self.test_df)
        
        # Check all change indicators are uppercase
        all_uppercase = all(
            indicator.isupper() 
            for indicator in result[COLUMNS["cdpos"]["change_indicator"]]
        )
        self.assertTrue(all_uppercase)


class TestSessionMerger(unittest.TestCase):
    """Test cases for the SessionMerger class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.merger = sap_audit_session_merger.SessionMerger()
        
        # Create test data for SM20
        self.sm20_data = pd.DataFrame({
            COLUMNS["sm20"]["user"]: ['USER1', 'USER1', 'USER2'],
            COLUMNS["sm20"]["date"]: ['2025-05-01', '2025-05-01', '2025-05-02'],
            COLUMNS["sm20"]["time"]: ['10:00:00', '10:05:00', '11:00:00'],
            COLUMNS["sm20"]["event"]: ['AU1', 'AU2', 'AU3'],
            COLUMNS["sm20"]["tcode"]: ['SE16', 'SM59', 'SU01'],
            COLUMNS["sm20"]["abap_source"]: ['PROGRAM1', 'PROGRAM2', 'PROGRAM3'],
            COLUMNS["sm20"]["message"]: ['Message 1', 'Message 2', 'Message 3'],
            'SYSAID#': ['1001', '1001', '1002']
        })
        
        # Add Datetime column
        self.sm20_data['Datetime'] = pd.to_datetime(
            self.sm20_data[COLUMNS["sm20"]["date"]] + ' ' + 
            self.sm20_data[COLUMNS["sm20"]["time"]]
        )
        self.sm20_data['Source'] = 'SM20'
        
        # Create test data for CDHDR
        self.cdhdr_data = pd.DataFrame({
            COLUMNS["cdhdr"]["user"]: ['USER1', 'USER2'],
            COLUMNS["cdhdr"]["date"]: ['2025-05-01', '2025-05-02'],
            COLUMNS["cdhdr"]["time"]: ['10:10:00', '11:10:00'],
            COLUMNS["cdhdr"]["tcode"]: ['SE16', 'SU01'],
            COLUMNS["cdhdr"]["change_number"]: ['0000000001', '0000000002'],
            COLUMNS["cdhdr"]["object"]: ['OBJECT1', 'OBJECT2'],
            COLUMNS["cdhdr"]["object_id"]: ['ID1', 'ID2'],
            'SYSAID#': ['1001', '1002']
        })
        
        # Add Datetime column
        self.cdhdr_data['Datetime'] = pd.to_datetime(
            self.cdhdr_data[COLUMNS["cdhdr"]["date"]] + ' ' + 
            self.cdhdr_data[COLUMNS["cdhdr"]["time"]]
        )
        self.cdhdr_data['Source'] = 'CDHDR'
        
        # Create test data for CDPOS
        self.cdpos_data = pd.DataFrame({
            COLUMNS["cdpos"]["change_number"]: ['0000000001', '0000000002'],
            COLUMNS["cdpos"]["table_name"]: ['USER_T', 'ROLE_T'],
            COLUMNS["cdpos"]["table_key"]: ['KEY1', 'KEY2'],
            COLUMNS["cdpos"]["field_name"]: ['FIELD1', 'FIELD2'],
            COLUMNS["cdpos"]["change_indicator"]: ['U', 'I'],
            COLUMNS["cdpos"]["value_new"]: ['NewVal1', 'NewVal2'],
            COLUMNS["cdpos"]["value_old"]: ['OldVal1', 'OldVal2']
        })
    
    def test_find_sysaid_column(self):
        """Test finding SysAid column."""
        # Should find the SYSAID# column
        col = self.merger.find_sysaid_column(self.sm20_data)
        self.assertEqual(col, 'SYSAID#')
        
        # Should not find any SysAid column
        no_sysaid_df = self.sm20_data.drop(columns=['SYSAID#'])
        col = self.merger.find_sysaid_column(no_sysaid_df)
        self.assertIsNone(col)
    
    def test_standardize_sysaid_references(self):
        """Test standardizing SysAid references."""
        # Create a DataFrame with various SysAid formats
        df = pd.DataFrame({
            'SYSAID#': ['SR-1001', 'CR#1002', '#1003', '1004', 'nan']
        })
        
        # Standardize references
        result = self.merger.standardize_sysaid_references(df, 'SYSAID#')
        
        # Check standardization
        expected = ['1001', '1002', '1003', '1004', 'UNKNOWN']
        for i, exp in enumerate(expected):
            self.assertEqual(result['SYSAID#'].iloc[i], exp)
    
    def test_assign_session_ids_by_sysaid(self):
        """Test assigning session IDs by SysAid ticket."""
        result = self.merger.assign_session_ids_by_sysaid(
            self.sm20_data, 'SYSAID#', 'Datetime'
        )
        
        # Check session IDs assigned
        self.assertIn('Session ID', result.columns)
        self.assertIn('Session ID with Date', result.columns)
        
        # Check grouping by SysAid
        session_counts = result['Session ID'].value_counts()
        # Should have two unique sessions (from tickets 1001 and 1002)
        self.assertEqual(len(session_counts), 2)
    
    def test_assign_session_ids_by_user_date(self):
        """Test assigning session IDs by user and date."""
        # Create a DataFrame without SysAid column
        df = self.sm20_data.drop(columns=['SYSAID#'])
        
        result = self.merger.assign_session_ids_by_user_date(
            df, COLUMNS["sm20"]["user"], 'Datetime'
        )
        
        # Check session IDs assigned
        self.assertIn('Session ID', result.columns)
        self.assertIn('Session ID with Date', result.columns)
        
        # Check grouping by user+date
        session_counts = result['Session ID'].value_counts()
        # Should have two unique sessions (USER1 on day1, USER2 on day2)
        self.assertEqual(len(session_counts), 2)
    
    def test_merge_cdhdr_cdpos(self):
        """Test merging CDHDR with CDPOS data."""
        merged = self.merger.merge_cdhdr_cdpos(self.cdhdr_data, self.cdpos_data)
        
        # Check merge worked
        self.assertGreaterEqual(len(merged), len(self.cdhdr_data))
        
        # Check CDPOS columns are present in merged data
        self.assertIn(COLUMNS["cdpos"]["table_name"], merged.columns)
        
        # Check source field updated
        cdpos_count = sum(merged['Source'] == 'CDPOS')
        self.assertGreater(cdpos_count, 0)
    
    def test_prepare_sm20_for_timeline(self):
        """Test preparing SM20 data for timeline."""
        prepared = self.merger.prepare_sm20_for_timeline(self.sm20_data)
        
        # Check key fields are present and renamed
        self.assertIn(self.merger.session_cols["user"], prepared.columns)
        self.assertIn(self.merger.session_cols["tcode"], prepared.columns)
        self.assertIn(self.merger.session_cols["description"], prepared.columns)
        
        # Check empty columns added for CDPOS fields
        self.assertIn("Table", prepared.columns)
        self.assertIn("Field", prepared.columns)
    
    def test_create_unified_timeline(self):
        """Test creating unified timeline."""
        timeline = self.merger.create_unified_timeline(
            self.sm20_data, self.cdhdr_data
        )
        
        # Check timeline created
        self.assertIsNotNone(timeline)
        self.assertGreater(len(timeline), 0)
        
        # Check session IDs assigned
        self.assertIn('Session ID', timeline.columns)
        self.assertIn('Session ID with Date', timeline.columns)
        
        # Check sorting
        prev_session = None
        prev_time = None
        
        for _, row in timeline.iterrows():
            if prev_session is None:
                prev_session = row['Session ID']
                prev_time = row['Datetime']
                continue
                
            # Within same session, times should be in order
            if row['Session ID'] == prev_session:
                self.assertGreaterEqual(row['Datetime'], prev_time)
            
            prev_session = row['Session ID']
            prev_time = row['Datetime']


class TestIntegration(unittest.TestCase):
    """Integration tests for the session merger module."""
    
    def setUp(self):
        """Set up test environment with temporary directories."""
        # Create a temporary directory structure
        self.temp_dir = tempfile.mkdtemp()
        self.input_dir = os.path.join(self.temp_dir, "input")
        os.makedirs(self.input_dir, exist_ok=True)
        
        # Save the original paths
        self.original_paths = PATHS.copy()
        
        # Replace paths for testing
        for key in ["sm20_input", "cdhdr_input", "cdpos_input"]:
            PATHS[key] = os.path.join(self.input_dir, os.path.basename(PATHS[key]))
        
        # Replace output path
        PATHS["session_timeline"] = os.path.join(self.temp_dir, "test_timeline.xlsx")
    
    def tearDown(self):
        """Clean up temporary test environment."""
        # Restore original paths
        for key, value in self.original_paths.items():
            PATHS[key] = value
        
        # Remove temporary directory
        shutil.rmtree(self.temp_dir)
    
    def create_test_files(self):
        """Create test input files."""
        # Create SM20 test file
        sm20_data = pd.DataFrame({
            COLUMNS["sm20"]["user"]: ['USER1', 'USER1', 'USER2'],
            COLUMNS["sm20"]["date"]: ['2025-05-01', '2025-05-01', '2025-05-02'],
            COLUMNS["sm20"]["time"]: ['10:00:00', '10:05:00', '11:00:00'],
            COLUMNS["sm20"]["event"]: ['AU1', 'AU2', 'AU3'],
            COLUMNS["sm20"]["tcode"]: ['SE16', 'SM59', 'SU01'],
            COLUMNS["sm20"]["abap_source"]: ['PROGRAM1', 'PROGRAM2', 'PROGRAM3'],
            COLUMNS["sm20"]["message"]: ['Message 1', 'Message 2', 'Message 3'],
            'SYSAID#': ['1001', '1001', '1002']
        })
        sm20_data.to_csv(PATHS["sm20_input"], index=False)
        
        # Create CDHDR test file
        cdhdr_data = pd.DataFrame({
            COLUMNS["cdhdr"]["user"]: ['USER1', 'USER2'],
            COLUMNS["cdhdr"]["date"]: ['2025-05-01', '2025-05-02'],
            COLUMNS["cdhdr"]["time"]: ['10:10:00', '11:10:00'],
            COLUMNS["cdhdr"]["tcode"]: ['SE16', 'SU01'],
            COLUMNS["cdhdr"]["change_number"]: ['0000000001', '0000000002'],
            COLUMNS["cdhdr"]["object"]: ['OBJECT1', 'OBJECT2'],
            COLUMNS["cdhdr"]["object_id"]: ['ID1', 'ID2'],
            'SYSAID#': ['1001', '1002']
        })
        cdhdr_data.to_csv(PATHS["cdhdr_input"], index=False)
        
        # Create CDPOS test file
        cdpos_data = pd.DataFrame({
            COLUMNS["cdpos"]["change_number"]: ['0000000001', '0000000002'],
            COLUMNS["cdpos"]["table_name"]: ['USER_T', 'ROLE_T'],
            COLUMNS["cdpos"]["table_key"]: ['KEY1', 'KEY2'],
            COLUMNS["cdpos"]["field_name"]: ['FIELD1', 'FIELD2'],
            COLUMNS["cdpos"]["change_indicator"]: ['U', 'I'],
            COLUMNS["cdpos"]["value_new"]: ['NewVal1', 'NewVal2'],
            COLUMNS["cdpos"]["value_old"]: ['OldVal1', 'OldVal2']
        })
        cdpos_data.to_csv(PATHS["cdpos_input"], index=False)
    
    def test_end_to_end(self):
        """Test the end-to-end process."""
        # Create test files
        self.create_test_files()
        
        # Create a merger and run the process
        merger = sap_audit_session_merger.SessionMerger()
        result = merger.process()
        
        # Check process succeeded
        self.assertTrue(result)
        
        # Check output file exists
        self.assertTrue(os.path.exists(PATHS["session_timeline"]))
        
        # Try to read the output file
        try:
            df = pd.read_excel(PATHS["session_timeline"])
            self.assertGreater(len(df), 0)
        except Exception as e:
            self.fail(f"Failed to read output file: {str(e)}")


if __name__ == "__main__":
    unittest.main()
