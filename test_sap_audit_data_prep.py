#!/usr/bin/env python3
"""
Unit Tests for SAP Audit Data Preparation Module

This script tests the functionality of the refactored sap_audit_data_prep.py module,
verifying that the Factory pattern implementation and data processing work correctly.
"""

import os
import sys
import unittest
import pandas as pd
import tempfile
import shutil
from pathlib import Path

# Import the module to test
import sap_audit_data_prep
from sap_audit_config import COLUMNS

class TestDataSourceProcessor(unittest.TestCase):
    """Test cases for the base DataSourceProcessor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = sap_audit_data_prep.DataSourceProcessor("test")
        
        # Create a test DataFrame
        self.test_df = pd.DataFrame({
            'user': ['USER1', 'USER2'],
            'date': ['2025-05-01', '2025-05-02'],
            'time': ['10:00:00', '11:00:00'],
            'event': ['LOGIN', 'CHANGE']
        })
    
    def test_standardize_columns(self):
        """Test standardizing column names to uppercase."""
        # Create a DataFrame with mixed case columns
        df = pd.DataFrame({
            'User': ['USER1', 'USER2'],
            'Date': ['2025-05-01', '2025-05-02'],
            'time': ['10:00:00', '11:00:00'],
            'EVENT': ['LOGIN', 'CHANGE']
        })
        
        # Standardize columns
        result = self.processor.standardize_columns(df)
        
        # Check all columns are uppercase
        for col in result.columns:
            self.assertEqual(col, col.upper())
    
    def test_create_datetime_column(self):
        """Test creating datetime column from date and time fields."""
        # Use the test DataFrame
        result = self.processor.create_datetime_column(
            self.test_df, 'date', 'time')
        
        # Check datetime column was created
        self.assertIn('DATETIME', result.columns)
        
        # Check values are correct
        expected_dates = pd.to_datetime([
            '2025-05-01 10:00:00', 
            '2025-05-02 11:00:00'
        ])
        # Convert expected_dates to Series for comparison
        expected_series = pd.Series(expected_dates)
        pd.testing.assert_series_equal(
            result['DATETIME'], 
            expected_series,
            check_names=False
        )
    
    def test_add_missing_columns(self):
        """Test adding missing columns."""
        # List of required columns, including one that's missing
        required_cols = ['user', 'date', 'time', 'event', 'missing_col']
        
        # Add missing columns
        result = self.processor.add_missing_columns(self.test_df, required_cols)
        
        # Check missing column was added
        self.assertIn('missing_col', result.columns)
        
        # Check missing column has empty values
        self.assertTrue((result['missing_col'] == '').all())


class TestSM20Processor(unittest.TestCase):
    """Test cases for the SM20Processor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = sap_audit_data_prep.SM20Processor()
        
        # Create a test DataFrame with SM20 data
        self.test_df = pd.DataFrame({
            'USER': ['USER1', 'USER2'],
            'DATE': ['2025-05-01', '2025-05-02'],
            'TIME': ['10:00:00', '11:00:00'],
            'EVENT': ['AU1', 'AU3'],
            'SOURCE TA': ['SE16', 'SM59'],
            'ABAP SOURCE': ['PROGRAM1', 'PROGRAM2'],
            'AUDIT LOG MSG. TEXT': ['Message 1', 'Message 2']
        })
    
    def test_validate_sm20_data(self):
        """Test validating SM20 data."""
        # Should be valid with all required columns
        is_valid, missing = self.processor.validate_sm20_data(self.test_df)
        self.assertTrue(is_valid)
        self.assertEqual(len(missing), 0)
        
        # Create a DataFrame missing a required column
        invalid_df = self.test_df.drop(columns=['EVENT'])
        is_valid, missing = self.processor.validate_sm20_data(invalid_df)
        self.assertFalse(is_valid)
        self.assertIn(COLUMNS["sm20"]["event"], missing)
    
    def test_field_mapping(self):
        """Test field mapping for SM20 columns."""
        # Create a DataFrame with alternate column names
        alt_df = pd.DataFrame({
            'USERNAME': ['USER1', 'USER2'],
            'LOG_DATE': ['2025-05-01', '2025-05-02'],
            'LOG_TIME': ['10:00:00', '11:00:00'],
            'EVENT_TYPE': ['AU1', 'AU3'],
            'TRANSACTION': ['SE16', 'SM59'],
            'PROGRAM': ['PROGRAM1', 'PROGRAM2'],
            'MESSAGE': ['Message 1', 'Message 2']
        })
        
        # Get field mapping
        field_mapping = self.processor.get_sm20_field_mapping()
        
        # Apply field mapping
        result = self.processor.apply_field_mapping(alt_df, field_mapping)
        
        # Check that columns were mapped correctly
        self.assertIn(COLUMNS["sm20"]["user"], result.columns)
        self.assertIn(COLUMNS["sm20"]["date"], result.columns)
        self.assertIn(COLUMNS["sm20"]["time"], result.columns)
        self.assertIn(COLUMNS["sm20"]["event"], result.columns)
        self.assertIn(COLUMNS["sm20"]["tcode"], result.columns)
        self.assertIn(COLUMNS["sm20"]["abap_source"], result.columns)
        self.assertIn(COLUMNS["sm20"]["message"], result.columns)


class TestCDHDRProcessor(unittest.TestCase):
    """Test cases for the CDHDRProcessor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = sap_audit_data_prep.CDHDRProcessor()
        
        # Create a test DataFrame with CDHDR data
        self.test_df = pd.DataFrame({
            'USER': ['USER1', 'USER2'],
            'DATE': ['2025-05-01', '2025-05-02'],
            'TIME': ['10:00:00', '11:00:00'],
            'TCODE': ['SE16', 'SM59'],
            'DOC.NUMBER': ['0000000001', '0000000002'],
            'OBJECT': ['OBJECT1', 'OBJECT2'],
            'OBJECT VALUE': ['ID1', 'ID2']
        })
    
    def test_validate_cdhdr_data(self):
        """Test validating CDHDR data."""
        # Should be valid with all required columns
        is_valid, missing = self.processor.validate_cdhdr_data(self.test_df)
        self.assertTrue(is_valid)
        self.assertEqual(len(missing), 0)
        
        # Create a DataFrame missing a required column
        invalid_df = self.test_df.drop(columns=['DOC.NUMBER'])
        is_valid, missing = self.processor.validate_cdhdr_data(invalid_df)
        self.assertFalse(is_valid)
        self.assertIn(COLUMNS["cdhdr"]["change_number"], missing)


class TestCDPOSProcessor(unittest.TestCase):
    """Test cases for the CDPOSProcessor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = sap_audit_data_prep.CDPOSProcessor()
        
        # Create a test DataFrame with CDPOS data
        self.test_df = pd.DataFrame({
            'DOC.NUMBER': ['0000000001', '0000000002'],
            'TABLE NAME': ['USER_T', 'ROLE_T'],
            'TABLE KEY': ['KEY1', 'KEY2'],
            'FIELD NAME': ['FIELD1', 'FIELD2'],
            'CHANGE INDICATOR': ['u', 'I'],
            'NEW VALUE': ['NewVal1', 'NewVal2'],
            'OLD VALUE': ['OldVal1', 'OldVal2']
        })
    
    def test_validate_cdpos_data(self):
        """Test validating CDPOS data."""
        # Should be valid with all required columns
        is_valid, missing = self.processor.validate_cdpos_data(self.test_df)
        self.assertTrue(is_valid)
        self.assertEqual(len(missing), 0)
        
        # Create a DataFrame missing a required column
        invalid_df = self.test_df.drop(columns=['CHANGE INDICATOR'])
        is_valid, missing = self.processor.validate_cdpos_data(invalid_df)
        self.assertFalse(is_valid)
        self.assertIn(COLUMNS["cdpos"]["change_indicator"], missing)
    
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


class TestIntegration(unittest.TestCase):
    """Integration tests for the data preparation module."""
    
    def setUp(self):
        """Set up test environment with temporary directories."""
        # Create a temporary directory structure
        self.temp_dir = tempfile.mkdtemp()
        self.input_dir = os.path.join(self.temp_dir, "input")
        os.makedirs(self.input_dir, exist_ok=True)
        
        # Save the original PATTERNS
        self.original_patterns = sap_audit_data_prep.PATTERNS.copy()
        
        # Replace patterns for testing
        for key in sap_audit_data_prep.PATTERNS:
            sap_audit_data_prep.PATTERNS[key] = os.path.join(
                self.input_dir, f"*_{key}_*.xlsx")
    
    def tearDown(self):
        """Clean up temporary test environment."""
        # Restore original PATTERNS
        sap_audit_data_prep.PATTERNS = self.original_patterns
        
        # Remove temporary directory
        shutil.rmtree(self.temp_dir)
    
    def test_file_matching(self):
        """Test that file pattern matching works correctly."""
        # Create a test file
        test_file = os.path.join(self.input_dir, "test_sm20_export.xlsx")
        
        # Create a simple Excel file
        df = pd.DataFrame({
            'USER': ['USER1', 'USER2'],
            'DATE': ['2025-05-01', '2025-05-02'],
            'TIME': ['10:00:00', '11:00:00'],
            'EVENT': ['AU1', 'AU3']
        })
        df.to_excel(test_file, index=False)
        
        # Create SM20 processor
        processor = sap_audit_data_prep.SM20Processor()
        
        # Test finding the file
        found_file = processor.find_input_file()
        self.assertEqual(found_file, test_file)


if __name__ == "__main__":
    unittest.main()
