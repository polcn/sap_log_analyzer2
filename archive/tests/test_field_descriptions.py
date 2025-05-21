#!/usr/bin/env python3
"""
SAP Audit Tool - Field Description Test Script

This script tests the field description functionality in the SAP Audit Tool,
focusing on vendor-related fields (KRED, KREDI, KTOKK, XCPDK) and overall
field description handling.
"""

import os
import sys
import pandas as pd
import inspect
from datetime import datetime

# Add script directory to Python path for module imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# Import the risk assessment module
try:
    from sap_audit_tool_risk_assessment import (
        get_common_field_descriptions,
        get_critical_field_patterns,
        get_critical_field_pattern_descriptions,
        get_field_info,
        custom_field_risk_assessment,
        assess_risk_session
    )
    print("Successfully imported risk assessment functions")
except ImportError as e:
    print(f"Error importing risk assessment module: {str(e)}")
    sys.exit(1)

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def test_field_descriptions_exist():
    """Test that field descriptions exist for key fields."""
    log_message("Testing field descriptions exist for key fields...")
    
    # Get field descriptions
    field_descriptions = get_common_field_descriptions()
    
    # Define key vendor fields to test
    vendor_fields = ["KRED", "KREDI", "KTOKK", "XCPDK"]
    
    # Check each field exists in the descriptions dictionary
    missing_fields = []
    for field in vendor_fields:
        if field not in field_descriptions:
            missing_fields.append(field)
            log_message(f"Field '{field}' is missing a description", "ERROR")
        else:
            log_message(f"Field '{field}' has description: {field_descriptions[field]}", "SUCCESS")
    
    # Report overall result
    if not missing_fields:
        log_message("All key vendor fields have descriptions", "SUCCESS")
        return True
    else:
        log_message(f"Missing descriptions for fields: {', '.join(missing_fields)}", "ERROR")
        return False

def test_field_description_format():
    """Test that field descriptions follow the proper format."""
    log_message("Testing field description format...")
    
    # Get field descriptions
    field_descriptions = get_common_field_descriptions()
    
    # Check format for all fields
    malformatted_fields = []
    for field, description in field_descriptions.items():
        # Check if description follows "Short description - More detailed explanation" format
        if " - " not in description:
            malformatted_fields.append(field)
            log_message(f"Field '{field}' has malformatted description: {description}", "ERROR")
    
    # Report overall result
    if not malformatted_fields:
        log_message("All field descriptions follow the proper format", "SUCCESS")
        return True
    else:
        log_message(f"Malformatted descriptions for fields: {', '.join(malformatted_fields)}", "ERROR")
        return False

def test_get_field_info_function():
    """Test the get_field_info function with various inputs."""
    log_message("Testing get_field_info function...")
    
    # Get field descriptions
    field_descriptions = get_common_field_descriptions()
    
    # Define test cases
    test_cases = [
        # (field_value, expected_contains)
        ("KRED", "Vendor Account"),          # Existing field with description
        ("UNKNOWN_FIELD", "UNKNOWN_FIELD"),  # Field without description
        ("", "unknown"),                     # Empty field
        (None, "unknown"),                   # None value
        (123, "unknown"),                    # Non-string value
    ]
    
    # Check each test case
    results = []
    for field_value, expected_contains in test_cases:
        result = get_field_info(field_value, field_descriptions)
        if expected_contains in result:
            log_message(f"get_field_info({field_value}) returned '{result}' which contains '{expected_contains}'", "SUCCESS")
            results.append(True)
        else:
            log_message(f"get_field_info({field_value}) returned '{result}' which does not contain '{expected_contains}'", "ERROR")
            results.append(False)
    
    # Report overall result
    if all(results):
        log_message("get_field_info function works correctly for all test cases", "SUCCESS")
        return True
    else:
        log_message("get_field_info function failed some test cases", "ERROR")
        return False

def test_custom_field_risk_assessment():
    """Test the custom_field_risk_assessment function with various inputs."""
    log_message("Testing custom_field_risk_assessment function...")
    
    # Define test cases
    test_cases = [
        # (field_name, expected_is_high_risk, expected_risk_desc_contains)
        ("KEY_SECURITY", True, "Security key"),      # High-risk key field
        ("CUSTOMER_KEY", True, "Security key"),      # High-risk key field
        ("SECURE_TOKEN", True, "Security key"),      # High-risk key field
        ("PERMISSION_LEVEL", True, "Permission"),   # High-risk permission field
        ("KEY", False, None),                       # Excluded field
        ("SPERM", False, None),                     # Excluded field
        ("SPERQ", False, None),                     # Excluded field
        ("QUAN", False, None),                      # Excluded field
        ("", False, None),                          # Empty field
        (None, False, None),                        # None value
    ]
    
    # Check each test case
    results = []
    for field_name, expected_is_high_risk, expected_risk_desc_contains in test_cases:
        is_high_risk, risk_desc = custom_field_risk_assessment(field_name)
        
        if is_high_risk == expected_is_high_risk:
            if expected_is_high_risk and expected_risk_desc_contains in (risk_desc or ""):
                log_message(f"custom_field_risk_assessment('{field_name}') correctly returned high risk with description containing '{expected_risk_desc_contains}'", "SUCCESS")
                results.append(True)
            elif not expected_is_high_risk and not risk_desc:
                log_message(f"custom_field_risk_assessment('{field_name}') correctly returned not high risk", "SUCCESS")
                results.append(True)
            else:
                log_message(f"custom_field_risk_assessment('{field_name}') returned correct risk level but unexpected description: '{risk_desc}'", "ERROR")
                results.append(False)
        else:
            log_message(f"custom_field_risk_assessment('{field_name}') returned risk level {is_high_risk}, expected {expected_is_high_risk}", "ERROR")
            results.append(False)
    
    # Report overall result
    if all(results):
        log_message("custom_field_risk_assessment function works correctly for all test cases", "SUCCESS")
        return True
    else:
        log_message("custom_field_risk_assessment function failed some test cases", "ERROR")
        return False

def test_field_pattern_matching():
    """Test the regex pattern matching for critical fields."""
    log_message("Testing field pattern matching...")
    
    # Get pattern dictionaries
    field_patterns = get_critical_field_patterns()
    pattern_descriptions = get_critical_field_pattern_descriptions()
    
    # Check all patterns have descriptions
    missing_descriptions = []
    for pattern in field_patterns:
        if pattern not in pattern_descriptions:
            missing_descriptions.append(pattern)
            log_message(f"Pattern '{pattern}' is missing a description", "ERROR")
    
    if missing_descriptions:
        log_message(f"Missing descriptions for patterns: {', '.join(missing_descriptions)}", "ERROR")
        return False
    
    # Define test cases for each pattern
    import re
    test_cases = []
    for pattern in field_patterns:
        try:
            regex = re.compile(pattern)
            
            # Create a sample field name that should match the pattern
            # This is simplified - in a real test you'd want specific test cases for each pattern
            sample_field = ""
            if "PASS" in pattern:
                sample_field = "PASSWORD"
            elif "AUTH" in pattern:
                sample_field = "AUTHORIZATION"
            elif "ROLE" in pattern:
                sample_field = "USER_ROLE"
            elif "PERM" in pattern:
                sample_field = "PERMISSION_LEVEL"
            elif "ACCESS" in pattern:
                sample_field = "ACCESS_CONTROL"
            elif "KEY" in pattern:
                sample_field = "SECURITY_KEY"
            elif "CRED" in pattern:
                sample_field = "CREDENTIAL"
            elif "AMOUNT" in pattern:
                sample_field = "AMOUNT_TOTAL"
            elif "CURR" in pattern:
                sample_field = "CURRENCY"
            elif "BANK" in pattern:
                sample_field = "BANK_ACCOUNT"
            elif "ACCOUNT" in pattern:
                sample_field = "ACCOUNT_NUMBER"
            elif "PAYMENT" in pattern:
                sample_field = "PAYMENT_METHOD"
            elif "VENDOR" in pattern:
                sample_field = "VENDOR_MASTER"
            elif "CUSTOMER" in pattern:
                sample_field = "CUSTOMER_ID"
            elif "EMPLOYEE" in pattern:
                sample_field = "EMPLOYEE_NUMBER"
            elif "CONFIG" in pattern:
                sample_field = "CONFIG_SETTING"
            elif "SETTING" in pattern:
                sample_field = "SYSTEM_SETTING"
            elif "PARAM" in pattern:
                sample_field = "PARAMETER"
            
            # Add to test cases if we created a sample field
            if sample_field:
                test_cases.append((pattern, sample_field, True))
                # Also add a negative test case
                test_cases.append((pattern, "UNRELATED_FIELD", False))
        except re.error as e:
            log_message(f"Invalid regex pattern '{pattern}': {str(e)}", "ERROR")
            return False
    
    # Check each test case
    results = []
    for pattern, field, should_match in test_cases:
        try:
            matches = bool(re.search(pattern, field))
            
            if matches == should_match:
                log_message(f"Pattern '{pattern}' correctly {'matched' if should_match else 'did not match'} field '{field}'", "SUCCESS")
                results.append(True)
            else:
                log_message(f"Pattern '{pattern}' {'matched' if matches else 'did not match'} field '{field}', expected {'match' if should_match else 'no match'}", "ERROR")
                results.append(False)
        except Exception as e:
            log_message(f"Error testing pattern '{pattern}' with field '{field}': {str(e)}", "ERROR")
            results.append(False)
    
    # Report overall result
    if all(results):
        log_message("Field pattern matching works correctly for all test cases", "SUCCESS")
        return True
    else:
        log_message("Field pattern matching failed some test cases", "ERROR")
        return False

def test_risk_assessment_with_fields():
    """Test the risk assessment function with different fields."""
    log_message("Testing risk assessment with various fields...")
    
    # Create a test DataFrame with various fields
    test_data = []
    
    # Add rows with vendor fields
    test_data.append({
        'User': 'TESTUSER', 
        'Datetime': pd.Timestamp('2025-04-14 12:00:00'),
        'TCode': 'XK01', 
        'Field': 'KRED', 
        'Table': 'LFA1',
        'Change_Indicator': 'I',
        'Session ID with Date': 'S0001 (2025-04-14)'
    })
    
    test_data.append({
        'User': 'TESTUSER', 
        'Datetime': pd.Timestamp('2025-04-14 12:05:00'),
        'TCode': 'XK02', 
        'Field': 'KREDI', 
        'Table': 'LFA1',
        'Change_Indicator': 'U',
        'Session ID with Date': 'S0001 (2025-04-14)'
    })
    
    test_data.append({
        'User': 'TESTUSER', 
        'Datetime': pd.Timestamp('2025-04-14 12:10:00'),
        'TCode': 'XK02', 
        'Field': 'KTOKK', 
        'Table': 'LFA1',
        'Change_Indicator': 'U',
        'Session ID with Date': 'S0001 (2025-04-14)'
    })
    
    test_data.append({
        'User': 'TESTUSER', 
        'Datetime': pd.Timestamp('2025-04-14 12:15:00'),
        'TCode': 'XK02', 
        'Field': 'XCPDK', 
        'Table': 'LFA1',
        'Change_Indicator': 'U',
        'Session ID with Date': 'S0001 (2025-04-14)'
    })
    
    # Add rows with some regular fields for comparison
    test_data.append({
        'User': 'TESTUSER', 
        'Datetime': pd.Timestamp('2025-04-14 12:20:00'),
        'TCode': 'MM01', 
        'Field': 'MATNR', 
        'Table': 'MARA',
        'Change_Indicator': 'I',
        'Session ID with Date': 'S0002 (2025-04-14)'
    })
    
    # Create DataFrame
    df = pd.DataFrame(test_data)
    
    # Apply risk assessment
    result_df = assess_risk_session(df)
    
    # Check if risk assessment was applied to all rows
    if 'risk_level' not in result_df.columns:
        log_message("Risk assessment did not add risk_level column", "ERROR")
        return False
    
    if 'risk_factors' not in result_df.columns:
        log_message("Risk assessment did not add risk_factors column", "ERROR")
        return False
    
    # Check vendor field risk assessments
    vendor_fields = ['KRED', 'KREDI', 'KTOKK', 'XCPDK']
    for field in vendor_fields:
        field_rows = result_df[result_df['Field'] == field]
        
        if field_rows.empty:
            log_message(f"No rows found with field '{field}'", "ERROR")
            continue
        
        for _, row in field_rows.iterrows():
            log_message(f"Field '{field}' risk level: {row['risk_level']}", "INFO")
            log_message(f"Field '{field}' risk factors: {row['risk_factors']}", "INFO")
            
            # Check if the risk description includes the field description
            if field in row['risk_factors']:
                log_message(f"Field '{field}' description included in risk factors", "SUCCESS")
            else:
                log_message(f"Field '{field}' description NOT included in risk factors", "WARNING")
    
    log_message("Risk assessment with fields completed", "SUCCESS")
    return True

def main():
    """Run all tests and report results."""
    log_message("=== SAP Audit Tool Field Description Tests ===")
    log_message("Starting tests...")
    
    # List of tests to run
    tests = [
        ("Field descriptions exist", test_field_descriptions_exist),
        ("Field description format", test_field_description_format),
        ("get_field_info function", test_get_field_info_function),
        ("custom_field_risk_assessment function", test_custom_field_risk_assessment),
        ("Field pattern matching", test_field_pattern_matching),
        ("Risk assessment with fields", test_risk_assessment_with_fields)
    ]
    
    # Run tests and collect results
    results = {}
    for test_name, test_func in tests:
        log_message(f"\nRunning test: {test_name}...")
        try:
            result = test_func()
            results[test_name] = result
        except Exception as e:
            log_message(f"Exception during test '{test_name}': {str(e)}", "ERROR")
            results[test_name] = False
    
    # Print summary
    log_message("\n=== Test Summary ===")
    all_passed = True
    
    for test_name, result in results.items():
        status = "PASSED" if result else "FAILED"
        log_message(f"{test_name}: {status}")
        if not result:
            all_passed = False
    
    # Final result
    if all_passed:
        log_message("\nAll tests passed! Field descriptions are working correctly.", "SUCCESS")
        return 0
    else:
        log_message("\nSome tests failed. Check the logs for details.", "ERROR")
        return 1

if __name__ == "__main__":
    sys.exit(main())
