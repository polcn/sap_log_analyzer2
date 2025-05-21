# SAP Audit Tool Test Documentation

This document provides an overview of the test suite for the SAP Audit Tool, explaining which tests are current, which have been superseded, and what functionality each test covers.

## Current Test Suite

The following tests are part of the current test suite and should be maintained and run regularly:

### Primary Test Modules

| Test File | Purpose | Description |
|-----------|---------|-------------|
| `test_sap_audit_analyzer.py` | Test the analyzer module | Validates the enhanced analysis features, including transaction code descriptions, event descriptions, table descriptions, and flag columns for activity categorization. |
| `test_sap_audit_integration.py` | End-to-end integration test | Tests the full audit pipeline from data preparation through session merging, risk assessment, SysAid integration, and report generation. |
| `test_sap_audit_data_prep.py` | Test data preparation | Tests the data preparation module, which processes raw SAP log files into a standardized format. |
| `test_sap_audit_session_merger.py` | Test session merging | Tests the functionality that merges data from different sources (SM20, CDHDR, CDPOS) into a unified timeline. |
| `test_sap_audit_risk.py` | Test risk assessment | Tests the risk assessment module that analyzes SAP activities and assigns risk levels based on various factors. |
| `test_sap_audit_sysaid.py` | Test SysAid integration | Tests the integration with SysAid ticket information, ensuring session data is correctly associated with tickets. |
| `test_sap_audit_tool.py` | Test main tool module | Tests the main controller that coordinates the execution of all modules. |
| `test_sysaid_sessions.py` | Test SysAid session handling | Tests specific SysAid session handling functionality, particularly with special tickets. |

## Superseded Tests

The following tests have been superseded by more comprehensive tests in the current suite and have been moved to the archive directory:

| Test File | Replacement | Reason |
|-----------|-------------|--------|
| `test_data_prep_execution.py` | `test_sap_audit_integration.py` | The integration test now covers data preparation execution in context of the whole pipeline. |
| `test_session_merger_execution.py` | `test_sap_audit_integration.py` | The integration test now covers session merger execution in context of the whole pipeline. |
| `test_sap_audit_results.py` | `test_sap_audit_analyzer.py` and `test_sap_audit_integration.py` | The new analyzer tests validate results more comprehensively. |
| `test_field_descriptions.py` | `test_sap_audit_analyzer.py` | The analyzer test module now handles field descriptions. |

## Running Tests

### Running the Current Test Suite

To run all current tests:

```powershell
cd C:\Users\craig\OneDrive\Documents\Python
python -m unittest discover -p "test_*.py"
```

To run a specific test:

```powershell
python -m unittest test_sap_audit_analyzer
```

### Test Data

Test data is stored in the `test_data` directory and includes:
- Sample SM20 logs
- Sample CDHDR and CDPOS records
- Sample SysAid ticket information
- Reference data for transaction codes, events, tables, and risk profiles

## Test Coverage

The current test suite provides the following coverage:

- **Data Preparation**: Tests parsing, cleaning, and standardization of input files
- **Session Merging**: Tests combining data from multiple sources and assigning session IDs
- **Risk Assessment**: Tests identification of high-risk activities and assignment of risk levels
- **SysAid Integration**: Tests mapping sessions to SysAid tickets and enriching data
- **Analysis**: Tests enhanced analysis features, including descriptive columns and activity flags
- **Output Generation**: Tests producing formatted reports

## Maintaining Tests

When adding new features or refactoring existing modules:

1. Update or create corresponding test cases
2. Run the full test suite to ensure no regressions
3. Update this documentation if test organization changes

## Archive

Superseded tests are archived in `archive/tests/` instead of being deleted. This preserves historical test coverage while keeping the main directory focused on current tests.
