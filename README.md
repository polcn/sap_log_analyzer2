# SAP Log Analyzer

A comprehensive tool for analyzing SAP logs and identifying security risks in user activities.

## Version
**4.2.0** - Dynamic Variable Field Handling (April 2025)
**4.1.0** - Field Description System enhancements (April 2025)

## Overview

SAP Log Analyzer processes SAP security logs and change documents to create a unified timeline of user activities with intelligent risk assessment. The tool helps auditors and security teams review SAP activities without requiring deep SAP technical knowledge.

## Components

- **sap_audit_data_prep.py**: Prepares raw SAP export files for analysis
  - Standardizes column headers and data formats
  - Creates datetime columns from date and time fields
  - Sorts data by user and timestamps

- **SAP Log Session Merger.py**: Creates a unified timeline of user sessions
  - Correlates events across SM20, CDHDR, and CDPOS logs
  - Groups activities into logical user sessions
  - Maintains session context across multiple log entries

- **sap_audit_tool_risk_assessment.py**: Evaluates risk levels of SAP activities
  - Identifies sensitive tables and transaction codes
  - Applies rule-based risk scoring algorithm
  - Flags suspicious usage patterns and high-risk operations

- **sap_audit_tool.py**: Main orchestration script that ties everything together
  - Checks if session timeline exists
  - Calls SAP Log Session Merger functionality if needed
  - Applies risk assessment
  - Generates output reports

- **sap_audit_tool_output.py**: Generates formatted Excel reports
  - Creates color-coded risk assessments
  - Formats data for readability
  - Includes summary statistics and charts

- **find_missing_descriptions.py**: Scans log data for fields without descriptions
  - Identifies technical field names lacking business descriptions
  - Creates a report of fields needing description updates

- **monitor_new_fields.py**: Automated tool to detect fields missing descriptions
  - Monitors logs for new field names
  - Alerts when fields without descriptions are detected

- **update_sap_descriptions.py**: Helps maintain SAP element descriptions
  - Updates field description database
  - Links technical field names to business-friendly descriptions

## Installation Requirements

- Python 3.6 or higher
- Required packages:
  - pandas
  - xlsxwriter
- Optional, but recommended:
  - colorama (for better console output)

```
pip install pandas xlsxwriter colorama
```

## Features

- **Comprehensive Data Processing**: Prepares and correlates data from SM20, CDHDR, and CDPOS logs
- **Dynamic Variable Field Handling**: Handles inconsistent field naming across different SAP exports
  - Maps variant column names to canonical field names
  - Creates consistent schema regardless of input format variations
  - Ensures reliable processing across different export formats
  - See `dynamic_field_handling.md` for details
- **User Session Timeline**: Creates a chronological view of user activities across log types
- **Intelligent Risk Assessment**: Evaluates security risks based on tables, fields, and transaction codes
- **Descriptive Risk Factors**: Provides detailed context for each flagged activity with SAP element descriptions
- **Detailed Excel Reports**: Generates formatted reports with risk highlighting and filtering
- **Complete Field Coverage**: Maintains descriptions for all SAP fields to improve report clarity
- **Debug Activity Detection**: Special detection and reporting of debugging activities
- **FireFighter Account Monitoring**: Highlights high-risk activities from emergency access accounts

## Usage

1. Place SAP export files in the 'input' folder
   - Files should follow naming patterns: `*_sm20_*.xlsx`, `*_cdhdr_*.xlsx`, `*_cdpos_*.xlsx`

2. Run `sap_audit_data_prep.py` to prepare the data
   ```
   python sap_audit_data_prep.py
   ```

3. Run `sap_audit_tool.py` to generate the report
   ```
   python sap_audit_tool.py
   ```

4. Review the results in `SAP_Audit_Report.xlsx`

## Field Description System

The Field Description System is a key feature that translates technical SAP field names into business-friendly descriptions, making reports understandable to non-technical reviewers:

- **Automatic Detection**: Scans logs for new field names without descriptions
- **Description Database**: Maintains a mapping of technical field names to business descriptions
- **Continuous Updates**: Provides tools to keep descriptions current as new fields appear
- **Enhanced Reporting**: Displays both technical field names and business descriptions in reports

Example:
```
Instead of:    Changed KRED 1005321
Reviewers see: Changed KRED (Vendor Account Number) 1005321
```

## Benefits

- **Improved Report Clarity**: Technical SAP field names are displayed with descriptions
- **Reduced SAP Expertise Required**: Reviewers don't need to be SAP experts to understand the significance of changes
- **Consistent Analysis**: Standardized descriptions ensure consistent interpretation across reviews
- **Complete Coverage**: The system tracks and maintains descriptions for all fields appearing in logs
